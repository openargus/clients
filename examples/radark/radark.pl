#!@PERLBIN@
#   Argus Client Software.  Tools to read, analyze and manage Argus data.
#   Copyright (c) 2000-2016 QoSient, LLC
#   All Rights Reserved

#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2, or (at your option)
#  any later version.

#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.

#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# radark.pl - Report on dark address space accesses.
#     This script takes as input an argus data stream (either file
#     or live stream)  and generates a scanner report. 
#     The strategy is to detect single host dark address accesses
#     report on the internal hosts that are discovered and respond.
#  
#     The technique uses racluster to identify a current dark address
#     space, using "no response" indications and specific ICMP
#     unreachable events, and then use the list of dark address
#     'accessors' to generate a scanners list. 

#     Who really cares about scanners, really, but we are interested
#     in what they discover, so we try to realize if there were any
#     internal responders to the scans, and more importantly, did
#     an internal machine provide any user data to the scanner.
#
#     The process involves clustering all the data to eliminate
#     spurious traffic that the probe may have been unable to
#     classify and correct for any direction issues.
#
#     Then the traffic is processed through a series of filters
#     designed to identify dark address space traffic.  From this
#     traffic, the set of scanners is formulated, and processed
#     to generate a list of searchers, the number of hosts discovered,
#     and what hosts responded to the the scan with data.
#
# 
#  $Id: //depot/argus/clients/examples/radark/radark.pl#6 $
#  $DateTime: 2016/06/01 15:17:28 $
#  $Change: 3148 $
# 
#

use POSIX;
use strict;
use Digest::MD5 qw(md5 md5_hex md5_base64);

my %attr = (PrintError=>0, RaiseError=>0);

my $scanthresh  = 0;
my $localaddr   = "";
my $multisig    = "";
my $verbose     = 0;
my $force       = 0;
my $percent     = 0;
my $filter      = 0;

my $hashindex   = "";
my @arglist     = ();
my $args        = "";

ARG: while (my $arg = shift(@ARGV)) {
   chomp $arg;
   for ($arg) {
      /^-L/   && do { $localaddr = shift (@ARGV); $hashindex .= $arg; next ARG; };
      /^-m/   && do { $multisig = shift (@ARGV); $hashindex .= $arg; next ARG; };
      /^-N/   && do { $scanthresh = shift (@ARGV); next ARG; };
      /^-v/   && do { $verbose++; next ARG; };
      /^-f/   && do { $force++; $hashindex .= $arg; next ARG; };
      /^-p/   && do { $percent++; next ARG; };
      /^-$/   && do { $filter++; };
      /^--$/  && do { $filter++; };
   }
   $hashindex .= $arg;
   $arglist[@arglist + 0] = $arg;
}

if ($localaddr eq "") {
   usage();
}

if ($filter) { $arglist[@arglist + 0] = "and net $localaddr"; }
else { $arglist[@arglist + 0] = " -- net $localaddr"; }

my $hash = md5_hex($hashindex);
my $RADATA  = "radark.$hash";

RaScanProcessArgusData ();
RaScanGenerateScannerList ();
RaScanGenerateScannerReport ();
RaScanCleanup ();
exit;


sub RaScanProcessArgusData {
   stat ("$RADATA");
   if ( ! -d _ ) {
      `mkdir -p $RADATA`;
   }
   stat ("$RADATA/racluster.out");
   if ( ! -f _ || $force) {
      if ($verbose) {print "conditioning data\n"};
      if ($verbose) {print "cmd: racluster -w -  @arglist | ra -E $RADATA/racluster.out -w $RADATA/raunreach.out - unreach\n"};
      `racluster -nnw -  @arglist | ra -nnE $RADATA/racluster.out -w $RADATA/raunreach.out - unreach`;
   } else {
      if ($verbose) {print "using existing $RADATA/racluster.out data\n";}
   }
}

my %wildcardports = ();
my $lastaddr  = "";
my $lastproto = "";
my $lastport  = "";
my $searcher  = "";

our (%addrs, %daddrs, %sdata, %adata, %probes, $thisaddr);
my ($data, $startime, $srcid, $dur, $saddr, $daddr, $trans, $proto, $dport);
my ($hosts, $srvhosts, $filter, $timerange, $resp);

sub RaScanGenerateScannerList {

#
#  Lets manage the radarkaddress.out file.  These are the internal hosts
#  we get from looking at unreachables.  We'll create the darkaddress.out
#  file, and if there is one above us, we'll update that as well.
#

   stat ("$RADATA/darkaddress.out");
   if ( ! -f _ || $force) {
      if ($verbose) {print "generating unreachable address list.\n"};
      if ($verbose) {print "cmd: racluster -nnM norep -m saddr daddr -r $RADATA/rareach.out -w - -- \\\n (not icmp) and (not src net $localaddr and dst net $localaddr) \\\n   | racluster -nnm saddr -w $RADATA/darkaddress.out\n"};

      `racluster -nnM norep -m saddr daddr -r $RADATA/raunreach.out -w -  -- \\\(not icmp\\\) and \\\(not src net $localaddr and dst net $localaddr\\\) | racluster -nnm saddr -w $RADATA/darkaddress.out`;

   } else {
      if ($verbose) {print "using existing $RADATA/lightnet.txt data\n"};
   }
   


#  Now lets tally the potential scan data to find remote hosts that touch more than one
#  dark net address:port pair, i.e. icmp unreachable or no response to stimulation on
#  a specific scan strategy.  First lets build the list of active addresses, this will
#  allow us to realize the darknet addresses, which will be our trigger for a scan.  By
#  adding ports to this list as well we'll get the whole thing.
#
   stat ("$RADATA/lightnet.out");
   if ( ! -f _ || $force) {
      if ($verbose) {print "generating active network data.\n"};
      if ($verbose) {print "cmd: racluster -nnM norep rmon -m smac saddr daddr -r $RADATA/racluster.out -w - - appbytes gt 0 \\\n   | racluster -nnm smac saddr  -w $RADATA/lightnet.out - src net $localaddr and not dst net $localaddr and src pkts gt 0\n"};
      `racluster -nnM norep rmon -m smac saddr daddr -r $RADATA/racluster.out -w - - appbytes gt 0 | racluster -nnm smac saddr  -w $RADATA/lightnet.out - src net $localaddr and not dst net $localaddr and src pkts gt 0`;
   } else {
      if ($verbose) {print "using existing $RADATA/lightnet.txt data\n"};
   }

   stat ("$RADATA/lightnet.txt");
   if ( ! -f _ || $force) {
      if ($verbose) {print "generating active network entities.\n"};
      if ($verbose) {print "cmd: ra -nns saddr -r $RADATA/lightnet.out > $RADATA/lightnet.txt\n"};
      `ra -nns saddr -r $RADATA/lightnet.out > $RADATA/lightnet.txt`;
   } else {
      if ($verbose) {print "using existing $RADATA/lightnet.txt data\n"};
   }

#
#  Now lets generate a scanners list.  These are the hosts that touch something that
#  is not active.  This will give us the candiate scanner list with the number of
#  host:proto:port that it touches.  We'll want those that hit more than one.
#  So, algorithm is, grab any traffic where the destination addres is local, but
#  not active.
#
 
   stat ("$RADATA/darkscanners.out");
   if ( ! -f _ || $force) {
      if ($verbose) { print ("creating darkscanners list\n"); }
      if ($verbose) { print ("cmd: rafilteraddr -nnm daddr -vf $RADATA/lightnet.txt -R $RADATA/racluster.out -w - - not src net $localaddr and dst net $localaddr | \\\n  racluster -nnm smac saddr -w $RADATA/darkscanners.out;\n")};
      `rafilteraddr -nnm daddr -vf $RADATA/lightnet.txt -R $RADATA/raunreach.out $RADATA/racluster.out -w - - not src net $localaddr and dst net $localaddr | racluster -nnm smac saddr -w $RADATA/darkscanners.out`;

      stat ("$RADATA/darkscanners.out");
      if ( -f _ ) {
         if ($verbose) { print ("cmd: ra -nnL-1 -r $RADATA/darkscanners.out -s saddr > $RADATA/darkscanners.txt\n")};
         `ra -nnL-1 -r $RADATA/darkscanners.out -s saddr > $RADATA/darkscanners.txt`;
      }

   } else {
      if ($verbose) { print "using existing $RADATA/darkscanners.out data\n"; }
   }

   stat ("$RADATA/scanreport.out");
   if ( ! -f _ || $force) {
      stat ("$RADATA/darkscanners.txt");
      if ( -f _ ) {
         if ($verbose) { print ("creating scan report file\n"); }
         `rafilteraddr -nnm saddr -f $RADATA/darkscanners.txt -r $RADATA/racluster.out -w - | racluster -nnM norep -m smac dmac saddr daddr -w - | racluster -nnm smac saddr -w - | rasort -nnm trans -w $RADATA/scanreport.out`;
      }

   } else {
      if ($verbose) { print "using existing $RADATA/scanreport.out data\n"; }
   }

#  last generate the time range for this report
   stat ("$RADATA/timerange.out");
   if ( ! -f _ || $force) {
      if ($verbose) {print "generating time range\n"};
      `ratimerange -nnr $RADATA/racluster.out > $RADATA/timerange.out`;
   }
   open(SESAME, "$RADATA/timerange.out");
   while ($data = <SESAME>) {
         chomp $data;
         $timerange = $data;
   }
   close(SESAME);
}

sub RaScanGenerateScannerReport {
   if ($verbose) { print "generating report\n"; }

#  Now build the scanner list for the report.
   stat ("$RADATA/scanreport.out");
   if ( -f _ || $force) {
      my @args = "ra -nnL-1 -r $RADATA/scanreport.out -s saddr dur trans -c , ";
      my $iter = 0;
      my $cnt = 0;

      open(SESAME, "@args |");

      while ($data = <SESAME>) {
         ($saddr, $dur, $trans) = split (/,/, $data);
         if ($trans > $scanthresh) {
            $addrs{$saddr} = "$trans,$dur";
            $cnt++;
         }
      }
      close(SESAME);
   }

   print "Scanner Report $timerange\n";
   
   if (($searcher = scalar(keys(%addrs))) > 0 ) {
      for $thisaddr ( sort ordinally keys(%addrs) ) {
         ($trans, $dur, $daddr, $resp) = split (/,/, $addrs{$thisaddr});
         printf "   %15.15s scanned %8d hosts in %16.16s secs discovered %6d hosts with %6d responders\n", $thisaddr, $trans, $dur, $daddr, $resp;
      }
   } else {
      printf "  No Scanners Found\n"; 
   }
}

sub RaScanCleanup {
   if ($verbose) { print "cleaning up\n"; }
}

sub ordinally {
   $addrs{$b} <=> $addrs{$a};
}

sub subliminally {
   my @a_fields = split /,/, @{$daddrs{$thisaddr}{$a}}[0];
   my @b_fields = split /,/, @{$daddrs{$thisaddr}{$b}}[0];
 
   $b_fields[2] <=> $a_fields[2];
}
 
sub numerically {
   $wildcardports{$lastaddr}{$lastproto}{$a} <=> $wildcardports{$lastaddr}{$lastproto}{$b}
   ||
   $a <=> $b
}

sub usage {
   printf "radark -L localaddr(cidr) -R data [-N threshold] [-m signum] [-vfp]\n";
   exit;
}
