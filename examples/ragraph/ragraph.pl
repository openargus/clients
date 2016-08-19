#!@PERLBIN@
#  Argus Software
#  Copyright (c) 2000-2016 QoSient, LLC
#  All rights reserved.
# 
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2, or (at your option)
#  any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#  
#  ragraph.pl - graph argus data.
#     This program uses rabins() and rrdtool to generate png formated  
#     graphs of argus data.  It is an ambitious program, trying to
#     support graphing a lot of stuff at a time, so if you find
#     that something is not quite right, just send mail to the argus
#     mailing list.
#  
#     See the manpages for rrdgraph, and rabins to try to understand
#     how this works, as it supports all the options for both these
#     programs.
#  
#  
# Complain about undeclared variables
use strict;

# Used modules
use RRDs;
use POSIX;

# Global variables
my $tmpfile = tmpnam();
my $RRD     = $tmpfile.".rrd";
my $RRDARG  = $tmpfile.".rrdargs";
my $PNG     = "ragraph.png";

my $RABINS = "/usr/local/bin/rabins";
my $VERSION = "3.0.8";
my @arglist = ();

my $input = 0;
my $title = "";
my $unitlen = 0;
my $unitsex = "";
my $units = 0;
my $comment = "";
my $debug = 0;
my $fill = 1;
my $stack = 1;
my $split = 1;
my $log = 0;
my $rigid = 0;
my $invert = 0;
my $graphonly = 0;
my $upper = 0;
my $lower = 0;
my $height = 353;
my $width = 651;
my $usryaxis = "";
my $yaxisstr;

my $timeindex = -1;
my $saddrindex = -1;
my $daddrindex = -1;
my $sportindex = -1;
my $dportindex = -1;
my $labelindex = -1;
my $serviceindex = -1;
my $inodeindex = -1;
my $protoindex = -1;
my $probeindex = -1;
my $transindex = -1;
my $avgdurindex = -1;
my $ddurindex = -1;
my $dstimeindex = -1;
my $dltimeindex = -1;
my $dspktindex = -1;
my $ddpktindex = -1;
my $dsbyteindex = -1;
my $ddbyteindex = -1;
my $srcpktindex = -1;
my $dstpktindex = -1;
my $srcbyteindex = -1;
my $dstbyteindex = -1;
my $srclossindex = -1;
my $dstlossindex = -1;
my $srcjitterindex = -1;
my $dstjitterindex = -1;
my $srctosindex = -1;
my $dsttosindex = -1;
my $srcttlindex = -1;
my $dstttlindex = -1;
my $srcipidindex = -1;
my $dstipidindex = -1;
my $srcwinindex = -1;
my $dstwinindex = -1;
my $tcprttindex = -1;
my $synackindex = -1;
my $ackdatindex = -1;
my $srctcpmaxindex = -1;
my $dsttcpmaxindex = -1;
my $jdelayindex = -1;
my $ldelayindex = -1;
  
my $srcdataindex = -1;
my $dstdataindex = -1;

my $minval  = 'U';
my $maxval  = 'U';
 
my @opts = ();
my @columns = ();
my @power = ();

my $average;
   
my @objects = ();
my @objectlist = ();
my $objectindex = -1;
my $percent = 0;
my $rate = 0;
my $matrix = 0;
my $probe = 0;
my $histo = 0;
my $objects;
my $yaxislabels = 0;
my $yaxislabel = "";

my $objectIn  = "objectIn";
my $objectOut = "objectOut";

my $num = 0;
my $noption;
my $done = 0;

my $fontstr = "";
my $fontmode = "";
my $fontsmooth = 0;
my $slope = 0;
my $nolegend = 0;
my $watermark = "";
my $imginfo = "";
my $zoom = 0;
my $altautoscale = 0;
my $altautoscalemax = 0;
my $nogridfit = 0;
my $xgrid = "";
my $ygrid = "";
my $altygrid = 0;
my $norrdwmark = 0;

my ($START, $FRAC, $END, $LAST, $SECONDS, $STEP, $COLUMNS, $PROTOS, $PROBES, $RUNS, $ERROR);
my @line_args;
my @command_args;

ARG: while (my $arg = shift(@ARGV)) {
   if (!$done) {
      for ($arg) {
         s/^-log//                && do { $log++; next ARG; };
         s/^-font$//              && do { $fontstr = shift(@ARGV); next ARG; };
         s/^-font-render-mode$//  && do { $fontmode = shift(@ARGV); next ARG; };
         s/^-font-smoothing-threshold$//
                                  && do { $fontsmooth = shift(@ARGV); next ARG; };
         s/^-slope-mode$//        && do { $slope++; next ARG; };
         s/^-no-legend$//         && do { $nolegend++; next ARG; };
         s/^-watermark$//         && do { $watermark = shift(@ARGV); next ARG; };
         s/^-imginfo$//           && do { $imginfo = shift(@ARGV); next ARG; };
         s/^-zoom$//              && do { $zoom = shift(@ARGV); next ARG; };
         s/^-norrdwmark$//        && do { $norrdwmark++; next ARG; };

         s/^-fill$//              && do { $fill = 0; next ARG; };
         s/^-stack$//             && do { $stack = 0; next ARG; };
         s/^-split$//             && do { $split = 0; next ARG; };
         s/^-invert$//            && do { $invert++; next ARG; };
         s/^-rigid$//             && do { $rigid++; next ARG; };
         s/^-height$//            && do { $height = shift (@ARGV); next ARG; };
         s/^-width$//             && do { $width = shift (@ARGV); next ARG; };
         s/^-only-graph$//        && do { $graphonly++; next ARG; };
         s/^-upper$//             && do { $upper = shift (@ARGV); next ARG; };
         s/^-upper-limit$//       && do { $upper = shift (@ARGV); next ARG; };
         s/^-lower$//             && do { $lower = shift (@ARGV); next ARG; };
         s/^-lower-limit$//       && do { $lower = shift (@ARGV); next ARG; };
         s/^-alt-autoscale$//     && do { $altautoscale++; next ARG; };
         s/^-alt-autoscale-max$// && do { $altautoscalemax++; next ARG; };
         s/^-no-gridfit$//        && do { $nogridfit++; next ARG; };
         s/^-x-grid$//            && do { $xgrid = shift (@ARGV); next ARG; };
         s/^-y-grid$//            && do { $ygrid = shift (@ARGV); next ARG; };
         s/^-alt-y-grid$//        && do { $altygrid++; next ARG; };

         s/^-title$//             && do { $title = shift (@ARGV); next ARG; };
         s/^-vertical-label$//    && do { $usryaxis = shift (@ARGV); next ARG; };
         s/^-yaxis-label$//       && do { $usryaxis = shift (@ARGV); next ARG; };
         s/^-units-exponent$//    && do { $unitsex = shift (@ARGV); next ARG; };
         s/^-units-length$//      && do { $unitlen = shift (@ARGV); next ARG; };
         s/^-units=si$//          && do { $units++; next ARG; };

         s/^-w$//                 && do { if ($arg) {
                                       $PNG = $arg;
                                       next ARG;
                                    } else {
                                       $PNG = shift (@ARGV);
                                       next ARG;
                                    };
                                 };
         s/^-N$//                && do {
                                    if (!($arg)) {
                                       $arg = shift (@ARGV);
                                    }
                                    if (/^*o/) {
                                       print "DEBUG: -N option starts with o $arg\n" if $debug;
                                       $arglist[@arglist + 0] = "-N $arg";
                                       next ARG; 
                                    } else {
                                       print "DEBUG: -N option is $arg\n" if $debug;
                                       $num = $arg;
                                       next ARG; 
                                    }
                                 };

         s/^-comment$//          && do { $comment = shift (@ARGV); next ARG; };
         s/^-debug$//            && do { $debug++; next ARG; };
         /^-H$/                  && do { $histo++; };
         /^-r$/                  && do { if ($ARGV[0] eq "-") { $arg .= " -"; shift (@ARGV); }; };
         /^win/                  && do { $arg = "swin dwin";};
         /^mac/                  && do { $arg = "smac";};
         /^addr/                 && do { $arg = "saddr";};
         /^dport/                && do { $serviceindex++; $arg = "dport"; };
         /^svc/                  && do { $serviceindex++; $arg = "sport dport"; };
         /^label/                && do { $labelindex++; $arg = "label"; };
         /^pdspkts/              && do { $percent++; $arglist[@arglist + 0] = "dspkts spkts"; next ARG; };
         /^pddpkts/              && do { $percent++; $arglist[@arglist + 0] = "ddpkts dpkts"; next ARG; };
         /^pdsbytes/             && do { $percent++; $arglist[@arglist + 0] = "dsbytes sbytes"; next ARG; };
         /^pddbytes/             && do { $percent++; $arglist[@arglist + 0] = "ddbytes dbytes"; next ARG; };
         /^-$/                   && do { $done++; };
      }

   } else {
      for ($arg) {
         s/\(/\\\(/            && do { ; };
         s/\)/\\\)/            && do { ; };
      }
   }

   $arglist[@arglist + 0] = $arg;
}

if ((@arglist + 0) == 0) {
   printf "usage: $0 metric(s) object [ragraph-options] [ra-options]\n";
   exit;
}

if ($invert) {
   $objectIn  = "objectOut";
   $objectOut = "objectIn";
}

chomp $RABINS;
if ((! -e $RABINS) || (! -x $RABINS)) {
   print "ragraph: $RABINS not found. See INSTALL\n";
   exit;
}

RagraphProcessArgusData ();
RagraphReadInitialValues ($tmpfile);

if ($input > 0) {
   RagraphGenerateRRDParameters ($tmpfile);
   RagraphGenerateRRD ();
   RagraphGeneratePNG ();
} else {
   printf "no data\n";
}

RagraphCleanUp ();
exit;


sub RagraphCleanUp {
   print "DEBUG: RagraphCleanUp - rm -f $tmpfile $RRD $RRDARG\n" if $debug;
   `rm -f $tmpfile $RRD $RRDARG` if !$debug;
}

sub RagraphReadInitialValues {
   my $file = shift;
   my ($i, $k, $v, $data);

   print "DEBUG: RagraphReadInitialValues($file)\n" if $debug;
   open(SESAME, $file) || die ("Could not open file $!");;

   for (1 .. 9) {
      $data = <SESAME>;
      if ( ($k, $v) = $data =~ m/(\w+)=(.*)/ ) {
         for ($k) {
            /StartTime/ and do {(($START, $FRAC) = $v =~ m/(\d*)\.(.*)/) ;};
            /StopTime/  and do {(($END, $FRAC) = $v =~ m/(\d*)\.(.*)/) ;};
            /LastTime/  and do {(($LAST, $FRAC) = $v =~ m/(\d*)\.(.*)/) ;};
            /Seconds/   and do {$SECONDS = $v;};
            /BinSize/   and do {(($STEP, $FRAC) = $v =~ m/(\d*)\.(.*)/) ;};
            /Columns/   and do {$COLUMNS = $v;};
            /Bins/      and do {$RUNS = $v;};
            /Protos/    and do {$PROTOS = $v;};
            /Probes/    and do {$PROBES = $v;};
         }
      }
      $input++;
   }

   print "DEBUG: RagraphReadInitialValue($tmpfile): start $START stop $END last $LAST seconds $SECONDS step $STEP Columns $COLUMNS bins $RUNS\n" if $debug;
   close(SESAME);
}

sub RagraphProcessArgusData {
   my @args = "";
   if ($histo) {
      @args = ("$RABINS -c, -M hard zero -p6 -GL0 -s ", @arglist, "> $tmpfile");
   } else {
      @args = ("$RABINS -c, -M hard zero -p6 -GL0 -s ltime ", @arglist, "> $tmpfile");
   }

   print "DEBUG: RagraphProcessArgusData: exec: @args\n" if $debug;
   my $input = `@args`;
}

my @dataobjects = ();
my @typeobjects = ();
my $objwidth = 0;

sub RagraphGenerateRRDParameters {
   my $file = shift;
   my $x;
   @columns = split(/,/, $COLUMNS);

   print "DEBUG: RagraphGenerateRRDParameters($file)\n" if $debug;

   for ($x = 0; $x < (@columns + 0); $x++) {
      for ($columns[$x]) {
         /Time/		and do {$timeindex = $x; };

         /Host/	        and do {push @typeobjects, $x; $saddrindex = $x; $objwidth = 20; };
         /SrcId/	and do {push @typeobjects, $x; $saddrindex = $x; $objwidth = 20; };
         /InAddr/	and do {push @typeobjects, $x; $saddrindex = $x; $objwidth = 20; $probe = 1;};
         /OutAddr/	and do {push @typeobjects, $x; $daddrindex = $x; $objwidth = 20; $probe = 1;};
         /SrcAddr/	and do {push @typeobjects, $x; $saddrindex = $x; $objwidth = 24; };
         /DstAddr/	and do {push @typeobjects, $x; $daddrindex = $x; $objwidth = 24; };
         /SrcDomain/	and do {push @typeobjects, $x; $saddrindex = $x; $objwidth = 20; };
         /DstDomain/	and do {push @typeobjects, $x; $daddrindex = $x; $objwidth = 20; };
         /^Net/		and do {push @typeobjects, $x; $saddrindex = $x; $objwidth = 20; };
         /SrcNet/	and do {push @typeobjects, $x; $saddrindex = $x; $objwidth = 20; };
         /DstNet/	and do {push @typeobjects, $x; $daddrindex = $x; $objwidth = 20; };
         /^sCo/		and do {push @typeobjects, $x; $saddrindex = $x; $objwidth = 5; };
         /^dCo/		and do {push @typeobjects, $x; $daddrindex = $x; $objwidth = 5; };
         /^Mac/		and do {push @typeobjects, $x; $saddrindex = $x; $objwidth = 23; };
         /SrcMac/	and do {push @typeobjects, $x; $saddrindex = $x; $objwidth = 23; };
         /DstMac/	and do {push @typeobjects, $x; $daddrindex = $x; $objwidth = 23; };
         /Proto/	and do {push @typeobjects, $x; $protoindex = $x; $objwidth = 6; };
         /ProbeId/	and do {push @typeobjects, $x; $probeindex = $x; $objwidth = 15; };
         /Sport/	and do {push @typeobjects, $x; $sportindex = $x; $objwidth = 12; };
         /Dport/	and do {push @typeobjects, $x; $dportindex = $x; $objwidth = 12; };
         /sToS/		and do {push @typeobjects, $x; $srctosindex = $x; $objwidth = 6; };
         /dToS/		and do {push @typeobjects, $x; $dsttosindex = $x; $objwidth = 6; };
         /sDSb/		and do {push @typeobjects, $x; $srctosindex = $x; $objwidth = 6; };
         /dDSb/		and do {push @typeobjects, $x; $dsttosindex = $x; $objwidth = 6; };
         /sIpId/	and do {push @typeobjects, $x; $srcipidindex = $x; $objwidth = 6; };
         /dIpId/	and do {push @typeobjects, $x; $dstipidindex = $x; $objwidth = 6; };
         /sTtl/		and do {push @typeobjects, $x; $srcttlindex = $x; $objwidth = 6; };
         /dTtl/		and do {push @typeobjects, $x; $dstttlindex = $x; $objwidth = 6; };

         /Inode/	and do {push @typeobjects, $x; $inodeindex = $x; $objwidth = 12; };
         /Service/	and do {push @typeobjects, $x; $serviceindex = $x; $objwidth = 12; };
         /Label/	and do {push @typeobjects, $x; $labelindex = $x; $objwidth = 20; };

         /TotPkts/	and do {push @dataobjects, $x; $srcpktindex = $x; $yaxislabels++; $yaxislabel = "Total Packets" ;};
         /SrcPkts/	and do {push @dataobjects, $x; $srcpktindex  = $x; $yaxislabels++; $yaxislabel = " pkts/sec" ;};
         /OutPkts/	and do {push @dataobjects, $x; $srcpktindex  = $x; $yaxislabels++; $yaxislabel = " pkts/sec" ;$probe = 1;};
         /DstPkts/	and do {push @dataobjects, $x; $dstpktindex  = $x; $yaxislabels++; $yaxislabel = " pkts/sec" ;};
         /InPkts/	and do {push @dataobjects, $x; $dstpktindex  = $x; $yaxislabels++; $yaxislabel = " pkts/sec" ;$probe = 1;};

         /pTotPkts/	and do {push @dataobjects, $x; $srcpktindex = $x; $yaxislabels++; $yaxislabel = "Percent Total Packets" ;};
         /pSrcPkts/	and do {push @dataobjects, $x; $srcpktindex  = $x; $yaxislabels++; $yaxislabel = " Percent pkts/sec" ;};
         /pOutPkts/	and do {push @dataobjects, $x; $srcpktindex  = $x; $yaxislabels++; $yaxislabel = " Percent pkts/sec" ;$probe = 1;};
         /pDstPkts/	and do {push @dataobjects, $x; $dstpktindex  = $x; $yaxislabels++; $yaxislabel = " Percent pkts/sec" ;};
         /pInPkts/	and do {push @dataobjects, $x; $dstpktindex  = $x; $yaxislabels++; $yaxislabel = " Percent pkts/sec" ;$probe = 1;};

         /TotBytes/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "Total bits/sec" ;};
         /SrcBytes/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;};
         /OutBytes/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;$probe = 1;};
         /DstBytes/	and do {push @dataobjects, $x; $dstbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;};
         /InBytes/	and do {push @dataobjects, $x; $dstbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;$probe = 1;};

         /pTotBytes/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "Percent Total bits/sec" ;};
         /pSrcBytes/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "Percent bits/sec" ;};
         /pOutBytes/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "Percent bits/sec" ;$probe = 1;};
         /pDstBytes/	and do {push @dataobjects, $x; $dstbyteindex = $x; $yaxislabels++; $yaxislabel = "Percent bits/sec" ;};
         /pInBytes/	and do {push @dataobjects, $x; $dstbyteindex = $x; $yaxislabels++; $yaxislabel = "Percent bits/sec" ;$probe = 1;};

         /TotAppBytes/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;$probe = 1;};
         /SAppBytes/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;$probe = 1;};
         /OAppBytes/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;$probe = 1;};
         /DAppBytes/	and do {push @dataobjects, $x; $dstbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;};
         /IAppBytes/	and do {push @dataobjects, $x; $dstbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;};

         /pAppBytes/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;$probe = 1;};
         /pSAppBytes/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;$probe = 1;};
         /pOAppBytes/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;$probe = 1;};
         /pDAppBytes/	and do {push @dataobjects, $x; $dstbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;};
         /pIAppBytes/	and do {push @dataobjects, $x; $dstbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;};

         /SIntPkt/	and do {push @dataobjects, $x; $srcpktindex = $x; $yaxislabels++; $yaxislabel = "Interpacket Arrival (uSec)" ;};
         /DIntPkt/	and do {push @dataobjects, $x; $dstpktindex = $x; $yaxislabels++; $yaxislabel = "Interpacket Arrival (uSec)" ;};
         /SIntPktAct/	and do {push @dataobjects, $x; $srcpktindex = $x; $yaxislabels++; $yaxislabel = "Active Interpacket Arrival (uSec)" ;};
         /DIntPktAct/	and do {push @dataobjects, $x; $dstpktindex = $x; $yaxislabels++; $yaxislabel = "Active Interpacket Arrival (uSec)" ;};
         /SIntPktIdl/	and do {push @dataobjects, $x; $srcpktindex = $x; $yaxislabels++; $yaxislabel = "Idle Interpacket Arrival (uSec)" ;};
         /DIntPktIdl/	and do {push @dataobjects, $x; $dstpktindex = $x; $yaxislabels++; $yaxislabel = "Idle Interpacket Arrival (uSec)" ;};

         /SIntPktMax/	and do {push @dataobjects, $x; $srcpktindex = $x; $yaxislabels++; $yaxislabel = "Interpacket Arrival (uSec)" ;};
         /DIntPktMax/	and do {push @dataobjects, $x; $dstpktindex = $x; $yaxislabels++; $yaxislabel = "Interpacket Arrival (uSec)" ;};
         /SIPActMax/	and do {push @dataobjects, $x; $srcpktindex = $x; $yaxislabels++; $yaxislabel = "Active Interpacket Arrival (uSec)" ;};
         /DIPActMax/	and do {push @dataobjects, $x; $dstpktindex = $x; $yaxislabels++; $yaxislabel = "Active Interpacket Arrival (uSec)" ;};
         /SIPIdlMax/	and do {push @dataobjects, $x; $srcpktindex = $x; $yaxislabels++; $yaxislabel = "Idle Interpacket Arrival (uSec)" ;};
         /DIPIdlMax/	and do {push @dataobjects, $x; $dstpktindex = $x; $yaxislabels++; $yaxislabel = "Idle Interpacket Arrival (uSec)" ;};
         /SIntPktMin/	and do {push @dataobjects, $x; $srcpktindex = $x; $yaxislabels++; $yaxislabel = "Interpacket Arrival (uSec)" ;};
         /DIntPktMin/	and do {push @dataobjects, $x; $dstpktindex = $x; $yaxislabels++; $yaxislabel = "Interpacket Arrival (uSec)" ;};
         /SIPActMin/	and do {push @dataobjects, $x; $srcpktindex = $x; $yaxislabels++; $yaxislabel = "Active Interpacket Arrival (uSec)" ;};
         /DIPActMin/	and do {push @dataobjects, $x; $dstpktindex = $x; $yaxislabels++; $yaxislabel = "Active Interpacket Arrival (uSec)" ;};
         /SIPIdlMin/	and do {push @dataobjects, $x; $srcpktindex = $x; $yaxislabels++; $yaxislabel = "Idle Interpacket Arrival (uSec)" ;};
         /DIPIdlMin/	and do {push @dataobjects, $x; $dstpktindex = $x; $yaxislabels++; $yaxislabel = "Idle Interpacket Arrival (uSec)" ;};

         /SrcJitter/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "Jitter (uSecs)" };
         /DstJitter/	and do {push @dataobjects, $x; $dstbyteindex = $x; $yaxislabels++; $yaxislabel = "Jitter (uSecs)" };
         /SrcJitAct/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "Active Jitter (uSecs)" };
         /DstJitAct/	and do {push @dataobjects, $x; $dstbyteindex = $x; $yaxislabels++; $yaxislabel = "Active Jitter (uSecs)" };
         /SrcJitIdl/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "Idle Jitter (uSecs)" };
         /DstJitIdl/	and do {push @dataobjects, $x; $dstbyteindex = $x; $yaxislabels++; $yaxislabel = "Idle Jitter (uSecs)" };

         /TcpRtt/	and do {push @dataobjects, $x; $tcprttindex = $x; $yaxislabels++; $yaxislabel = "TCP Round Trip Time (Secs)" };
         /SynAck/	and do {push @dataobjects, $x; $synackindex = $x; $yaxislabels++; $yaxislabel = "Syn -> SynAck Time (Secs)" };
         /AckDat/	and do {push @dataobjects, $x; $ackdatindex = $x; $yaxislabels++; $yaxislabel = "SynAck -> Data (Secs)" };

         /STcpMax/	and do {push @dataobjects, $x; $srctcpmaxindex = $x; $yaxislabels++; $yaxislabel = "TCP Maximum Bandwidth" };
         /DTcpMax/	and do {push @dataobjects, $x; $dsttcpmaxindex = $x; $yaxislabels++; $yaxislabel = "TCP Maximum Bandwidth" };

         /Rate/		and do {push @dataobjects, $x; $srcpktindex = $x; $yaxislabels++; $yaxislabel = "pkts/sec" ;};
         /SrcRate/	and do {push @dataobjects, $x; $srcpktindex = $x; $yaxislabels++; $yaxislabel = "pkts/sec" ;};
         /DstRate/	and do {push @dataobjects, $x; $dstpktindex = $x; $yaxislabels++; $yaxislabel = "pkts/sec" ;};
 
         /Load/		and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;};
         /SrcLoad/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;};
         /DstLoad/	and do {push @dataobjects, $x; $dstbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;};
 
         /AppRate/	and do {push @dataobjects, $x; $srcpktindex = $x; $yaxislabels++; $yaxislabel = "pkts/sec" ;};
         /SrcAppRate/	and do {push @dataobjects, $x; $srcpktindex = $x; $yaxislabels++; $yaxislabel = "pkts/sec" ;};
         /DstAppRate/	and do {push @dataobjects, $x; $dstpktindex = $x; $yaxislabels++; $yaxislabel = "pkts/sec" ;};
 
         /AppLoad/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;};
         /SrcAppLoad/	and do {push @dataobjects, $x; $srcbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;};
         /DstAppLoad/	and do {push @dataobjects, $x; $dstbyteindex = $x; $yaxislabels++; $yaxislabel = "bits/sec" ;};

         /Loss/		and do {push @dataobjects, $x; $srclossindex = $x; $yaxislabels++; $yaxislabel = "Loss (pkts/sec)" ;};
         /pLoss/	and do {push @dataobjects, $x; $srclossindex = $x; $yaxislabels++; $yaxislabel = "Percent Loss (pkts/sec)" ;};
         /SrcLoss/	and do {push @dataobjects, $x; $srclossindex = $x; $yaxislabels++; $yaxislabel = "Loss (pkts/sec)" ;};
         /pSrcLoss/	and do {push @dataobjects, $x; $srclossindex = $x; $yaxislabels++; $yaxislabel = "Percent Loss (pkts/sec)" ;};
         /DstLoss/	and do {push @dataobjects, $x; $dstlossindex = $x; $yaxislabels++; $yaxislabel = "Loss (pkts/sec)" ;};
         /pDstLoss/	and do {push @dataobjects, $x; $dstlossindex = $x; $yaxislabels++; $yaxislabel = "Percent Loss (pkts/sec)" ;};
         /Trans/	and do {push @dataobjects, $x; $transindex   = $x; $yaxislabels++; $yaxislabel = "Concurrent Transactions" ;};
         /AvgDur/	and do {push @dataobjects, $x; $avgdurindex  = $x; $yaxislabels++; $yaxislabel = "Average Transaction Time (secs)" ;};
         /dDur/		and do {push @dataobjects, $x; $ddurindex    = $x; $yaxislabels++; $yaxislabel = "Network Transit Time (secs)" ;};
         /dsTime/	and do {push @dataobjects, $x; $dstimeindex  = $x; $yaxislabels++; $yaxislabel = "Delta StartTime (secs)" ;};
         /dlTime/	and do {push @dataobjects, $x; $dltimeindex  = $x; $yaxislabels++; $yaxislabel = "Delta LastTime (secs)" ;};
         /JDelay/	and do {push @dataobjects, $x; $jdelayindex  = $x; $yaxislabels++; $yaxislabel = "Join Delay (secs)" ;};
         /LDelay/	and do {push @dataobjects, $x; $ldelayindex  = $x; $yaxislabels++; $yaxislabel = "Leave Delay (secs)" ;};
         /SrcWin/	and do {push @dataobjects, $x; $srcwinindex  = $x; $yaxislabels++; $yaxislabel = "TCP Window Size (bytes)" ;};
         /DstWin/	and do {push @dataobjects, $x; $dstwinindex  = $x; $yaxislabels++; $yaxislabel = "TCP Window Size (bytes)" ;};

         /dsPkts/	and do {
            if ($percent) {
               push @dataobjects, "pdsPkts";
               $dspktindex = $x++;
               $srcpktindex = $x;
               $yaxislabels++; 
               $yaxislabel = "Percent Delta Pkts per sec" ;
            } else {
               push @dataobjects, $x; $dspktindex = $x;
               $yaxislabels++; 
               $yaxislabel = "Delta Pkts (secs)" ;
            }
         };
         /ddPkts/	and do {
            if ($percent) {
               push @dataobjects, "pddPkts";
               $ddpktindex = $x++;
               $dstpktindex = $x;
               $yaxislabels++; 
               $yaxislabel = "Percent Delta Pkts per sec" ;
            } else {
               push @dataobjects, $x; $ddpktindex = $x;
               $yaxislabels++; 
               $yaxislabel = "Delta Pkts (secs)" ;
            }
         };
         /dsByte/	and do {
            if ($percent) {
               push @dataobjects, "pdsByte";
               $dsbyteindex = $x++;
               $srcbyteindex = $x;
               $yaxislabels++; 
               $yaxislabel = "Percent Delta Bytes per sec" ;
            } else {
               push @dataobjects, $x; $dsbyteindex = $x;
               $yaxislabels++; 
               $yaxislabel = "Delta Bytes (secs)" ;
            }
         };
         /ddByte/	and do {
            if ($percent) {
               push @dataobjects, "pddByte";
               $ddbyteindex = $x++;
               $dstbyteindex = $x;
               $yaxislabels++; 
               $yaxislabel = "Percent Delta Bytes per sec" ;
            } else {
               push @dataobjects, $x; $ddbyteindex = $x;
               $yaxislabels++; 
               $yaxislabel = "Delta Bytes (secs)" ;
            }
         };
      }
   }

   if (($srcpktindex >= 0) || ($dstpktindex >= 0)) {
      if ($srcpktindex >= 0) {
         $srcdataindex = $srcpktindex;
      }
      if ($dstpktindex >= 0) {
         $dstdataindex = $dstpktindex;
      }
   
   } else {
      if (($srcbyteindex >= 0) || ($dstbyteindex >= 0)) {
         if ($srcbyteindex >= 0) {
           $srcdataindex = $srcbyteindex;
         }
         if ($dstbyteindex >= 0) {
            $dstdataindex = $dstbyteindex;
         }
   
      } else {
         if (($srcjitterindex >= 0) || ($dstjitterindex >= 0)) {
            if ($srcjitterindex >= 0) {
               $srcdataindex = $srcjitterindex;
            }
            if ($dstjitterindex >= 0) {
               $dstdataindex = $dstjitterindex;
            }
         } else {
            if (($srclossindex >= 0) || ($dstlossindex >= 0)) {
               if ($srclossindex >= 0) {
                  $srcdataindex = $srclossindex;
               }
               if ($dstlossindex >= 0) {
                  $dstdataindex = $dstlossindex;
               }
            } else {
               if (($srcwinindex >= 0) || ($dstwinindex >= 0)) {
                  if ($srcwinindex >= 0) {
                     $srcdataindex = $srcwinindex;
                  }
                  if ($dstwinindex >= 0) {
                     $dstdataindex = $dstwinindex;
                  }
               }
            }
         }
      }

      if ($avgdurindex >= 0) {
         $srcdataindex = -1;
         $dstdataindex = $avgdurindex;
         $minval = 0.000001;
      }
      if ($ddurindex >= 0) {
         $srcdataindex = -1;
         $dstdataindex = $ddurindex;
      }
      if ($transindex >= 0) {
         $srcdataindex = -1;
         $dstdataindex = $transindex;
      }
      if ($dstimeindex >= 0) {
         $srcdataindex = -1;
         $dstdataindex = $dstimeindex;
      }
      if ($dltimeindex >= 0) {
         $srcdataindex = -1;
         $dstdataindex = $dltimeindex;
      }
      if ($dspktindex >= 0) {
         $srcdataindex = $dspktindex;
      }
      if ($ddpktindex >= 0) {
         $dstdataindex = $ddpktindex;
      }
      if ($dsbyteindex >= 0) {
         $srcdataindex = $dsbyteindex;
      }
      if ($ddbyteindex >= 0) {
         $dstdataindex = $ddbyteindex;
      }
   }

   my $ind     = 4;
   my $cnt     = 1;
   my $lineind = 0;

   @opts = ("--start", $START, "--step", $STEP);

   if (@typeobjects + 0) {
      my %objectlist = ();
      my %timelist = ();

      open(SESAME, $file);
      for (1 .. 9) {
         my $data = <SESAME>;
      }

      while (my $data = <SESAME>) {
         my @items = split(/,/, $data);
         my $done = 0;

         for (my $i = 0; $i < (@typeobjects + 0); $i++) {
            my $dothis = 1;
            my $objs = ();

            chomp $items[$typeobjects[$i]];
            $objs = $items[$typeobjects[$i]];

            if ($serviceindex >= 0) {
               if ($typeobjects[$i] == $sportindex) {
                  if (!($objs eq "ftp-data")) {
                     $dothis = 0;
                  } else {
                     $done = 1;
                  }
               } else {
                  if ($done) { 
                     $dothis = 0;
                  }
               }
            }

            if ($dothis) {
               if ($objs && (!(($objs eq "0.0.0.0") || ($objs eq "0:0:0:0:0:0")))) {
                  my $count = 0;

                  $timelist{$items[0], $objs}++;

                  if ($srcdataindex >= 0) {
                     $count += $items[$srcdataindex];
                  }
                  if ($dstdataindex >= 0) {
                     $count += $items[$dstdataindex];
                  }
                  $objectlist{$objs}+= $count;
               }
            }
         }
      }
   
      for my $objs (sort { $objectlist{$b} <=> $objectlist{$a} } keys %objectlist) {
         if ($objs && (!(($objs eq "0.0.0.0") || ($objs eq "0:0:0:0:0:0") || ($objs eq " ") || $objs eq "(null)"))) {
            if (!(($objs eq "ip") && ($objectlist{"ip"} == 0))) {
               push @objects, $objs;
            }
         }
      }
   
      if ($num > 0) {
         splice @objects, $num;
      }

      seek(SESAME, 0, 0);
      for (1 .. 9) { 
         my $data = <SESAME>;
      }
   
      if ($protoindex >= 0) {
         if ($daddrindex >= 0) {
            push @objects, "mcast";
         }
      }

      my $ncnt = 0;
      my $ocnt = 0;

      for (my $i = 0; $i < (@objects + 0); $i++) {
         for (my $x = 0; $x < (@dataobjects + 0); $x++) {
            for ($columns[$dataobjects[$x]]) {
               /Label|Tot|Host|Src|Out|SApp|ds/             and do {
                  $opts[$ind++]          = "DS:$objectIn$ncnt:GAUGE:$STEP:U:$maxval";
                  $line_args[$lineind++] = "DEF:alphaIn$ncnt=$RRD:objectIn$ncnt:AVERAGE";
                  $line_args[$lineind++] = "CDEF:ralphaIn$ncnt=alphaIn$ncnt,$STEP,/";
                  $ncnt++;
               };

               /Dst|In|DApp|Trans|Dur|Time|dd/  and do {
                  $opts[$ind++]          = "DS:$objectOut$ocnt:GAUGE:$STEP:$minval:U";
                  $line_args[$lineind++] = "DEF:alphaOut$ocnt=$RRD:objectOut$ocnt:AVERAGE";
                  $line_args[$lineind++] = "CDEF:ralphaOut$ocnt=alphaOut$ocnt,$STEP,/";
                  $ocnt++;
               };
            }
         }
      }

   } else {
      my $ncnt = 0;
      my $ocnt = 0;

      shift @columns;
      push @objects, @columns;
      @columns = split(/,/, $COLUMNS);

      for (my $i = 0; $i < (@objects + 0); $i++) {
         for ($objects[$i]) {
            /Tot|Src|ds/             and do {
               if ($percent) {
                  for ($objects[$i]) {
                     /Src/ and do {
                        $opts[$ind++]          = "DS:$objectIn$ncnt:GAUGE:$STEP:U:$maxval";
                        $line_args[$lineind++] = "DEF:alphaIn$ncnt=$RRD:objectIn$ncnt:AVERAGE";
                        $line_args[$lineind++] = "CDEF:ralphaIn$ncnt=alphaIn$ncnt,$STEP,/";
                        $ncnt++;
                     };
                  }
               } else {
                  $opts[$ind++]          = "DS:$objectIn$ncnt:GAUGE:$STEP:U:$maxval";
                  $line_args[$lineind++] = "DEF:alphaIn$ncnt=$RRD:objectIn$ncnt:AVERAGE";
                  $line_args[$lineind++] = "CDEF:ralphaIn$ncnt=alphaIn$ncnt,$STEP,/";
                  $ncnt++;
               };
            };

            /Label|Host|Out|SApps/             and do {
               $opts[$ind++]          = "DS:$objectIn$ncnt:GAUGE:$STEP:U:$maxval";
               $line_args[$lineind++] = "DEF:alphaIn$ncnt=$RRD:objectIn$ncnt:AVERAGE";
               $line_args[$lineind++] = "CDEF:ralphaIn$ncnt=alphaIn$ncnt,$STEP,/";
               $ncnt++;
            };

            /Dst|dd/  and do {
               if ($percent) {
                  for ($objects[$i]) {
                     /Dst/ and do {
                        $opts[$ind++]          = "DS:$objectOut$ocnt:GAUGE:$STEP:$minval:U";
                        $line_args[$lineind++] = "DEF:alphaOut$ocnt=$RRD:objectOut$ocnt:AVERAGE";
                        $line_args[$lineind++] = "CDEF:ralphaOut$ocnt=alphaOut$ocnt,$STEP,/";
                        $ocnt++;
                     };
                  }
               } else {
                  $opts[$ind++]          = "DS:$objectOut$ocnt:GAUGE:$STEP:$minval:U";
                  $line_args[$lineind++] = "DEF:alphaOut$ocnt=$RRD:objectOut$ocnt:AVERAGE";
                  $line_args[$lineind++] = "CDEF:ralphaOut$ocnt=alphaOut$ocnt,$STEP,/";
                  $ocnt++;
               }
            };

            /In|DApp|Trans|Dur|Time/  and do {
               $opts[$ind++]          = "DS:$objectOut$ocnt:GAUGE:$STEP:$minval:U";
               $line_args[$lineind++] = "DEF:alphaOut$ocnt=$RRD:objectOut$ocnt:AVERAGE";
               $line_args[$lineind++] = "CDEF:ralphaOut$ocnt=alphaOut$ocnt,$STEP,/";
               $ocnt++;
            };
         }
      }
   }

   my %inColors;
   my %outColors;

   my @outcolors = ( "#0101bc", "#808080", "#cc0000", "#01b701", "#ddc03b", "#cc33cc", "#4a4a4a", "#3180bc", "#dd5902", "#9c0000", "#663399", "#33cc33",
                     "#a87dd3", "#5858d8", "#b6b6b6", "#a95454", "#bc8e04", "#137e12", "#510051", "#a0a0a0", "#015680", "#dfae8e", "#00d000", "#e28484" );
   my @incolors  = ( "#5a79fd", "#959595", "#ee0000", "#01d000", "#f5d541", "#cc00ff", "#595959", "#43acfe", "#ff6600", "#b60000", "#883dd3", "#33ff33",
                     "#c794fb", "#6666ff", "#cccccc", "#cc6666", "#dba606", "#179d16", "#660066", "#bbbbbb", "#006699", "#fcc6a2", "#00f000", "#fc9494" );

   my $colorcnt = 24;
    
   if ($protoindex >= 0) {
      %outColors  = (
         tcp   => "#3030A0", udp   => "#008000", icmp  => "#800000", igmp  => "#008080",
         ospf  => "#8000A0", pim   => "#808080", mcast => "#808000", ip    => "#707070"
      );
    
      %inColors = (
         tcp   => "#4040e0", udp   => "#00f000", icmp  => "#e00000", igmp  => "#00e0e0",
         ospf  => "#e000e0", pim   => "#e0e0e0", mcast => "#e0e000", ip    => "#b0b0b0"
      );
    
   } else {
      if ($serviceindex >= 0) {
         %outColors  = (
            afs3call => "#808080",    afs3fsrv => "#808080",   afs3kasrv => "#808080",
           afs3prsrv => "#808080",   afs3vlsrv => "#808080",  afs3volsrv => "#808080",
                 aol => "#de2d31",        arcp => "#808080",       argus => "#f5d541",
              ashwin => "#8e0d01",
              bootps => "#cf4334",  cslistener => "#808080",     dditcpl => "#808080",
              domain => "#800080",      dtspcd => "#808080",      finger => "#808080",
                 ftp => "#808080", gnutellartr => "#808080", gnutellasvc => "#808080",
              groove => "#808080",   h323hcall => "#808080",        hbci => "#808080",
                http => "#3180bc",     httpalt => "#808080",       https => "#808080",
                 ici => "#808080",       ident => "#808080",        imap => "#808080",
               imaps => "#808080",        imsp => "#808080",     imtcmcs => "#808080",
                 ipp => "#808080",         irc => "#808080",       irdmi => "#808080",
               kazaa => "#808080",    kerberos => "#808080",  kerberosiv => "#808080",
                kpop => "#808080",      krb524 => "#808080",        ldap => "#808080",
      "microsoft-ds" => "#800080",        msnp => "#808080", msstreaming => "#808080",
    "micromuse-ncps" => "#00B000",  "ms-sql-s" => "#B0B000",      msdfsr => "#20A0A0",
    "micromuse-ncpw" => "#008000",
                name => "#808080",  netbiosdgm => "#808080",   netbiosns => "#808080",
          netbiosssn => "#808080",  nfsdstatus => "#808080",     nicname => "#808080",
                 nkd => "#808080",        nntp => "#808080",       ntalk => "#808080",
                 ntp => "#808080",      osunms => "#808080",     outlook => "#bebebe",
                pop3 => "#0101bc",       pop3s => "#808080",        pptp => "#808080",
               quake => "#808080",         rfb => "#808080",      router => "#008080",
                rsip => "#808080",        rtsp => "#808080", searchagent => "#808080",
               shell => "#02ce02",        smtp => "#808080",        snmp => "#808080",
            sscagent => "#808080",         ssh => "#808080",      sunrpc => "#808080",
              svrloc => "#808080",   synoptics => "#808080",      syslog => "#808080",
              telnet => "#808080",        time => "#808080",   ultrahttp => "#808080",
          upsonlinet => "#808080",  vcomtunnel => "#808080",      ypserv => "#808080",
           zephyrclt => "#808080",       other => "#900000"
         );

         %inColors  = (
            afs3call => "#b0b0b0",    afs3fsrv => "#b0b0b0",   afs3kasrv => "#b0b0b0",
           afs3prsrv => "#b0b0b0",   afs3vlsrv => "#b0b0b0",  afs3volsrv => "#b0b0b0",
                 aol => "#fca633",        arcp => "#b0b0b0",       argus => "#ffff66",
              ashwin => "#bc2613",
              bootps => "#fe5442",  cslistener => "#b0b0b0",     dditcpl => "#b0b0b0",
              domain => "#e000e0",      dtspcd => "#b0b0b0",      finger => "#b0b0b0",
                 ftp => "#b0b0b0", gnutellartr => "#b0b0b0", gnutellasvc => "#b0b0b0",
              groove => "#b0b0b0",   h323hcall => "#b0b0b0",        hbci => "#b0b0b0",
                http => "#43acfe",     httpalt => "#b0b0b0",       https => "#b0b0b0",
                 ici => "#b0b0b0",       ident => "#b0b0b0",        imap => "#b0b0b0",
               imaps => "#b0b0b0",        imsp => "#b0b0b0",     imtcmcs => "#b0b0b0",
                 ipp => "#b0b0b0",         irc => "#b0b0b0",       irdmi => "#b0b0b0",
               kazaa => "#b0b0b0",    kerberos => "#b0b0b0",  kerberosiv => "#b0b0b0",
                kpop => "#b0b0b0",      krb524 => "#b0b0b0",        ldap => "#b0b0b0",
      "microsoft-ds" => "#b000b0",        msnp => "#b0b0b0", msstreaming => "#b0b0b0",
    "micromuse-ncps" => "#00E000",  "ms-sql-s" => "#E0E000",      msdfsr => "#20C0C0",
    "micromuse-ncpw" => "#00B000",
                name => "#b0b0b0",  netbiosdgm => "#b0b0b0",   netbiosns => "#b0b0b0",
          netbiosssn => "#b0b0b0",  nfsdstatus => "#b0b0b0",     nicname => "#b0b0b0",
                 nkd => "#b0b0b0",        nntp => "#b0b0b0",       ntalk => "#b0b0b0",
                 ntp => "#b0b0b0",      osunms => "#b0b0b0",     outlook => "#fefefe",
                pop3 => "#5a79fd",       pop3s => "#b0b0b0",        pptp => "#b0b0b0",
               quake => "#b0b0b0",         rfb => "#b0b0b0",      router => "#00e0e0",
                rsip => "#b0b0b0",        rtsp => "#b0b0b0", searchagent => "#b0b0b0",
               shell => "#01e901",        smtp => "#b0b0b0",        snmp => "#b0b0b0",
            sscagent => "#b0b0b0",         ssh => "#b0b0b0",      sunrpc => "#b0b0b0",
              svrloc => "#b0b0b0",   synoptics => "#b0b0b0",      syslog => "#b0b0b0",
              telnet => "#b0b0b0",        time => "#b0b0b0",   ultrahttp => "#b0b0b0",
          upsonlinet => "#b0b0b0",  vcomtunnel => "#b0b0b0",      ypserv => "#b0b0b0",
           zephyrclt => "#b0b0b0",       other => "#f00000"
         );

      } else {
         if (@typeobjects + 0) {
            for (my $i = 0; $i < (@objects + 0); $i++) {
               $inColors{$objects[$i]}  =  $incolors[$i % $colorcnt];
               $outColors{$objects[$i]} = $outcolors[$i % $colorcnt];
            }
         } else {
            $inColors{$objects[0]} = $incolors[0];
            $outColors{$objects[0]} = $outcolors[0];
         }
      }
   }

   if ((@dataobjects + 0) == 0) {
      printf "usage: $0 metric(s) object [ragraph-options] [ra-options]\n";
      exit;
   }
   
   if (($srcdataindex < 0) || ($dstdataindex < 0)) {
      $split = 0;
   }

   print "DEBUG: RagraphGenerateRRD: split $split lower $lower\n" if $debug;
   
   my $col;
   my $date;
   
   if (($END - $START) > (60 * 60 * 24)) {
      $date  = strftime "%a %b %e %Y", localtime($START);
      $date .= " - ";
      $date .= strftime "%a %b %e %Y", localtime($END);
    
   } else {
      $date  = strftime "%a %b %e %Y", localtime($START);
   }
    
   $line_args[$lineind++] = "COMMENT:$date\\c";
   my @comments=split (/\n/, $comment) if $comment;
   foreach (@comments) {$line_args[$lineind++] = "COMMENT:$_\\c"}
   $line_args[$lineind++] = "COMMENT:\\s";
   
   if (!(($dspktindex >= 0) || ($ddpktindex >= 0) ||
         ($dsbyteindex >= 0) || ($ddbyteindex >= 0))) {
      if ($fill && $split) {
         $line_args[$lineind++] = "HRULE:0#ffffff";
      } else {
         $line_args[$lineind++] = "HRULE:0#888888";
      }
   }
   
   my $style;
   my $method;
   
   if ($fill) {
      $style = "AREA";
   } else {
      $style = "LINE1";
   }
   
   if ($stack) {
      $method = "STACK";
   } else {
      $method = $style;
   }

   if (@typeobjects + 0) {
      my $ncnt = 0;
      my $ocnt = 0;
      my $object;

      for (my $i = 0; $i < (@objects + 0); $i++) {
         if (!($objects[$i] eq "")) {
            my $tobj = $objects[$i];
            $tobj =~ s/:/\\:/g;
            for (my $x = 0; $x < (@dataobjects + 0); $x++) {
               for ($columns[$dataobjects[$x]]) {
                  /Label|Host|Tot|Src|Out|SApp|ds/   and do {
                     if (!($col = $inColors{$objects[$i]})) {
                        $col = "#808070";
                     }
                     for ($columns[$dataobjects[$x]]) {
                        /Tot/   and do {
                           $object = sprintf "%-2.2s%-*.*s \l", " ", $objwidth, $objwidth, $tobj;
                        };
                        /Out/   and do {
                           $object = sprintf "%-4.4s%-*.*s \l", "out ", $objwidth, $objwidth, $tobj;
                        };
                        /Host|Src|SApp|ds/   and do {
                           $object = sprintf "%-4.4s%-*.*s \l", "src ", $objwidth, $objwidth, $tobj;
                        };
                     }
                     if ($ncnt == 0) {
                        $line_args[$lineind++] = "$style:ralphaIn$i$col:$object:";
                     } else {
                        $line_args[$lineind++] = "$method:ralphaIn$i$col:$object:";
                     }
                     $ncnt++;
                  };
               }
            }
         }
      }

      $line_args[$lineind++] = "COMMENT:\\s";
      $line_args[$lineind++] = "COMMENT:\\s";
      $line_args[$lineind++] = "COMMENT:\\s";
      $line_args[$lineind++] = "COMMENT:\\s";

      for (my $i = 0; $i < (@objects + 0); $i++) {
         if (!($objects[$i] eq "")) {
            my $tobj = $objects[$i];
            $tobj =~ s/:/\\:/g;
            for (my $x = 0; $x < (@dataobjects + 0); $x++) {
               for ($columns[$dataobjects[$x]]) {
                  /Dst|In|DApp|dd/  and do {
                     if (!($col = $outColors{$objects[$i]})) {
                        $col = "#707070";
                     }
                     for ($columns[$dataobjects[$x]]) {
                        /In/  and do {
                           $object = sprintf "%-4.4s%-*.*s \l", "in  ", $objwidth, $objwidth, $tobj;
                        };
                        /Dst|DApp|dd/  and do {
                           $object = sprintf "%-4.4s%-*.*s \l", "dst ", $objwidth, $objwidth, $tobj;
                        };
                     }
                     if ($ocnt == 0) {
                        $line_args[$lineind++] = "$style:ralphaOut$i$col:$object:";
                     } else {
                        $line_args[$lineind++] = "$method:ralphaOut$i$col:$object:";
                     }
                     $ocnt++;
                  };
                  /Trans|Dur|Time/  and do {
                     if (!($col = $inColors{$objects[$i]})) {
                        $col = "#a0a0a0";
                     }
                     $object = sprintf "%-*.*s \l", $objwidth, $objwidth, $tobj;
                     if ($ocnt == 0) {
                        $line_args[$lineind++] = "$style:ralphaOut$i$col:$object:";
                     } else {
                        $line_args[$lineind++] = "$method:ralphaOut$i$col:$object:";
                     }
                     $ocnt++;
                  };
               }
            }
         }
      }

      $line_args[$lineind++] = "COMMENT:\\s";
      $line_args[$lineind++] = "COMMENT:\\s";

   } else {
      my $ncnt = 0;
      my $ocnt = 0;
      my $legend = "";;

      for (my $x = 0; $x < (@objects + 0); $x++) {
         for (my $object = $objects[$x]) {
            /Tot|Src|ds/          and do {
               if (!($col = $outcolors[$ncnt])) {
                  $col = "#a0a0a0";
               }
               if ($percent) {
                  for ($objects[$x]) {
                     /ds/     and do { $legend = "p".$objects[$x]; };
                     /Tot|Src/    and do {
                        if ($ncnt == 0) {
                           $line_args[$lineind++] = "$style:ralphaIn$ncnt$col:$legend";
                        } else {
                           $line_args[$lineind++] = "$method:ralphaIn$ncnt$col:$legend";
                        }
                        $ncnt++;
                        $legend = "";
                     };
                  }
               } else {
                  if ($ncnt == 0) {
                     $line_args[$lineind++] = "$style:ralphaIn$ncnt$col:$object";
                  } else {
                     $line_args[$lineind++] = "$method:ralphaIn$ncnt$col:$object";
                  }
                  $ncnt++;
               }
            };

            /Label|Host|Out|SApp/    and do {
               if (!($col = $outcolors[$ncnt])) {
                  $col = "#a0a0a0";
               }
               if ($ncnt == 0) {
                  $line_args[$lineind++] = "$style:ralphaIn$ncnt$col:$object";
               } else {
                  $line_args[$lineind++] = "$method:ralphaIn$ncnt$col:$object";
               }
               $ncnt++;
            };

            /Dst|dd/   and do {
               if (!($col = $outcolors[$ocnt])) {
                  $col = "#707070";
               }
               if ($percent) {
                  for ($objects[$x]) {
                     /ds/     and do { $legend = "p".$objects[$x]; };
                     /Src/    and do {
                        if ($ocnt == 0) {
                           $line_args[$lineind++] = "$style:ralphaOut$ocnt$col:$legend";
                        } else {
                           $line_args[$lineind++] = "$method:ralphaOut$ocnt$col:$legend"; 
                        }
                        $ocnt++;
                        $legend = "";
                     };
                  }
               } else {
                  if ($ocnt == 0) {
                     $line_args[$lineind++] = "$style:ralphaOut$ocnt$col:$object";
                  } else {
                     $line_args[$lineind++] = "$method:ralphaOut$ocnt$col:$object";
                  }
                  $ocnt++;
               }
            };

            /In|DApp|Trans|Dur|Time/   and do {
               if (!($col = $outcolors[$ocnt % $colorcnt])) {
                  $col = "#707070";
               }
               if ($ocnt == 0) {
                  $line_args[$lineind++] = "$style:ralphaOut$ocnt$col:$object";
               } else {
                  $line_args[$lineind++] = "$method:ralphaOut$ocnt$col:$object";
               }
               $ocnt++;
            };
         }
      }
   }
   
   for (my $x = 0; $x < (@columns + 0); $x++) {
      for ($columns[$x]) {
         /^SIntPkt/ and do {$power[$x] = $STEP ; };
         /^DIntPkt/ and do {$power[$x] = $STEP ; };
         /Pkts/     and do {$power[$x] = 1.0 ; };
         /Rate/     and do {$power[$x] = $STEP ; };
         /Load/     and do {$power[$x] = $STEP ; };
         /Bytes/    and do {$power[$x] = 1.0 * 8.0; };
         /Jitter/   and do {$power[$x] = 1.0; };
         /Loss/     and do {$power[$x] = 1.0 ; };
         /Trans/    and do {$power[$x] = $STEP ; };
         /AvgDur/   and do {$power[$x] = $STEP ; };
         /Win/      and do {$power[$x] = $STEP ; };
         /dDur/     and do {$power[$x] = $STEP ; };
         /dsTime/   and do {$power[$x] = $STEP ; };
         /dlTime/   and do {$power[$x] = $STEP ; };
         /^dsPkts/  and do {
            if ($percent) {
               $power[$x] = $STEP;
            } else {
               $power[$x] = 1.0;
            }
         };
         /^ddPkts/  and do {
            if ($percent) {
               $power[$x] = $STEP;
            } else {
               $power[$x] = 1.0;
            }
         };
         /^dsBytes/ and do {
            if ($percent) {
               $power[$x] = $STEP;
            } else {
               $power[$x] = 1.0;
            }
         };
         /^ddBytes/ and do {
            if ($percent) {
               $power[$x] = $STEP;
            } else {
               $power[$x] = 1.0;
            }
         };
      }
   }

   if ($yaxislabels > 1) {
      if (($ddurindex >= 0) && (($dstimeindex >= 0) || ($dltimeindex >= 0))) {
         $yaxislabel = "Delta Time (secs)" ;
      }
      if (($dspktindex >= 0) && ($ddpktindex >= 0)) {
         $yaxislabel = "Delta Pkts (secs)" ;
      }
      if (($dsbyteindex >= 0) && ($ddbyteindex >= 0)) {
         $yaxislabel = "Delta Bytes (secs)" ;
      }
   }
   
   if ($usryaxis eq "") {
      if ($split) {
         if ($probe) {
            $yaxisstr = "inbound(-).outbound(+) ";
         } else {
            $yaxisstr = "dest(-).src(+) ";
         }
      } else {
         $yaxisstr = "";
         if ($yaxislabels > 1) {
            $yaxislabel = "" ;
         }
      }
      $yaxisstr .= $yaxislabel;

   } else {
      $yaxisstr = $usryaxis;
   }
    
   $opts[$ind] = "RRA:AVERAGE:0.5:1:$RUNS"; 
}


sub RagraphGenerateRRD {
   my $data;

   print "DEBUG: RagraphGenerateRRD($tmpfile)\n" if $debug;

   open(SESAME, $tmpfile);
    
   for (1 .. 9) {
      $data = <SESAME>;
   }
   
   print "DEBUG: RagraphGenerateRRD: RRDs::create $RRD, @opts\n" if $debug;
   
   RRDs::create $RRD, @opts;
   
   $ERROR = RRDs::error;
   if ($ERROR) {
     print "DEBUG: RagraphGenerateRRD: $RRD: $ERROR\n" if $debug;
     die "$0: unable to create `$RRD': $ERROR\n";
   }
   
   my $last = RRDs::last $RRD;
   if ($ERROR = RRDs::error) {
     die "$0: unable to get last `$RRD': $ERROR\n";
   }
   
   @opts = ();

   my $startime = $START;
   my $lasttime = $START + $STEP;
   
   my %objectvals;
   my %bins;
   my @vals;
   
   for (my $i = 0; $i < (@objects + 0); $i++) {
      $objectvals{$objects[$i], "src"} = 0;
      $objectvals{$objects[$i], "dst"} = 0;
   }

   while (my $data = <SESAME>) {
      my ($thistime, $thattime, $FRAC);
      @opts = split(/,/, $data);
   
      $thattime = $opts[0];
      (($thistime, $FRAC) = $thattime =~ m/(\d*)\.(.*)/);

      if ($bins{$thistime}++ == 0) {
      }

      if (@typeobjects + 0) {
         for (my $i = 0; $i < (@typeobjects + 0); $i++) {
            my $thisobject = $opts[$typeobjects[$i]];
            my $dothis = 1;

            chomp $thisobject;
  
            if ($daddrindex >= 0) {
               my @addr = split(/./, $opts[2]);
               if (($addr[0] & 0xF0) == 0xE0) {
                  $thisobject = "mcast";
               }
            }
            if ($serviceindex >= 0) {
               if ($typeobjects[$i] == $sportindex) {
                  if (!($thisobject eq "ftp-data")) {
                     $dothis = 0;
                  }
               }
            }

            if ($dothis > 0) {
               for (my $x = 0; $x < (@dataobjects + 0); $x++) {
                  my $dataindex = $dataobjects[$x];
                  for ($columns[$dataindex]) {
                     /Label|Host|Tot|Src|Out|SApp|ds/       and do {
                        $objectvals{$thistime, $thisobject, "src"} += $opts[$dataindex] * $power[$dataindex];
                     };
    
                     /Dst|In|DApp|Trans|Dur|Time|dd/  and do {
                        $objectvals{$thistime, $thisobject, "dst"} += $opts[$dataindex] * $power[$dataindex];
                     };
                  }
               }
               print "DEBUG: RagraphGenerateRRD - thisobject is $thisobject\n" if $debug;

            } else {
            }
         }

      } else {
         my $label;

         for (my $i = 0; $i < (@objects + 0); $i++) {
            for ($objects[$i]) {
               /Label|Host|Tot|Src|Out|SApp|ds/       and do { $label = "src"; };
               /Dst|In|DApp|Trans|Dur|Time|dd/  and do { $label = "dst"; };
            }
            $objectvals{$thistime, $objects[$i], $label} += $opts[$i + 1] * $power[$i + 1];
         }
      }
   }
   
   close(SESAME);

   for my $thisbin (sort keys %bins) {
      my $prime = $thisbin;
      my $nvalue = 0;
      my $ovalue = 0;

      my $divisor = 0;
      for (my $i = 0; $i < (@objects + 0); $i++) {
         if (@typeobjects + 0) {
            for (my $x = 0; $x < (@dataobjects + 0); $x++) {
               my $dataindex = $dataobjects[$x];

               for ($columns[$dataindex]) {
                  /Dst|In|DApp|Trans|Dur|Time|dd/  and do {
                     if (!($nvalue = $objectvals{$thisbin, $objects[$i], "dst"})) {
                        $nvalue = 0;
                     }
                     if ($split) {
                        if ($nvalue == 0) {
                           $prime .= ":$nvalue";
                        } else {
                           if ($invert) {
                              $prime .= ":$nvalue";
                           } else {
                              $prime .= ":-$nvalue";
                           }
                        }
                     } else {
                        $prime .= ":$nvalue";
                     }
                  };
 
                  /Label|Host|Tot|Src|Out|SApp|ds/       and do {
                     if (!($ovalue = $objectvals{$thisbin, $objects[$i], "src"})) {
                        $ovalue = 0;
                     }
                     if ($split) {
                        if ($ovalue == 0) {
                           $prime .= ":$ovalue";
                        } else {
                           if ($invert) {
                              $prime .= ":-$ovalue";
                           } else {
                              $prime .= ":$ovalue";
                           }
                        }
                     } else {
                        $prime .= ":$ovalue";
                     }
                  };
               }
            }

         } else {
            my $label = '';
            for ($objects[$i]) {
               /Tot|Src|ds/                   and do {
                  if ($percent) {
                     for ($objects[$i]) {
                        /ds/              and do { $divisor = $objectvals{$thisbin, $objects[$i], "src"}; };
                        /Src/             and do { $label   = "src"; };
                     }
                  } else {
                     $label = "src";
                  };
               };

               /Dst|dd/                   and do {
                  if ($percent) {
                     for ($objects[$i]) {
                        /dd/              and do { $divisor = $objectvals{$thisbin, $objects[$i], "dst"}; };
                        /Dst/             and do { $label = "dst"; };
                     }
                  } else {
                     $label = "dst";
                  }
               };

               /Label|Host|Out|SApp/      and do { $label = "src"; };
               /In|DApp|Trans|Dur|Time/   and do { $label = "dst"; };
            }

            if (!($label eq "")) {
               if ($percent) {
                  if ($objectvals{$thisbin, $objects[$i], $label}) {
                     $nvalue = ($divisor * 100.0)/$objectvals{$thisbin, $objects[$i], $label};
                  } else {
                     $nvalue = 0.0;
                  }
               } else {
                  $nvalue = $objectvals{$thisbin, $objects[$i], $label};
               }

               if ($split && ($label eq "dst")) {
                  if ($invert) {
                     $prime .= ":$nvalue";
                  } else {
                     $prime .= ":-$nvalue";
                  }
               } else {
                  if ($invert) {
                     $prime .= ":-$nvalue";
                  } else { 
                     $prime .= ":$nvalue";
                  } 
               }
            }
         }
      }

      print "DEBUG: RagraphGenerateRRD - RRDs::update $RRD, $prime\n" if $debug;

      RRDs::update $RRD, "$prime";

      if ($ERROR = RRDs::error) {
         die "$0: unable to update `$RRD': $ERROR\n";
      }
   }
}



sub RagraphGeneratePNG {
   my @rrd_pngs = ($RRD, $PNG);
   my @rrd_args = (
         "--base", "1000",
         "--vertical-label", $yaxisstr,
         "--start", $START,
         "--end", $END,
         "--color", "BACK#EAEAE0",
         "--color", "SHADEA#EAEAE0",
         "--color", "SHADEB#EAEAE0",
         "--color", "CANVAS#FAFAF0",
         "--interlace", "--imgformat","PNG",
   );

   print "DEBUG: RagraphGeneratePNG - rrd_pngs @rrd_pngs\n" if $debug;
   print "DEBUG: RagraphGeneratePNG - rrd_args @rrd_args\n" if $debug;

   if ($SECONDS < 360) {
      if ($SECONDS >= 240) {
         push @rrd_args, ("--x-grid", "SECOND:20:MINUTE:1:MINUTE:1:0:%H:%M:%S");
      } else {
         if ($SECONDS > 60) {
            push @rrd_args, ("--x-grid", "SECOND:10:SECOND:30:SECOND:30:0:%H:%M:%S");
         } else {
            if ($SECONDS > 20) {
               push @rrd_args, ("--x-grid", "SECOND:5:SECOND:10:SECOND:10:0:%H:%M:%S");
            } else {
               if ($SECONDS > 5) {
                  push @rrd_args, ("--x-grid", "SECOND:1:SECOND:5:SECOND:5:0:%H:%M:%S");
               } else {
                  push @rrd_args, ("--x-grid", "SECOND:1:SECOND:1:SECOND:1:0:%H:%M:%S");
               }
            }
         }
      }
   }

   if (!($fontstr eq "")) {
      push @rrd_args, ("--font", $fontstr); 
   }
   if (!($fontmode eq "")) {
      push @rrd_args, ("--font-render-mode", $fontmode); 
   }
   if ($fontsmooth) {
      push @rrd_args, ("--font-smoothing-threshold", $fontsmooth); 
   }
   if ($slope) {
      push @rrd_args, ("--slope-mode"); 
   }
   if ($nolegend) {
      push @rrd_args, ("--no-legend"); 
   }
   if (!($watermark eq "")) {
      push @rrd_args, ("--watermark", $watermark); 
   }
   if (!($imginfo eq "")) {
      push @rrd_args, ("--imginfo", $imginfo); 
   }
   if ($zoom) {
      push @rrd_args, ("--zoom", $zoom); 
   }
   if ($altautoscale) {
      push @rrd_args, ("--alt-autoscale"); 
   }
   if ($altautoscalemax) {
      push @rrd_args, ("--alt-autoscale-max"); 
   }
   if ($nogridfit) {
      push @rrd_args, ("--no-gridfit"); 
   }
   if (!($xgrid eq "")) {
      push @rrd_args, ("--x-grid", $xgrid); 
   }
   if (!($ygrid eq "")) {
      push @rrd_args, ("--y-grid", $ygrid); 
   }
   if ($altygrid) {
      push @rrd_args, ("--alt-y-grid"); 
   }
   if ($title) {
      push @rrd_args, ("--title", $title); 
   }
   if ($unitlen) {
      push @rrd_args, ("--units-length", $unitlen); 
   }
   if ($unitsex) {
      push @rrd_args, ("--units-exponent", $unitsex); 
   }
   if ($units) {
      push @rrd_args, ("--units=si"); 
   }
   if ($graphonly) {
      $rrd_args[++$#rrd_args] = "--only-graph";
   }
   if ($rigid) {
      $rrd_args[++$#rrd_args] = "--rigid";
   }
   if ($log) {
      $rrd_args[++$#rrd_args] = "--log";
   }
   if ($width) {
      $rrd_args[++$#rrd_args] = "--width";
      $rrd_args[++$#rrd_args] = $width;
   }
   if ($height) {
      $rrd_args[++$#rrd_args] = "--height";
      $rrd_args[++$#rrd_args] = $height;
   }
   if (!($rigid) && ($upper || $lower)) {
      $rrd_args[++$#rrd_args] = "--rigid";
   }
   if ($upper) {
      my $upperval = $upper;
      for ($upper) {
         /k|K/  and do { $upperval *= 1000; };
         /m|M/  and do { $upperval *= 1000000; };
         /g|G/  and do { $upperval *= 1000000000; };
      }
      $rrd_args[++$#rrd_args] = "--upper-limit";
      $rrd_args[++$#rrd_args] = $upperval;
   }
   if ($lower) {
      my $lowerval = $lower;
      for ($lower) {
         /k|K/  and do { $lowerval *= 1000; };
         /m|M/  and do { $lowerval *= 1000000; };
         /g|G/  and do { $lowerval *= 1000000000; };
      }
      if ($split && ($lowerval > 0)) {
         $lowerval = -$lowerval;
      }
    
      $rrd_args[++$#rrd_args] = "--lower-limit";
      $rrd_args[++$#rrd_args] = $lowerval;
   }

   if ($norrdwmark) {
      $rrd_args[++$#rrd_args] = "--disable-rrdtool-tag";
   }

   print "DEBUG: RRDs::last $RRD\n" if $debug;
   
   my $last = RRDs::last $RRD;
   if ($ERROR = RRDs::error) {
     print "DEBUG: ERROR $ERROR\n" if $debug;
     die "$0: unable to get last `$RRD': $ERROR\n";
   }

   push @rrd_args, @line_args;

   while (@rrd_pngs) {
      my $RRD = shift(@rrd_pngs);
      my $PNG = shift(@rrd_pngs);

      if (open(SESAME, $RRDARG)) {
         @rrd_args = ();
         my $i = 0;
   
         while (my $data = <SESAME>) {
            chomp $data;
            $rrd_args[++$#rrd_args] = $data;
         };

      } else {
         open(SESAME, ">$RRDARG");
         for (my $x = 0; $x < (@rrd_args + 0); $x++) {
            printf SESAME "%s\n", $rrd_args[$x];
         }
         close(SESAME);
      }

      print "DEBUG: RagraphGeneratePNG RRDs::graph $PNG, @rrd_args\n" if $debug;

      my ($graphret,$xs,$ys) = RRDs::graph $PNG, @rrd_args;
   
      if ($ERROR = RRDs::error) {
         print "ERROR: $ERROR\n";
      }
   }
}
