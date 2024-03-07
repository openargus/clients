#!@PERLBIN@
# 
#  Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
#  Copyright (c) 2000-2024 QoSient, LLC
#  All rights reserved.
# 
#  THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
#  AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
#  EXPRESS PERMISSION OF QoSIENT, LLC.
# 
#  QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
#  SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
#  SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
#  IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
#  ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
#  THIS SOFTWARE.
#
#  
#   ra() based host use report
#  
#  $Id: //depot/gargoyle/clients/examples/rahosts/rahosts.pl#5 $
#  $DateTime: 2014/10/07 15:00:33 $
#  $Change: 2938 $
# 

#
# Complain about undeclared variables
use v5.6.0;
use strict;

local $ENV{PATH} = "$ENV{PATH}:/bin:/usr/bin:/usr/local/bin";

# Used modules
use URI::URL;
use DBI;
use Switch;
use Net::IP;
use File::Which qw/ which /;
use Socket;

use File::Temp qw/ tempfile tempdir /;
use File::Which qw/ which where /;
use Time::Local;

# Global variables
my $debug = 0;
my $drop  = 1;
my $time;
my $database;
my $filter;
my $sort;
my $fields;
my $obj;

my $VERSION = "5.0";                

my ($mode, %items, %addrs, %loc, $local, $sid, $inf, $saddr, $daddr, $taddr, $baddr, $proto, $stype, $sloc, $dloc);

my $quiet = 0;
my $done = 0;
my @args;

my $startseries = 0;
my $startcount = 0;
my $lastseries = 0;
my $lastcount = 0;
my $count = 0;
my $score = 0;
 
my ($user, $pass, $host, $port, $space, $db, $table);
my $dbh;
my $sth;

my $uri     = 0;
my $scheme;
my $netloc;
my $path;

my $datename    = "";
my @results     = ();
my $results_ref = \@results;
my $elements    = "";
my $object      = "";

my $RA;
my $rasql       = which 'rasql';
my $racluster   = which 'racluster';
my $ralabel     = which 'ralabel';
my $rasort      = which 'rasort';

my $ralabelconf = "/usr/argus/ralabel.local.conf";

my $f;
my $fname;
($f,  $fname)   = tempfile();

my @arglist = ();

ARG: while (my $arg = shift(@ARGV)) {
   if (!$done) {
      for ($arg) {
         s/^-q//           && do { $quiet++; next ARG; };
         s/^-w//           && do { $uri = shift (@ARGV); next ARG; };
         s/^-debug//       && do { $debug++; next ARG; };
         s/^-drop//        && do { $drop = 0; next ARG; };
         s/^-dbase$//      && do { $database = shift(@ARGV); next ARG; };
         s/^-t$//          && do { $time = shift(@ARGV); next ARG; };
         s/^-time$//       && do { $time = shift(@ARGV); next ARG; };
         s/^-filter$//     && do { $filter = shift(@ARGV); next ARG; };
         s/^-sort$//       && do { $sort = shift(@ARGV); next ARG; };
         s/^-fields$//     && do { $fields = shift(@ARGV); next ARG; };
         s/^-obj$//        && do { $obj = shift(@ARGV); next ARG; };
      }

   } else {
      for ($arg) {
         s/\(/\\\(/            && do { ; };
         s/\)/\\\)/            && do { ; };
      }
   }
   $arglist[@arglist + 0] = $arg;
}

  if ((not defined $time) || ($time eq "Today")) {
     $time = "-1d";
  }
  if ($obj eq "") {
     $obj = "daddr";
  }
  if ($fields eq "") {
     $fields="stime dur spkts dpkts pcr score";
  }
  if ($sort eq "") {
     $sort="pkts";
  }
  if ($filter eq "") {
     $filter="- ipv6";
  } else {
     $filter="- $filter";
  }
  if ($score eq "") {
     $score = "0";
  }

  RaHostsProcessParameters();
  RaHostsFetchData($fname);
  RaHostsGenerateOutput($fname);
  RaHostsCleanUp($fname);
  exit;

sub RaHostsProcessParameters {
   if ($uri) {
      my $url = URI::URL->new($uri);

      $scheme = $url->scheme;
      $netloc = $url->netloc;
      $path   = $url->path;

      if ($netloc ne "") {
         ($user, $host) = split /@/, $netloc;
         if ($user =~ m/:/) {
            ($user , $pass) = split/:/, $user;
         }
         if ($host =~ m/:/) {
            ($host , $port) = split/:/, $host;
         }
      }
      if ($path ne "") {
         ($space, $db, $table)  = split /\//, $path;
      }

      $dbh = DBI->connect("DBI:$scheme:;host=$host", $user, $pass) || die "Could not connect to database: $DBI::errstr";
      $dbh->do("CREATE DATABASE IF NOT EXISTS $db");
      $dbh->do("use $db");

      # Drop table 'foo'. This may fail, if 'foo' doesn't exist
      # Thus we put an eval around it.

      if ($drop > 0) {
         local $dbh->{RaiseError} = 0;
         local $dbh->{PrintError} = 0;
         eval { $dbh->do("DROP TABLE IF EXISTS $table") };
      }

      # Create a new table 'foo'. This must not fail, thus we don't catch errors.

      my $dbstr = "CREATE TABLE IF NOT EXISTS $table (region VARCHAR(8), sid VARCHAR(64), inf VARCHAR(4), saddr VARCHAR(64) NOT NULL, sloc TINYINT, count INTEGER, hoststring TEXT, PRIMARY KEY ( region,saddr,sid,inf ))";

      print "DEBUG: RaHostsProcessParameters: cmd: $dbstr\n" if $debug;
      $dbh->do($dbstr);
   }
}


sub RaHostsFetchData {
# Start the program

   my $Options = "-L -1 -n -s sid:42 inf saddr:32 daddr:32 proto sloc dloc -c , ";
   $RA = "$rasql -t $time -r 'mysql://root\@localhost/ipMatrix/ip_%Y_%m_%d' -M time 1d  -w - - ip | $ralabel -f $ralabelconf $Options";

   print "DEBUG: RaHostsFetchData: cmd: $RA\n" if $debug;

   my $etherRegex = '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$';
   my $ipv4Regex  = '\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b';
   my $ipv6Regex  = '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))';

   open(SESAME, "$RA |");

   while (my $data = <SESAME>) {
      chomp $data;
      ($sid, $inf, $saddr, $daddr, $proto, $sloc, $dloc) = split (/,/, $data, 7);

      if ($proto && !($proto eq "man")) {
         if ($saddr =~ /$etherRegex/) {
            $stype = "ether";
         } else {
         if ($saddr =~ /$ipv4Regex/) {
            $stype = "ipv4";
         } else {
         if ($saddr =~ /$ipv6Regex/) {
            $stype = "ipv6";
         } else {
         if ($saddr =~ /:/) {
            $stype = "ether";
         }}}}

         if (!(length ($sloc))) { $sloc = 4; }
         if (!(length ($dloc))) { $dloc = 4; }

         if (($sloc >= 3) && ($dloc >= 3)) {
            print "DEBUG: RaHostsFetchData: data: ($sid,$inf,$saddr,$daddr,$proto,$sloc,$dloc) local \n" if $debug;
            $local = 'local';
         } else {
            print "DEBUG: RaHostsFetchData: data: ($sid,$inf,$saddr,$daddr,$proto,$sloc,$dloc) remote \n" if $debug;
            $local = 'remote';
         }

         switch ($stype) {
            case "ipv4"  {
               if ((!($saddr eq "0.0.0.0")) && (!($daddr eq "0.0.0.0"))) {
                  $addrs{$local}{$stype}{$sid}{$inf}{$saddr}++;
                  $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr}++;
                  $addrs{$local}{$stype}{$sid}{$inf}{$daddr}++;
                  $items{$local}{$stype}{$sid}{$inf}{$daddr}{$saddr}++;
                  $loc{$saddr}=$sloc;
                  $loc{$daddr}=$dloc;
               }
            }
            case "ether" { next }
            case "ipv6"  {
               $addrs{$local}{$stype}{$sid}{$inf}{$saddr}++;
               $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr}++;
               $addrs{$local}{$stype}{$sid}{$inf}{$daddr}++;
               $items{$local}{$stype}{$sid}{$inf}{$daddr}{$saddr}++;
               $loc{$saddr}=$sloc;
               $loc{$daddr}=$dloc;
            }
         }
      }
   }
   close(SESAME);
}

sub RaHostsGenerateOutput {
   print "DEBUG: RaHostsGenerateOutput starting\n" if $debug;
   if ($uri) {
      for $local ( sort keys(%items) ) {
      for $stype ( sort keys(%{$items{$local}}) ) {
         my $hoststring;
         switch ($stype) {
            case "ether" { next }
            case "ipv6"  {
               for $sid ( sort keys(%{$items{$local}{$stype}}) ) {
                  for $inf ( sort keys( %{$items{$local}{$stype}{$sid}}) ) {
                     for $saddr ( sort internet keys( %{$items{$local}{$stype}{$sid}{$inf}}) ) {
                        my $cnt = 0;
                        $hoststring = "";

                        $count = RaGetAddressCount($local, $saddr, $stype, $sid, $inf);
                        for $daddr ( sort internet keys( %{$items{$local}{$stype}{$sid}{$inf}{$saddr}}) ) {
                           if ($cnt++ > 0) {
                              $hoststring .= ",";
                           }
                           $hoststring .= "$daddr";
                        }

                        if (length ($hoststring)) {
                           if (!(defined $loc{$saddr})) {
                              $loc{$saddr} = 4;
                           }
                           print "DEBUG: INSERT INTO $table VALUES(?, ?, ?, ?, ?, ?, ?), $local, $sid, $inf, $saddr, $loc{$saddr}, $count, $hoststring\n" if $debug;
                           $dbh->do("INSERT INTO $table VALUES(?, ?, ?, ?, ?, ?, ?)", undef, $local, $sid, $inf, $saddr, $loc{$saddr}, $count, $hoststring);
                        }
                     }
                  }
               }
            }
            case "ipv4"  {
               for $sid ( sort keys(%{$items{$local}{$stype}}) ) {
                  for $inf ( sort keys( %{$items{$local}{$stype}{$sid}}) ) {
                     for $saddr ( sort internet keys( %{$items{$local}{$stype}{$sid}{$inf}}) ) {
                        $hoststring = "";
                        $startseries = 0;
                        $lastseries = 0;
                        $count = RaGetAddressCount($local, $saddr, $stype, $sid, $inf);

                        if ( $quiet == 0 ) {
                           for $daddr ( sort internet keys(%{$items{$local}{$stype}{$sid}{$inf}{$saddr} })) {
                              my $ipaddr = inet_aton($daddr);
                              my $naddr = unpack "N", $ipaddr;

                              if ($startseries > 0) {
                                 if ($naddr == ($lastseries + 1)) {
                                    $lastseries = $naddr;
                                    $lastcount = $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                 } else {
                                    my ($a1, $a2, $a3, $a4) = unpack('C4', pack("N", $lastseries));

                                    if ((($naddr - $lastseries) < 3) && ($a4 == 254)) {
                                       $lastseries = $naddr;
                                       $lastcount = $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                    } else {
                                       my $startaddr = inet_ntoa(pack "N", $startseries);
                                       my $lastaddr  = inet_ntoa(pack "N", $lastseries);

                                       if ($startseries != $lastseries) {
                                          $hoststring .= "$startaddr($startcount)-$lastaddr($lastcount),";
                                          $startseries = $naddr;
                                          $startcount = $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                          $lastseries = $naddr;
                                          $lastcount = $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                       } else {
                                          $hoststring .= "$startaddr($startcount),";
                                          $startseries = $naddr;
                                          $startcount = $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                          $lastseries = $naddr;
                                          $lastcount = $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                       }
                                    }
                                 }

                              } else {
                                 $startseries = $naddr;
                                 $startcount = $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                 $lastseries = $naddr;
                                 $lastcount = $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr};
                              }
                           }
                        }

                        if ($startseries > 0) {
                           my $startaddr = inet_ntoa(pack "N", $startseries);
                           my $lastaddr  = inet_ntoa(pack "N", $lastseries);

                           if ($startseries != $lastseries) {
                              $hoststring .= "$startaddr($startcount)-$lastaddr($lastcount)";
                           } else {
                              $hoststring .= "$startaddr($startcount)";
                           }
                        }

                        if (length ($hoststring)) {
                           if (!(defined $loc{$saddr})) {
                              $loc{$saddr} = 4;
                           }
                           print "DEBUG: INSERT INTO $table VALUES(?, ?, ?, ?, ?, ?, ?), $local, $sid, $inf, $saddr, $loc{$saddr}, $count, $hoststring\n" if $debug;
                           $dbh->do("INSERT INTO $table VALUES(?, ?, ?, ?, ?, ?, ?)", undef, $local, $sid, $inf, $saddr, $loc{$saddr}, $count, $hoststring);
                        }
                     }
                  }
               }
            }
         }
      }
      }

      $dbh->disconnect();

   } else {
      for $local ( sort keys(%items) ) {
      for $stype ( sort keys(%{$items{$local}}) ) {
         switch ($stype) {
            case "ether" { next }
            case "ipv6"  {
               for $sid ( sort keys(%{$items{$local}{$stype}}) ) {
                  for $inf ( sort keys( %{$items{$local}{$stype}{$sid}}) ) {
                     for $saddr ( sort internet keys( %{$items{$local}{$stype}{$sid}{$inf}}) ) {
                        my $cnt = 0;

                        $count = RaGetAddressCount($local, $saddr, $stype, $sid, $inf);
                        print "$local $sid:$inf $saddr: ($count) ";
                        for $daddr ( sort internet keys( %{$items{$local}{$stype}{$sid}{$inf}{$saddr}}) ) {
                           if ($cnt++ > 0) {
                              print ",";
                           }
                           print "$daddr";
                        }
                        print "\n";
                     }
                  }
               }
            }

            case "ipv4"  {
               for $sid ( sort keys(%{$items{$local}{$stype}}) ) {
                  for $inf ( sort keys( %{$items{$local}{$stype}{$sid}}) ) {
                     for $saddr ( sort internet keys( %{$items{$local}{$stype}{$sid}{$inf}}) ) {
                        $startseries = 0;
                        $lastseries = 0;
                        $count = RaGetAddressCount($local, $saddr, $stype, $sid, $inf);
                        print "$local $sid:$inf $saddr: ($count) ";

                        if ( $quiet == 0 ) {
                           for $daddr ( sort internet keys(%{$items{$local}{$stype}{$sid}{$inf}{$saddr} })) {
                              my $ipaddr = inet_aton($daddr);
                              my $naddr = unpack "N", $ipaddr;
                              if ($startseries > 0) {
                                 if ($naddr == ($lastseries + 1)) {
                                    $lastseries = $naddr;
                                    $lastcount = $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                 } else {
                                    my ($a1, $a2, $a3, $a4) = unpack('C4', pack("N", $lastseries));

                                    if ((($naddr - $lastseries) < 3) && ($a4 == 254)) {
                                       $lastseries = $naddr;
                                       $lastcount = $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                    } else {
                                       my $startaddr = inet_ntoa(pack "N", $startseries);
                                       my $lastaddr  = inet_ntoa(pack "N", $lastseries);

                                       if ($startseries != $lastseries) {
                                          print "$startaddr($startcount)-$lastaddr($lastcount),";
                                          $startseries = $naddr;
                                          $startcount = $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                          $lastseries = $naddr;
                                          $lastcount = $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                       } else {
                                          print "$startaddr($startcount),";
                                          $startseries = $naddr;
                                          $startcount = $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                          $lastseries = $naddr;
                                          $lastcount = $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                       }
                                    }
                                 }
                              } else {
                                 $startseries = $naddr;
                                 $startcount = $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                 $lastseries = $naddr;
                                 $lastcount = $items{$local}{$stype}{$sid}{$inf}{$saddr}{$daddr};
                              }
                           }
                        }

                        if ($startseries > 0) {
                           my $startaddr = inet_ntoa(pack "N", $startseries);
                           my $lastaddr  = inet_ntoa(pack "N", $lastseries);

                           if ($startseries != $lastseries) {
                              print "$startaddr($startcount)-$lastaddr($lastcount)";
                           } else {
                              print "$startaddr($startcount)";
                           }
                        }
                        print "\n";
                     }
                  }
               }
            }
         }
      }
      }
   }
}

sub RaHostsCleanUp {
   my $file = shift;
   print "DEBUG: deleting '$file'\n" if $debug;
   unlink $file;
   exit 0;
}


sub RaGetAddressCount() {
   my $tlocal = shift(@_);
   my $thisaddr = shift(@_);
   my $thistype = shift(@_);
   my $sid = shift(@_);
   my $inf = shift(@_);
   my $retn = 0;
   my $daddr;

   for $daddr ( keys( %{$items{$tlocal}{$thistype}{$sid}{$inf}{$thisaddr}} )) {
      $retn++;
   }

   return ($retn);
}

sub numerically { $a <=> $b };

sub internet {
   my $ipA = new Net::IP ($a);
   my $ipB = new Net::IP ($b);
   my $retn = 0;

   if ((defined $ipA) && (defined $ipB)) {
      $retn = ($ipA->intip() <=> $ipB->intip()); 
   }

   return ($retn);
}
