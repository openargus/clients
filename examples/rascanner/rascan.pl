#! /usr/bin/perl 
# 
#  Gargoyle Client Software. Tools to read, analyze and manage Argus data.
#  Copyright (c) 2000-2014 QoSient, LLC
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
#  rascan.pl - the script takes a radium distribution stream
#     or file(s) and generates a searcher report. 
#     The strategy is to detect single host, multihost/multiport
#     scans and report on the hosts that are actively scanning.
#  
#     The technique uses raisd to segregate valid service traffic
#     and then to process non-service traffic for single host
#     mulit-host/port accesses for UDP and TCP based traffic.
#
#  $Id: //depot/gargoyle/clients/examples/rascanner/rascan.pl#2 $
#  $DateTime: 2014/10/07 15:23:30 $
#  $Change: 2939 $
#

use File::Temp qw/ :POSIX /;
use strict;
use Digest::MD5 qw(md5_hex);
use DBI;


my $tmpfile     = tmpnam();
my $tmpconf     = $tmpfile . ".conf";
my $tmpraisconf = $tmpfile . ".rais.conf";
my $tmpraconf   = $tmpfile . ".rag.conf";
my $tmpp1conf   = $tmpfile . ".pass1.conf";
my $tmpp2conf   = $tmpfile . ".pass2.conf";
my $tmpp3conf   = $tmpfile . ".pass3.conf";
my $tmpp4conf   = $tmpfile . ".pass4.conf";

my $RACONF        = "/usr/local/ntam/";
my $RANTAIS       = "ntais";
my $RASEARCHER    = "$RANTAIS/Searcher";
my $RAPASSONE     = "racluster.pass1.out";
my $RAPASSTWO     = "racluster.pass2.out";
my $RAPASSTHREE   = "racluster.pass3.out";
my $RAPASSFOUR    = "racluster.pass4.out";
my $RASCANTHRESH  = 9;

my $ConfFile      = `echo ~/.rarc`;

my @arglist;
my $localaddr  = "";
my $database   = "";
my $hashindex  = "";
my $probes     = "";

my $multisig   = 0;
my $verbose    = 0;
my $force      = 0;
my $percent    = 0;

my %attr = (PrintError=>0, RaiseError=>0);
my $dbh  = "";

ARG: while (my $arg = shift(@ARGV)) {
   chomp $arg;
   $hashindex .= $arg;
   for ($arg) {
      /^-L/   && do { $localaddr = shift (@ARGV); next ARG; };
      /^-m/   && do { $multisig = shift (@ARGV); next ARG; };
      /^-N/   && do { $RASCANTHRESH = shift (@ARGV); next ARG; };
      /^-v/   && do { $verbose++; next ARG; };
      /^-P/   && do { $database = shift (@ARGV); next ARG; };
      /^-F/   && do { $ConfFile = shift (@ARGV); next ARG; };
      /^-f/   && do { $force++; next ARG; };
      /^-p/   && do { $percent++; next ARG; };
   }

   $arglist[@arglist + 0] = $arg;
}

if ($localaddr eq "") {
   usage();
}

if (!($database eq "")) {
   my $user;
   my $pass;
  
   open (FH, "< $ConfFile") or die "can't open $ConfFile: $!";
   while (<FH>) {
      /^RA_DB_USER=/ and do {
         /^.*?"(.*?)[\/"]/;
         $user = $1;
      };
      /^RA_DB_PASS=/ and do {
         /^.*?"(.*)"$/;
         $pass = $1;
      };
   }

   $dbh = DBI->connect("dbi:mysql:NTAIS", $user, $pass, \%attr) or die "can't connect: ", $DBI::errstr, "\n";
   my $str  = sprintf "CREATE TABLE IF NOT EXISTS %s_Searchers (addr varchar(16), proto varchar(8), dport varchar(16), startime varchar(32), dur varchar(32), trans varchar(16), INDEX addrIndex(addr)) TYPE=MyISAM", $database;
   my $sth = $dbh->prepare($str) or die "can't prepare: ", $DBI::errstr, "\n";
   $sth->execute() or die "can't execute: ", $DBI::errstr, "\n";
}
 
my $hash = md5_hex($hashindex);
my $RADATA  = "data.$hash";

RaScanProcessArgusData ();
RaScanGenerateSearcherList ();
exit;

sub RaScanProcessArgusData {
   stat $RAPASSTHREE;
   if ( ! -f _  || $force) {
      stat $RAPASSTWO;
      if ( ! -f _  || $force) {
         stat $RAPASSONE;
         if ( ! -f _  || $force) {
            stat $RANTAIS;
            if ( ! -d _  || $force) {
               stat $RADATA;
               if ( ! -d _  || $force) {
                  stat $RANTAIS;
                  if ( -d _  || $force) {
                     if ($verbose) { print "cleaning data caches\n"};
                     `rm -rf $RANTAIS`;
                  }
                  if ($verbose) { print "conditioning data\n"};
                  `mkdir $RADATA`;
                  createTmpRaclusterTimeoutConfig ();
                  `racluster -f $tmpraconf -w - @arglist | rasplit -M time 1h -w $RADATA/ntam.%Y.%m.%d.%H.%M.%S`;
                  `rm $tmpraconf`;
                  if ($verbose) { 
                     print "sorting\n";
                    `rasort -M replace -v -R $RADATA`;
                  } else {
                    `rasort -M replace -R $RADATA`;
                  }
               }

               if ($verbose) { print "creating ntais\n"};
               createTmpRaisConfig ();
               `raisd -f $tmpraisconf -R $RADATA - ip`;
               `rm $tmpraisconf`

            } else {
               if ($verbose) { print "using existing $RANTAIS data\n"};
            }

            if ($verbose) { print "processing ntais data pass1\n"};
            createTmpRaclusterPass1Config ();
            `racluster -f $tmpp1conf -w $RAPASSONE -R $RASEARCHER - ip`;
            `rm -f $tmpp1conf`;

         } else {
            if ($verbose) { print "using existing $RAPASSONE\n"};
         }

         if ($verbose) { print "processing ntais data pass2\n"};
         createTmpRaclusterNoTimeoutConfig ();
         createTmpRaclusterPass2Config ();
         `racluster -f $tmpraconf -r $RAPASSONE -w - | racluster -f $tmpp2conf -w $RAPASSTWO`;
         `rm -f $tmpp2conf`;
         `rm $tmpraconf`;
      } else {
         if ($verbose) { print "using existing $RAPASSTWO\n"};
      }

      if ($verbose) { print "processing ntais data pass3\n"};
      createTmpRaclusterPass3Config ();
      `racluster -f $tmpp3conf -w $RAPASSTHREE -r $RAPASSTWO`;
      `rm -f $tmpp3conf`;

      if ($verbose) {
         print "sorting ntais data\n";
         `rasort -vM replace trans -r racluster.pass3.out`;
      } else {
         `rasort -M replace trans -r racluster.pass3.out`;
      }

   } else {
      if ($verbose) { print "using existing $RAPASSTHREE\n"};
   }
}


my %wildcardports = ();
my $lastaddr  = "";
my $lastproto = "";
my $lastport  = "";

our (%addrs, %daddrs, %sdata, %adata, %probes, $thisaddr);
my ($startime, $srcid, $dur, $saddr, $trans, $proto, $dport, $timerange);

sub RaScanGenerateSearcherList {
   my @args = ( "ratimerange", "-p0 -r",  $RAPASSTHREE );
   my $datapass = 0;
   my $data = "";

   open(SESAME, "@args |") or die "can't open @args\n";

   while ($data = <SESAME>) {
      chomp $data;
      $timerange = $data;
      $datapass++;
   }
   if ($datapass == 0) {
      print "@args returned NULL\n";
      exit -1;
   }
   close(SESAME);

   createTmpConfig ();
   if ($verbose) { print "generating searcher list\n"};
   createTmpAggConfig ();
   @args = ( "ra", "-nF $tmpconf -p3 -s startime srcid dur saddr trans proto dport",
                   "-r $RAPASSTHREE - ip and not icmp and port not \\(http or domain or 135\\) ");
   my $searchers = 0;
   my $afilter = "";
   my $sfilter = "";
   my $iter = 0;

   if ($verbose) { print "@args\n"};
   open(SESAME, "@args |");
   my $data = <SESAME>;
   while ($data = <SESAME>) {
      chomp $data;
      ($startime, $srcid, $dur, $saddr, $trans, $proto, $dport) = split (/,/, $data);
      if (($trans > $RASCANTHRESH) && (!($saddr eq "")) && (!($saddr eq "0.0.0.0"))) {
         $addrs{$saddr} += $trans;
         $probes{$srcid} += $trans;
         my $key = $proto;
         if (!($dport eq "")) {
            $key .= ":$dport";
         } else {
            if (($proto eq "tcp") || ($proto eq "udp")) {
               $key .= ":\*";
            }
         }

         push @{$daddrs{$saddr}{$key}} , $data;
         if ($iter > 0) {
            $sfilter .= " or "; 
         };
         if (!($lastaddr eq $saddr)) {
            if ($iter++ > 0) {
               $afilter .= " or "; 
            }
            $afilter .= "\\( dst host $saddr \\)";
            $lastaddr = $saddr;
         }

         if (!($dport eq "")) {
            $sfilter .= "\\( src host $saddr and dst port $dport \\)";
         } else {
            $sfilter .= "\\( src host $saddr \\)";
         }
      }
   }
   close(SESAME);

   print "Searcher Report $timerange\n";

   if (( $probes = scalar(keys(%probes))) > 0 ) {
      my $thisprobe;
      print "Probe ";
      for $thisprobe ( sort ordinally keys(%probes) ) {
         print "$thisprobe ";
      }
      print "\n";
   }

   my $dirs = '';
   stat 'ntais/Services';
   if ( -d _ ) {
      $dirs .= 'ntais/Services ';
   }
   stat 'ntais/Other';
   if ( -d _ ) {
      $dirs .= 'ntais/Other ';
   }

   if (!($dirs eq "")) {
      my $responders = 0;
      my @hargs = ("racluster -w - -f $tmpraconf -R $dirs - $sfilter | ", 
                   "ra -np0 -ds16:d24 -Az -s startime proto saddr dir daddr dport bytes user");

      open(HOSTSUCCESS, "@hargs |");

GRA: while (my $tdata = <HOSTSUCCESS>) {
         my ($sd,$st,$pr,$sa,$dir,$da,$sb,$db) = split (" ", $tdata);
         my ($a1, $a2, $a3, $a4, $dp) = split /\./, $da;
         my ($p1,$su,$p2,$du) = split ("\"", $tdata);
         my $da = "$a1.$a2.$a3.$a4";

         if (!($pr eq "man")) {
            for ($su) {
               /Timeout/   && do { next GRA; };
               /istener/   && do { next GRA; };
               /tcp/       && do { next GRA; };
               /No |no /   && do { next GRA; };
            }
            for ($du) {
               /Timeout/   && do { next GRA; };
               /istener/   && do { next GRA; };
               /tcp/       && do { next GRA; };
               /No |no /   && do { next GRA; };
            }

            if ($db > 0) {
               push @{$sdata{$sa}{$pr}} , $tdata;
            }
         }
      }
      close (HOSTSUCCESS);
   }

   if (!($afilter eq "")) {
      my @hargs = ("ra -p0 -d16 -Az -R ntais -s startime proto saddr sport dir daddr dport bytes user - $afilter and not icmp");
      my $responders = 0;

      open(HOSTSUCCESS, "@hargs |");
    
RAG:  while (my $tdata = <HOSTSUCCESS>) {
         my ($sd,$st,$pr,$sa,$dir,$da,$sb,$db) = split (" ", $tdata);
         my ($p1,$su,$p2,$du) = split ("\"", $tdata);
         my ($sa1, $sa2, $sa3, $sa4, $sp) = split /\./, $sa;
         my $sa = "$sa1.$sa2.$sa3.$sa4";
         my ($da1, $da2, $da3, $da4, $dp) = split /\./, $da;
         my $da = "$da1.$da2.$da3.$da4";
    
         if ((!($pr eq "man")) && ($sb > 0)) {
            for ($su) {
               /Timeout/   && do { next RAG; };
               /istener/   && do { next RAG; };
               /tcp/       && do { next RAG; };
               /No |no /   && do { next RAG; };
            }
            for ($du) {
               /Timeout/   && do { next RAG; };
               /istener/   && do { next RAG; };
               /tcp/       && do { next RAG; };
               /No |no /   && do { next RAG; }; 
            }
            push @{$adata{$da}{$pr}} , $tdata;
         }
      }
      close (HOSTSUCCESS);
   }

   my $label = "";
   $lastaddr = "";

# Look to see if we have any multiple strategy scans and
# prepare the list so we can see a few of them in the
# report, if we're configured to do so.

   if ($multisig > 0) {
      my %wildcards = ();

      if (( $searchers = scalar(keys(%addrs))) > 0 ) {
         for $thisaddr ( sort ordinally keys(%addrs) ) {
            if ( scalar(keys(%{$daddrs{$thisaddr} })) > 0 ) {
               for my $key ( sort subliminally keys(%{$daddrs{$thisaddr} }) ) {
                  ($startime, $srcid, $dur, $saddr, $trans, $proto, $dport) = split (/,/, $daddrs{$thisaddr}{$key}[0]);
                  if ($dport eq "") {
                     if (($proto eq "tcp") || ($proto eq "udp")) {
                        push @{$wildcards{$thisaddr}} , $daddrs{$thisaddr}{$key}[0];
                     }
                  }
               }
            }
         }


         if ( scalar(keys( %wildcards )) > 0 ) {
            my $filter = "";
            my $laddr  = "";
            my $iter = 0;

            for $thisaddr ( sort ordinally keys(%wildcards) ) {
               if (!($laddr eq $thisaddr)) {
                  if ($iter++ > 0) {
                     $filter .= " or ";
                  }
                  $filter .= "\\( src host $thisaddr \\)";
                  $laddr = $thisaddr;
               }
            }

            stat $RAPASSFOUR;
            if ( ! -f _ ) {
               if ($verbose) { print "creating ntais data pass4\n"};
               createTmpRaclusterPass4Config ();
               `racluster -f $tmpp4conf -w $RAPASSFOUR -r $RAPASSONE - $filter`;
               `rm -f $tmpp3conf`;
            }

            if ($verbose) { print "processing ntais data pass4\n"};

            my @hargs = ("rasort -nM trans saddr proto dport -s saddr proto dport -r $RAPASSFOUR - not man");
            open(HOSTSUCCESS, "@hargs |");
          
            while (my $tdata = <HOSTSUCCESS>) {
               chomp $tdata;
               $tdata =~ s/^\s+//gm;
               $tdata =~ s/ +/ /gm;
               my ($sa, $pr, $dp) = split (/ /,$tdata);
               if (!(($dp eq "") || ($dp eq "*"))) {
                  $wildcardports{$sa}{$pr}{$dp}++;
               }
            }
         }
         close (HOSTSUCCESS);
      }
   }

# First print out the searchers that have responders.

   if (( $searchers = scalar(keys(%addrs))) > 0 ) {
      for $thisaddr ( sort ordinally keys(%addrs) ) {
         if ( scalar(keys(%{$daddrs{$thisaddr} })) > 0 ) {
            for my $key ( sort subliminally keys(%{$daddrs{$thisaddr}}) ) {
               my ($startime, $srcid, $dur, $saddr, $trans, $proto, $dport) = split (/,/, $daddrs{$thisaddr}{$key}[0]);

               if (!($lastaddr eq $saddr)) {
                  $label = "Searcher: ";
                  $lastaddr = $saddr;
               } else {
                  $label = "          ";
               }
               if (!($lastproto eq $proto)) {
                  $lastproto = $proto;
               }
               if (($#{$sdata{$saddr}{$proto}} >= 0) || ($#{$adata{$saddr}{$proto}} >= 0)) {
                  if ($dport eq "") {
                     my $ports = 0;
                     if ($multisig == 0) {
                        $dport = "*";
                     } else {
                        my $totalporthits = 0;
                        for my $portnum ( keys %{ $wildcardports{$saddr}{$proto}}) {
                           $totalporthits += $wildcardports{$saddr}{$proto}{$portnum};
                        }
                        if (($ports = scalar(keys(%{$wildcardports{$saddr}{$proto} }))) > 0 ) {
                           my $portnum = 0;
                           my $passnum = 0;
                           $dport = sprintf "%-7.7s ", "[$ports]";
                           for $portnum ( sort numerically keys %{ $wildcardports{$saddr}{$proto}}) {
                              if ($passnum++ < $multisig) {
                                 my $hits = sprintf "%s", $portnum;
                                 if ($percent) {
                                    $hits .= sprintf "(%2.2f%%)", (($wildcardports{$saddr}{$proto}{$portnum} * 100.0) / $totalporthits);
                                 }
                                 $dport .= $hits;
                                 if ($passnum != $multisig) {
                                    $dport .= ",";
                                 }
                              }
                           }
                           if ($ports >= $multisig) {
                              if ($multisig != 0) {
                                 $dport .= ",";
                              }
                                 $dport .= "*";
                           }
                        } else {
                           $dport = "[1]     65535";
                           if ($percent) {
                              $dport .= "(100%)";
                           }
                        }
                     }
                  } else {
                     my $tdport = "[1]     $dport";
                     if ($percent) {
                        $tdport .= "(100%)";
                     }
                     $dport = $tdport;
                  }

                  my $str = sprintf "$label %15.15s scanned %6d hosts in %10s secs using %4s:%-6s\n", $saddr, $trans, $dur, $proto, $dport;
                  print "$str";

                  if (( my $index = $#{$sdata{$lastaddr}{$proto}} ) >= 0) {
                     print "Data Responders:\n";
                     while ($index >= 0) {
                        my $tdata = @{$sdata{$lastaddr}{$proto}}[$index--];
                        print "   $tdata";
                     }
                  }

                  if (( my $index = $#{$adata{$lastaddr}{$proto}} ) >= 0) {
                     print "Aberrant Responders:\n";
                     while ($index >= 0) {
                        my $tdata = @{$adata{$lastaddr}{$proto}}[$index--];
                        print "   $tdata";
                     }
                  }
                  print "\n";
               } else {
               }
            }
         }
      }
   }

   $lastaddr = "";
   print "\n";

# Then print out the searchers that did not have responders.

   if (( $searchers = scalar(keys(%addrs))) > 0 ) {
      for $thisaddr ( sort ordinally keys(%addrs) ) {
         if ( scalar(keys(%{$daddrs{$thisaddr} })) > 0 ) {
            for my $key ( sort subliminally keys(%{$daddrs{$thisaddr} }) ) {
               my ($startime, $srcid, $dur, $saddr, $trans, $proto, $dport) = split (/,/, $daddrs{$thisaddr}{$key}[0]);
               if (!($lastaddr eq $saddr)) {
                  $label = "Searcher: ";
                  $lastaddr = $saddr;
               } else {
                  $label = "          ";
               }
               if (!($lastproto eq $proto)) {
                  $lastproto = $proto;
               }
               if (($#{$sdata{$saddr}{$proto}} < 0) && ($#{$adata{$saddr}{$proto}} < 0)) {
                  if ($dport eq "") {
                     my $ports = 0;
                     if ($multisig == 0) {
                           $dport = "*";
                     } else {
                        my $totalporthits = 0;
                        for my $portnum ( keys %{ $wildcardports{$saddr}{$proto}}) {
                              $totalporthits += $wildcardports{$saddr}{$proto}{$portnum};
                        }
                        
                        if (($ports = scalar(keys(%{$wildcardports{$saddr}{$proto} }))) > 0 ) {
                           my $portnum = 0;
                           my $passnum = 0;
                           $dport = sprintf "%-7.7s ", "[$ports]";
                           for $portnum ( sort numerically keys %{ $wildcardports{$saddr}{$proto}}) {
                              if ($passnum++ < $multisig) {
                                 my $hits = sprintf "%s", $portnum;
                                 if ($percent) {
                                    $hits .= sprintf "(%2.2f%%)", (($wildcardports{$saddr}{$proto}{$portnum} * 100.0) / $totalporthits);
                                 }
                                 $dport .= $hits;
                                 if ($passnum != $multisig) {
                                    $dport .= ",";
                                 }
                              }
                           }
                           if ($ports >= $multisig) {
                              if ($multisig != 0) {
                                 $dport .= ",";
                              }
                                 $dport .= "*";
                           }
                        } else {
                           $dport = "[1]     65535";
                           if ($percent) {
                              $dport .= "(100%)";
                           }
                        }
                     }
                  } else {
                     my $tdport = "[1]     $dport";
                     if ($percent) {
                        $dport .= "(100%)";
                     }
                     $dport = $tdport;
                  }

                  my $str = sprintf "$label %15.15s scanned %6d hosts in %10s secs using %4s:%-6s\n", $saddr, $trans, $dur, $proto, $dport;
                  print "$str";
               }
            }
         }
      }
   }

   if ($searchers == 0) {
      if ($verbose) { print "no searchers seen\n"};
   } else {
      if (!($database eq "")) {
         if (( $searchers = scalar(keys(%addrs))) > 0 ) {
            for $thisaddr ( sort ordinally keys(%addrs) ) {
               if ( scalar(keys(%{$daddrs{$thisaddr} })) > 0 ) {
                  for my $key ( sort subliminally keys(%{$daddrs{$thisaddr} }) ) {
                     my ($startime, $srcid, $dur, $saddr, $trans, $proto, $dport) = split (/,/, $daddrs{$thisaddr}{$key}[0]);
                     if (!($lastaddr eq $saddr)) {
                        $label = "Searcher: ";
                        $lastaddr = $saddr;
                     } else {
                        $label = "          ";
                     }
 
                     if (($#{$sdata{$saddr}{$proto}} < 0) && ($#{$adata{$saddr}{$proto}} < 0)) {
                        if ($dport eq "") {
                           if (($proto eq "tcp") || ($proto eq "udp")) {
                              $dport = "\*";
                           }
                        }

                        my $str  = sprintf "INSERT %s_Searchers (addr,proto,dport,startime,dur,trans) VALUES ", $database;
                           $str .= "(\"$saddr\",\"$proto\",\"$dport\",\"$startime\",\"$dur\",\"$trans\")";
                        my $sth = $dbh->prepare($str) or die "can't prepare: ", $DBI::errstr, "\n";

                        $sth->execute() or die "can't execute: ", $DBI::errstr, "\n";
                     }
                  }
               }
            }
         }
      }
   }

   `rm -f $tmpconf $tmpraconf`;
}


sub ordinally {
   $addrs{$b} <=> $addrs{$a};
}

sub subliminally {
   my @a_fields = split /,/, @{$daddrs{$thisaddr}{$a}}[0];
   my @b_fields = split /,/, @{$daddrs{$thisaddr}{$b}}[0];
 
   $b_fields[2] <=> $a_fields[2];
}
 



sub createTmpConfig {
   open(CONFFILE, "> $tmpconf");
   print CONFFILE <<_EOCONFIG_ ;
 
#
#  Copyright (c) 2000-2004 QoSient, LLC
#  All rights reserved.
#
#  QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
#  SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
#  FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
#  SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
#  RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
#  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
#  CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
#

RA_FIELD_DELIMITER=','
RA_HOST_FIELD_LENGTH=15
RA_PORT_FIELD_LENGTH=15
_EOCONFIG_
 
   close(CONFFILE);
}



sub createTmpRaclusterPass4Config {
   open(CONFFILE, "> $tmpp4conf");
   print CONFFILE <<_EOCONFIG_ ;
# 
#  Copyright (c) 2000-2012 QoSient, LLC
#  All rights reserved.
# 
# Racluster Aggregation Policy Configuration
#
# Carter Bullard
# QoSient, LLC
#
#
RACLUSTER_MODEL_NAME=Test Configuration
RACLUSTER_PRESERVE_FIELDS=yes
RACLUSTER_REPORT_AGGREGATION=yes
RACLUSTER_AUTO_CORRECTION=no
#
filter="ip" model="saddr proto dport"
 
_EOCONFIG_
 
   close(CONFFILE);
}

sub createTmpRaclusterPass3Config {
   open(CONFFILE, "> $tmpp3conf");
   print CONFFILE <<_EOCONFIG_ ;
# 
#  Copyright (c) 2000-2012 QoSient, LLC
#  All rights reserved.
# 
# Racluster Aggregation Policy Configuration
#
# Carter Bullard
# QoSient, LLC
#
#
RACLUSTER_MODEL_NAME=Test Configuration
RACLUSTER_PRESERVE_FIELDS=yes
RACLUSTER_REPORT_AGGREGATION=yes
RACLUSTER_AUTO_CORRECTION=no
# 
filter="ip" model="saddr proto"
 
_EOCONFIG_
 
   close(CONFFILE);
}


sub createTmpRaclusterPass2Config {
   open(CONFFILE, "> $tmpp2conf");
   print CONFFILE <<_EOCONFIG_ ;
# 
#  Copyright (c) 2000-2012 QoSient, LLC
#  All rights reserved.
#
# Racluster Aggregation Policy Configuration
#
# Carter Bullard
# QoSient, LLC
#
#
RACLUSTER_MODEL_NAME=Test Configuration
RACLUSTER_PRESERVE_FIELDS=yes
RACLUSTER_REPORT_AGGREGATION=no
RACLUSTER_AUTO_CORRECTION=no

#
# 
#     id      SrcCIDRAddr  DstCIDRAddr  Proto SPort DPort Model Dur Idle
filter="dst net $localaddr" model="saddr daddr proto"
filter="ip"                 model="srcid"

_EOCONFIG_
 
   close(CONFFILE);
}


sub createTmpRaclusterPass1Config {
   open(CONFFILE, "> $tmpp1conf");
   print CONFFILE <<_EOCONFIG_ ;
# 
#  Copyright (c) 2000-2012 QoSient, LLC
#  All rights reserved.
# 
# Racluster Aggregation Policy Configuration
#
# Carter Bullard
# QoSient, LLC
#
#
RACLUSTER_MODEL_NAME=Test Configuration
RACLUSTER_PRESERVE_FIELDS=yes
RACLUSTER_REPORT_AGGREGATION=no
RACLUSTER_AUTO_CORRECTION=no

#
# 
#     id      SrcCIDRAddr  DstCIDRAddr  Proto SPort DPort Model Dur Idle
filter="src net $localaddr"  model="srcid"                    status=0 idle=1200
filter="dst net $localaddr"  model="saddr daddr proto dport"  status=0 idle=3600

_EOCONFIG_
 
   close(CONFFILE);
}

sub createTmpAggConfig {
   open(CONFFILE, "> $tmpraconf");
   print CONFFILE <<_EOCONFIG_ ;
# 
#  Copyright (c) 2000-2012 QoSient, LLC
#  All rights reserved.
# 
# Racluster Aggregation Policy Configuration
#
# Carter Bullard
# QoSient, LLC
#
#
RACLUSTER_MODEL_NAME=Test Configuration
RACLUSTER_PRESERVE_FIELDS=yes
RACLUSTER_REPORT_AGGREGATION=yes
RACLUSTER_AUTO_CORRECTION=no
#
# 
filter="ip" model="saddr daddr proto dport"           status=0 idle=0

_EOCONFIG_
 
   close(CONFFILE);
}

sub createTmpRaclusterTimeoutConfig {
   open(CONFFILE, "> $tmpraconf");
   print CONFFILE <<_EOCONFIG_ ;
# 
#  Copyright (c) 2000-2012 QoSient, LLC
#  All rights reserved.
# 
# Racluster Aggregation Policy Configuration
#
# Carter Bullard
# QoSient, LLC
#
#
RACLUSTER_MODEL_NAME=Test Configuration
RACLUSTER_PRESERVE_FIELDS=yes
RACLUSTER_REPORT_AGGREGATION=no
RACLUSTER_AUTO_CORRECTION=yes
#
filter="ip"    model="saddr daddr proto sport dport" status=0 idle=3600

_EOCONFIG_
 
   close(CONFFILE);
}


sub createTmpRaclusterNoTimeoutConfig {
   open(CONFFILE, "> $tmpraconf");
   print CONFFILE <<_EOCONFIG_ ;
# 
#  Copyright (c) 2000-2012 QoSient, LLC
#  All rights reserved.
# 
# Racluster Aggregation Policy Configuration
#
# Carter Bullard
# QoSient, LLC
#
#
RACLUSTER_MODEL_NAME=Test Configuration
RACLUSTER_PRESERVE_FIELDS=yes
RACLUSTER_REPORT_AGGREGATION=no
RACLUSTER_AUTO_CORRECTION=yes
# 
filter="ip"  model="saddr daddr proto dport" status=0 idle=0

_EOCONFIG_
 
   close(CONFFILE);
}


sub createTmpRaisConfig {
   open(CONFFILE, "> $tmpraisconf");
   print CONFFILE <<_EOCONFIG_ ;
#
#  Copyright (c) 2000-2004 QoSient, LLC
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
# RaIs Configuration File
#
# RaIs can provide a complex set of argus data processing
# functions to its output.  This collection of processing
# functions allows the radium to act as a node/component of
# a dataflow machine.
#
# Radium functions are structured tasks that support:
#    Multiprobe record correlation, where records collected
#       from multiple ntams can be recognized as the same
#       flow, allowing for differential metrics to be
#       determined, such as one-way delay and loss.
#    
#    Input source specification, whether this function
#       will act on all records, or the excluding records
#       of a previous function.
#
#    Input filtering to select the appropriate records
#       Records that match will be processed and records
#       that do not match, can be discarded, or passed
#       to other functions.
#
#    Classification strategies to assign semantic types.
#       Radium supports x types of classification,
#       such as 'service', etc ....
#
#    Classification specific aggregation.
#       Each function has its own complex aggregation function
#         all aggregates share the same classification semantic.
#
#
# Function Zero, find validated services.  So we need to have
# the first of the tcp and udp streams, but not FTP data, at
# this point.  Assumption is that data has been processed by 
# racluster() prior to this.
#
# If not complete TCP connections, or straight UDP with data, then
# go to connectionless logic.  If is complete can user payload
# can be validated, then output 60 second service aggregations, to
# the service specific directory into 1hour bins.
#
# This should catch most/all of the TCP/UDP well formed audit records.
#

[begin function 0]
RADIUM_NAME="Validated Service"
RADIUM_PRINT_FIELDS="ind proto saddr sport dir daddr dport pkts bytes status"
RADIUM_SORT_FIELDS="daddr saddr proto pkts"
RADIUM_INPUT_SOURCE=all
RADIUM_FILTER="((tcp and (syn or synack) and (dst port not ftp and src port not ftp-data)) and (src data and dst data)) or (udp and data)"
RADIUM_FILTER_EXCEPTION=function 1
RADIUM_CLASSIFIER=Services(/usr/local/ntam/std.sig)
RADIUM_CLASSIFIER_EXCEPTION=function 3
RADIUM_AGGREGATION=yes
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Services/\$svc/%Y/%m/%d/rais.%Y.%m.%d.%H
[begin model]
RACLUSTER_MODEL_NAME=Services Matrix
RACLUSTER_PRESERVE_FIELDS=yes
RACLUSTER_REPORT_AGGREGATION=yes
RACLUSTER_AUTO_CORRECTION=yes
# 
filter="tcp and src port ftp-data"  model="saddr daddr proto dport"   status=60 idle=300
filter=""                           model="saddr daddr proto sport"   status=60 idle=300
[end model]
[end function 0]


# Function One, function zero filter exception thread.  So we need
# to work with the FTP part of the equation.  In order to catch
# FTP-Data connections on arbitrary ports, we need to put a cache
# into this function for other functions to test against.
#
# FTP data needs to be validated, and then held for a while.  Because
# its TCP, we'll keep it with a very long idle times and update
# the idle status if any ftp-data connections are seen.  The idle
# timer should be watched, if ftp-data transactions end up in the
# Other slots.
#
# If the connection can't be validated, then it could be a covert
# channel, since we matched the filter, so send it in the classifier
# problem function.
#
# We'll output ftp control connections as 60 second service aggregations,
# to the ftp service specific directory into 1hour bins.


[begin function 1]
RADIUM_NAME="Validated FTP Service"
RADIUM_INPUT_SOURCE=function
RADIUM_FILTER="((tcp and (syn or synack)) and dst port ftp) and (src data and dst data)"
RADIUM_FILTER_EXCEPTION=function 2
RADIUM_CLASSIFIER=Services(/usr/local/ntam/std.sig)
RADIUM_CLASSIFIER_EXCEPTION=function 3
RADIUM_AGGREGATION=yes
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Services/\$svc/%Y/%m/%d/rais.%Y.%m.%d.%H"
[begin model]
RACLUSTER_MODEL_NAME=Matrix
RACLUSTER_PRESERVE_FIELDS=yes
RACLUSTER_REPORT_AGGREGATION=yes
RACLUSTER_AUTO_CORRECTION=yes
#
filter="ip" model="saddr daddr proto sport dport"   status=60 idle=3600
[end model]
[end function 1]
 

# Function Two, function zero/one/two filter exception thread.  So we need
# to deal with the FTP-data connections, which should be obvious.  To
# strengthen the test, there should be a parent FTP control channel, so
# we'll test that here.  The way the parent control works, is if there
# is a parent match, then you use the parent thread as if it matched.
# If there is no parent, then we'll do the action at this node.
# So if we get to the file dispatch, we'll be here with ftp-data
# connections with no parent, so we'll dispatch records under that title.
# This would be an expected covert channel.
#
# Filter exceptions jump to function 4, as 3 is the classifier exception
# block.
#

[begin function 2]
RADIUM_NAME="FTP Data Service"
RADIUM_INPUT_SOURCE=function
RADIUM_FILTER="(tcp and (syn or synack) and src port ftp-data) and data"
RADIUM_FILTER_EXCEPTION=function 4
RADIUM_PARENT_TEST=function 1
RADIUM_AGGREGATION=yes
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Services/\$svc/%Y/%m/%d/rais.%Y.%m.%d.%H"
[begin model]
RACLUSTER_MODEL_NAME=IP Matrix Protocol DstPort
RACLUSTER_PRESERVE_FIELDS=yes
RACLUSTER_REPORT_AGGREGATION=yes
RACLUSTER_AUTO_CORRECTION=yes
#
filter="" model="saddr daddr proto sport"  status=60 idle=300
[end model]
[end function 2]


# Function Three, the classifier exception block.  We'll want to do multiple
# exception tests, and the first will be ftp-data on an arbitrary port, so
# lets test that.  If no match in any Parent tests, then we'll put it
# in the Other bin.
#

[begin function 3]
RADIUM_NAME="Non-classifiable Connections"
RADIUM_INPUT_SOURCE=all
RADIUM_FILTER="((tcp and (syn or synack)) or udp) and data and not icmpmap"
RADIUM_FILTER_EXCEPTION=function 4
RADIUM_PARENT_TEST=function 0
RADIUM_PARENT_TEST=function 1
RADIUM_AGGREGATION=yes
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Other/%Y/%m/%d/rais.%Y.%m.%d.%H"
[begin model]
RACLUSTER_PRESERVE_FIELDS=yes
RACLUSTER_REPORT_AGGREGATION=yes
RACLUSTER_AUTO_CORRECTION=yes
#
filter="ip"   model="saddr daddr proto sport dport"  status=60  idle=300
[end model]
[end function 3]


[begin function 4]
RADIUM_NAME="Multicast"
RADIUM_INPUT_SOURCE=function
RADIUM_FILTER="igmp or ip multicast"
RADIUM_FILTER_EXCEPTION=function 5
RADIUM_AGGREGATION=yes
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Services/\$svc/%Y/%m/%d/rais.%Y.%m.%d.%H
[begin model]
RACLUSTER_MODEL_NAME=IP Matrix Protocol DstPort
RACLUSTER_PRESERVE_FIELDS=yes
RACLUSTER_REPORT_AGGREGATION=yes
RACLUSTER_AUTO_CORRECTION=yes
#
filter="igmp"     model="saddr daddr proto dport"  status=0 idle=300
filter="ip"       model="saddr daddr proto dport"  status=0 idle=300
[end model]
[end function 4]

[begin function 5]
RADIUM_NAME="Traceroute"
RADIUM_INPUT_SOURCE=function
RADIUM_FILTER="ip and timexed and not icmp"
RADIUM_FILTER_EXCEPTION=function 6
RADIUM_AGGREGATION=yes
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Paths/%Y/%m/%d/rais.%Y.%m.%d.%H"
[begin model]
RACLUSTER_MODEL_NAME=Proto Matrix
RACLUSTER_PRESERVE_FIELDS=yes
RACLUSTER_REPORT_AGGREGATION=yes
RACLUSTER_AUTO_CORRECTION=no
#
filter="ip"    model="saddr daddr proto sport dport"  status=60 idle=300
[end model]
[end function 5]

[begin function 6]
RADIUM_NAME="Beacon"
RADIUM_INPUT_SOURCE=function
RADIUM_FILTER="echo"
RADIUM_FILTER_EXCEPTION=function 7
RADIUM_AGGREGATION=yes
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Beacon/%Y/%m/%d/rais.%Y.%m.%d.%H"
[begin model]
RACLUSTER_MODEL_NAME=Services Matrix
#
filter="ip" model="none"  status=0  idle=3600

[end model]
[end function 6]

[begin function 7]
RADIUM_NAME="Backscatter TCP RST"
RADIUM_INPUT_SOURCE=function
RADIUM_FILTER="tcp and reset and not (syn or synack or est or fin or finack or ack)"
RADIUM_FILTER_EXCEPTION=function 8
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Backscatter/TCPRstScans/%Y/%m/%d/rais.%Y.%m.%d.%H"
RADIUM_PARENT_TEST=function 0
RADIUM_PARENT_TEST=function 1
[begin model]
RACLUSTER_MODEL_NAME=No Model
#
filter="ip"    model="saddr daddr proto sport"   status=0 idle=3600
[end model]
[end function 7]

[begin function 8]
RADIUM_NAME="Backscatter TCP RST"
RADIUM_INPUT_SOURCE=function
RADIUM_FILTER="tcp and reset and ack and not (syn or synack or est or fin or finack)"
RADIUM_FILTER_EXCEPTION=function 9
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Backscatter/TCPRstAckScans/%Y/%m/%d/rais.%Y.%m.%d.%H"
RADIUM_PARENT_TEST=function 0
RADIUM_PARENT_TEST=function 1
[begin model]
RACLUSTER_MODEL_NAME=No Model
#
filter="ip" model="saddr daddr proto sport"   status=0 idle=3600
[end model]
[end function 8]

[begin function 9]
RADIUM_NAME="Backscatter SYN ACK"
RADIUM_INPUT_SOURCE=function
RADIUM_FILTER="tcp and (synack and not (syn or est or fin or finack)) or (synack and reset and not (syn or est or fin or finack))"
RADIUM_FILTER_EXCEPTION=function 10
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Backscatter/TCPSynAckScans/%Y/%m/%d/rais.%Y.%m.%d.%H"
RADIUM_PARENT_TEST=function 0
RADIUM_PARENT_TEST=function 1
[begin model]
RACLUSTER_MODEL_NAME=No Model
#
filter="ip" model="saddr daddr proto dport"  status=0 idle=3600
[end model]
[end function 9]
 
[begin function 10]
RADIUM_NAME="SearcherCandiateData"
RADIUM_INPUT_SOURCE=function
RADIUM_FILTER="tcp and syn and ((synack and (reset or fin or finack)) or (not synack)) and not data"
RADIUM_FILTER_EXCEPTION=function 11
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Searcher/SynScan/%Y/%m/%d/rais.%Y.%m.%d.%H"
[begin model]
RACLUSTER_MODEL_NAME=No Model
#
filter="ip"  model="none"  status=0 idle=300
[end model]
[end function 10]
 
[begin function 11]
RADIUM_NAME="SearcherCandiateData"
RADIUM_INPUT_SOURCE=function
RADIUM_FILTER="tcp and syn and synack and not (reset or fin or finack) and not data"
RADIUM_FILTER_EXCEPTION=function 12
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Searcher/HalfSynScan/%Y/%m/%d/rais.%Y.%m.%d.%H"
[begin model]
RACLUSTER_MODEL_NAME=No Model
#
filter="ip"  model="none"  status=0 idle=300
[end model]
[end function 11]

[begin function 12]
RADIUM_NAME="SearcherCandiateData"
RADIUM_INPUT_SOURCE=function
RADIUM_FILTER="tcp and ack and not (syn or synack or fin or finack or est)"
RADIUM_FILTER_EXCEPTION=function 13
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Searcher/AckScan/%Y/%m/%d/rais.%Y.%m.%d.%H"
[begin model]
RACLUSTER_MODEL_NAME=No Model
#
filter="ip"  model="none"  status=0 idle=300
[end model]
[end function 12]
 
[begin function 13]
RADIUM_NAME="SearcherCandiateData"
RADIUM_INPUT_SOURCE=function
RADIUM_FILTER="tcp and (fin or finack) and not (syn or synack or est)"
RADIUM_FILTER_EXCEPTION=function 14
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Searcher/FinScan/%Y/%m/%d/rais.%Y.%m.%d.%H"
[begin model]
RACLUSTER_MODEL_NAME=No Model
#
filter="ip"  model="none"  status=0 idle=300
[end model]
[end function 13]
 
[begin function 14]
RADIUM_NAME="SearcherCandiateData"
RADIUM_INPUT_SOURCE=function
RADIUM_FILTER="tcp and urg and push and fin and not (syn or synack or est)"
RADIUM_FILTER_EXCEPTION=function 15
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Searcher/XmasScan/%Y/%m/%d/rais.%Y.%m.%d.%H"
[begin model]
RACLUSTER_MODEL_NAME=No Model
#
filter="ip"  model="none"  status=0 idle=300
[end model]
[end function 14]
 
[begin function 15]
RADIUM_NAME="SearcherCandiateData"
RADIUM_INPUT_SOURCE=function
RADIUM_FILTER="udp"
RADIUM_FILTER_EXCEPTION=function 16
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Searcher/UdpScan/%Y/%m/%d/rais.%Y.%m.%d.%H"
[begin model]
RACLUSTER_MODEL_NAME=No Model
#
filter="ip"  model="none"  status=0 idle=300
[end model]
[end function 15]

[begin function 16]
RADIUM_NAME="SearcherCandiateData"
RADIUM_INPUT_SOURCE=function
RADIUM_SPLITMODE="time 1h"
RADIUM_FILENAME="ntais/Searcher/Unclassified/%Y/%m/%d/rais.%Y.%m.%d.%H"
[begin model]
RACLUSTER_MODEL_NAME=No Model
#
filter="ip"  model="none"  status=0 idle=300
[end model]
[end function 16]

_EOCONFIG_

   close(CONFFILE);
}


sub numerically {
   $wildcardports{$lastaddr}{$lastproto}{$a} <=> $wildcardports{$lastaddr}{$lastproto}{$b}
   ||
   $a <=> $b
}

sub usage {
   printf "rascan -L localaddr(cidr) -R data [-N threshold] [-m signum] [-vfp]\n";
   exit;
}
