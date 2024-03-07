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
#  ra() based host port use report
#
#  written by Carter Bullard
#  QoSient, LLC
#
#
#  $Id: //depot/gargoyle/clients/examples/raports/raports.pl#5 $
#  $DateTime: 2014/10/07 15:23:30 $
#  $Change: 2939 $
#

#
# Complain about undeclared variables

use strict;

# Used modules
use POSIX;
use URI::URL;
use DBI;
use File::Which qw/ which /;


local $ENV{PATH} = "$ENV{PATH}:/bin:/usr/bin:/usr/local/bin";

# Global variables
my $debug = 0;
my $drop  = 1;
my $racluster = which 'racluster';
chomp $racluster;

my $VERSION = "5.0";
my $Options = " -nc , -M rmon";   # Default Options
my $format  = 'addr';
my $fields  = '-s sid inf saddr proto sport';
my $model   = '-m sid inf saddr proto sport';
my $uri     = 0;
my $quiet   = 0;
my $scheme;
my $netloc;
my $path;

my ($user, $pass, $host, $port, $space, $db, $table);
my $dbh;
my @arglist = ();

ARG: while (my $arg = shift(@ARGV)) {
   for ($arg) {
      s/^-q//             && do { $quiet++; next ARG; };
      s/^-debug//         && do { $debug++; next ARG; };
      s/^-drop//          && do { $drop = 0; next ARG; };
      s/^-w//             && do {
         $uri = shift (@ARGV);
         next ARG;
      };
      /^-M/               && do {
         for ($ARGV[0]) {
            /src/  && do {
               $format = 'src';
               $fields = '-s sid:42 inf saddr:15 proto sport:15';
               $model  = '-m sid inf saddr proto sport';
               shift (@ARGV);
               next ARG;
            };

            /dst/  && do {
               $format = 'dst';
               $fields = '-s sid:42 inf saddr:15 proto dport:15';
               $model  = '-m sid inf saddr proto dport';
               shift (@ARGV);
               next ARG;
            };
         };
      };
      /^-$/               && do {
         $arglist[@arglist + 0] = "-";
         while (length $ARGV[0]) {
            $arglist[@arglist + 0] = shift (@ARGV);
         }
         next ARG;
      };
   }

   $arglist[@arglist + 0] = $arg;
}

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
 
   $dbh->do("CREATE TABLE IF NOT EXISTS $table (sid VARCHAR(64), inf VARCHAR(4), addr VARCHAR(64) NOT NULL, tcp INTEGER, udp INTEGER, tcpports MEDIUMTEXT, udpports MEDIUMTEXT, PRIMARY KEY ( addr, sid, inf ))");
}


# Start the program

my @args = ($racluster, "-w - ", @arglist, " | ", $racluster, $Options, $model, $fields);

my (%items, %addrs, $sid, $inf, $addr, $proto, $port);

print "DEBUG: raports: calling '@args'\n" if $debug;

open(SESAME, "@args |");
while (my $data = <SESAME>) {
   $data =~ s/^,//;
   ($sid, $inf, $addr, $proto, $port) = split(/,/, $data);
   chomp $port;
   if (!($addr eq "0.0.0.0")) {
      for ($proto) {
         /6/   && do {
            $addrs{$sid}{$inf}{$addr}++;
            $items{$sid}{$inf}{$addr}{$proto}{$port}++;
         } ;
         /17/   && do {
            $addrs{$sid}{$inf}{$addr}++;
            $items{$sid}{$inf}{$addr}{$proto}{$port}++;
         } ;
      }
   }
}
close(SESAME);

my $startseries = 0;
my $lastseries = 0;

my $tcpports;
my $udpports;

my $udpportstring;
my $tcpportstring;

 
if ($uri) {
   for $sid ( keys %items ) {
      for $inf ( keys %{$items{$sid}} ) {
         for $addr ( keys %{$items{$sid}{$inf}} ) {
            $tcpports = 0;
            $udpports = 0;
            $tcpportstring = "";
            $udpportstring = "";

            for $proto ( keys %{ $items{$sid}{$inf}{$addr} } ) {
               if ($proto == 6) {
                  $tcpports = scalar(keys(%{$items{$sid}{$inf}{$addr}{$proto} }));

                  $startseries = 0;
                  $lastseries = 0;
         
                  if ( scalar(keys(%{$items{$sid}{$inf}{$addr}{$proto} })) > 0 ) {
                     for $port ( sort numerically keys %{ $items{$sid}{$inf}{$addr}{$proto} } ) {
                        if ($startseries > 0) {
                           if ($port == ($lastseries + 1)) {
                              $lastseries = $port;
                           } else {
                              if ($startseries != $lastseries) {
                                 $tcpportstring .= "$startseries-$lastseries, ";
                                 $startseries = $port;
                                 $lastseries = $port;
                              } else {
                                 $tcpportstring .= "$startseries,";
                                 $startseries = $port;
                                 $lastseries = $port;
                              }
                           }
                        } else {
                           $startseries = $port;
                           $lastseries = $port;
                        }
                     }
         
                     if ($startseries > 0) {
                        if ($startseries != $lastseries) {
                           $tcpportstring .= "$startseries-$lastseries";
                        } else {
                           $tcpportstring .= "$startseries";
                        }
                     }
                  }

               } else {
                  $udpports = scalar(keys(%{$items{$sid}{$inf}{$addr}{$proto} }));

                  $startseries = 0;
                  $lastseries = 0;
                  
                  if ( scalar(keys(%{$items{$sid}{$inf}{$addr}{$proto} })) > 0 ) {
                     for $port ( sort numerically keys %{ $items{$sid}{$inf}{$addr}{$proto} } ) {
                        if ($startseries > 0) {
                           if ($port == ($lastseries + 1)) {
                              $lastseries = $port;
                           } else {
                              if ($startseries != $lastseries) {
                                 $udpportstring .= "$startseries-$lastseries, ";
                                 $startseries = $port;
                                 $lastseries = $port;
                              } else {
                                 $udpportstring .= "$startseries,";
                                 $startseries = $port;
                                 $lastseries = $port;
                              }
                           }
                        } else {
                           $startseries = $port;
                           $lastseries = $port;
                        }
                     }
                     
                     if ($startseries > 0) {
                        if ($startseries != $lastseries) {
                           $udpportstring .= "$startseries-$lastseries";
                        } else {
                           $udpportstring .= "$startseries";
                        }
                     }
                  }
               }
            }
            $dbh->do("INSERT INTO $table VALUES(?, ?, ?, ?, ?, ?, ?)", undef, $sid, $inf, $addr, $tcpports, $udpports, $tcpportstring, $udpportstring);
         }
      }
   }
   $dbh->disconnect();

} else {
   for $sid ( keys %items ) {
      for $inf ( keys %{$items{$sid}} ) {
         for $addr ( keys %{$items{$sid}{$inf}} ) {
            for $proto ( keys %{$items{$sid}{$inf}{$addr}} ) {
               if ($proto == 6) {
                  printf "$sid:$inf $addr tcp: (%d) ", scalar(keys(%{$items{$sid}{$inf}{$addr}{$proto} }));
               } else {
                  printf "$sid:$inf $addr udp: (%d) ", scalar(keys(%{$items{$sid}{$inf}{$addr}{$proto} }));
               }

               if ($quiet == 0) {
                  $startseries = 0;
                  $lastseries = 0;

                  if ( scalar(keys(%{$items{$sid}{$inf}{$addr}{$proto} })) > 0 ) {
                     for $port ( sort numerically keys %{ $items{$sid}{$inf}{$addr}{$proto} } ) {
                        if ($startseries > 0) {
                           if ($port == ($lastseries + 1)) {
                              $lastseries = $port;
                           } else {
                              if ($startseries != $lastseries) {
                                 print "$startseries-$lastseries, ";
                                 $startseries = $port;
                                 $lastseries = $port;
                              } else {
                                 print "$startseries, ";
                                 $startseries = $port;
                                 $lastseries = $port;
                              }
                           }
                        } else {
                           $startseries = $port;
                           $lastseries = $port;
                        }
                     }

                     if ($startseries > 0) {
                        if ($startseries != $lastseries) {
                           print "$startseries-$lastseries";
                        } else {
                           print "$startseries";
                        }
                     }
                  }
               }
               print "\n";
            }
         }
      }
   }
}

exit 0;

sub numerically { $a <=> $b };

