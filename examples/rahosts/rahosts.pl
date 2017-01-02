#!@PERLBIN@
#  Argus Software
#  Copyright (c) 2000-2022 QoSient, LLC
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

use strict;

# Used modules
use POSIX;
use Socket;

# Global variables
my $tmpfile = tmpnam();
my $tmpconf = $tmpfile . ".conf";

my $Program = `which ra`;
my $Options = "-L -1 -n -s saddr:32 daddr:32 proto -c , ";
my $VERSION = "3.0.1";                
my @arglist = ();

chomp $Program;

our ($mode, %items, %addrs, $saddr, $daddr, $taddr, $baddr, $proto);

my $quiet = 0;
my $done = 0;
my @arglist;
my @args;

my ($sx, $sy, $sz, $sw);
my ($dx, $dy, $dz, $dw);

ARG: while (my $arg = shift(@ARGV)) {
   if (!$done) {
      for ($arg) {
         s/^-q//    && do { $quiet++; next ARG; };
      }

   } else {
      for ($arg) {
         s/\(/\\\(/            && do { ; };
         s/\)/\\\)/            && do { ; };
      }
   }

   $args[@args + 0] = $arg;
}

@arglist = ($Program, $Options, @args);

# Start the program

open(SESAME, "@arglist |");
while (my $data = <SESAME>) {
   chomp $data;
   ($saddr, $daddr, $proto) = split (/,/, $data);

   if (!($proto eq "man")) {
      if ((!($saddr eq "0.0.0.0")) && (!($daddr eq "0.0.0.0"))) {
         ($sx, $sy, $sz, $sw) = split(/\./, $saddr);
         ($dx, $dy, $dz, $dw) = split(/\./, $daddr);
         $addrs{$saddr}++; 
         $items{$saddr}{$dx}{$dy}{$dz}{$dw}++; 
         $addrs{$daddr}++; 
         $items{$daddr}{$sx}{$sy}{$sz}{$sw}++; 
      }
   }
}

close(SESAME);

for $saddr ( sort internet keys(%items) ) {
   my $startseries = 0;
   my $lastseries = 0;

   if ($addrs{$saddr} >= 1) {
      if ( scalar(keys(%{$items{$saddr} })) > 0 ) {
         my $count = RaGetAddressCount($saddr);
         print "$saddr: ($count) ";

         if ( $quiet == 0 ) {
         for $sx ( sort numerically keys(%{$items{$saddr} })) {
            if ( scalar(keys(%{$items{$saddr}{$sx} })) > 0 ) {
               for $sy ( sort numerically keys(%{$items{$saddr}{$sx}})) {
                  if ( scalar(keys(%{$items{$saddr}{$sx}{$sy}})) > 0 ) {
                     for $sz ( sort numerically keys(%{$items{$saddr}{$sx}{$sy}})) {
                        if ( scalar(keys(%{$items{$saddr}{$sx}{$sy}{$sz}})) > 0 ) {
                           for $sw ( sort numerically keys(%{$items{$saddr}{$sx}{$sy}{$sz}})) {
                              my $addr = "$sx.$sy.$sz.$sw";
                              my $ipaddr = inet_aton($addr);
                              my $naddr = unpack "N", $ipaddr;

                              if ($startseries > 0) {
                                 if ($naddr == ($lastseries + 1)) {
                                    $lastseries = $naddr;  
                                 } else {
                                    my ($a1, $a2, $a3, $a4) = unpack('C4', pack("N", $lastseries));
                                    if ((($a4 == 254) && ($sw == 0)) && (($a3 + 1) == $sz)) {
                                       $lastseries = $naddr;
                                    } else {
                                       my $startaddr = inet_ntoa(pack "N", $startseries);
                                       my $lastaddr  = inet_ntoa(pack "N", $lastseries);

                                       if ($startseries != $lastseries) {
                                          print "$startaddr - $lastaddr, ";
                                          $startseries = $naddr;
                                          $lastseries = $naddr;
                                       } else {
                                          print "$startaddr, ";
                                          $startseries = $naddr;
                                          $lastseries = $naddr;
                                       }
                                    }
                                 }

                              } else {
                                 $startseries = $naddr;
                                 $lastseries = $naddr;
                              }
                           }
                        }
                     }
                  }
               }
            }
         }
      }
    
      if ($startseries > 0) {
         my $startaddr = inet_ntoa(pack "N", $startseries);
         my $lastaddr  = inet_ntoa(pack "N", $lastseries);

         if ($startseries != $lastseries) {
            print "$startaddr - $lastaddr";
         } else {
            print "$startaddr";
         }
      }
      }
      print "\n";
   }
}

`rm -f $tmpconf`;

exit 0;

sub RaGetAddressCount() {
   my $thisaddr = shift(@_);
   my $retn = 0;
   my ($i, $j, $k, $l);

   for $i ( sort keys %{$items{$thisaddr} }) {
      for $j ( sort keys(%{$items{$thisaddr}{$i}})) {
         for $k ( sort keys(%{$items{$thisaddr}{$i}{$j}})) {
            for $l ( sort keys(%{$items{$thisaddr}{$i}{$j}{$k}})) {
               $retn++;
            }
         }
      }
   }

   return ($retn);
}

sub numerically { $a <=> $b };

sub internet {
   my @a_fields = split /\./, $a;
   my @b_fields = split /\./, $b;
 
   $a_fields[0] <=> $b_fields[0] ||
   $a_fields[1] <=> $b_fields[1] ||
   $a_fields[2] <=> $b_fields[2] ||
   $a_fields[3] <=> $b_fields[3]
}
