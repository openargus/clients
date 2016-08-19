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
#  
#   ra() based host use report
#  
#  $Id: //depot/argus/clients/examples/rahosts/rahosts.pl#7 $
#  $DateTime: 2016/06/01 15:17:28 $
#  $Change: 3148 $
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

my @args = ($Program, $Options, @ARGV);
our ($mode, %items, %addrs, $saddr, $daddr, $taddr, $baddr, $proto);
my ($x, $y, $z, $w);

# Start the program

open(SESAME, "@args |");
while (my $data = <SESAME>) {
   chomp $data;
   ($saddr, $daddr, $proto) = split (/,/, $data);

   if (!($proto eq "man")) {
      if ((!($saddr eq "0.0.0.0")) && (!($daddr eq "0.0.0.0"))) {
         ($x, $y, $z, $w) = split(/\./, $daddr);
         $addrs{$saddr}++; 
         $items{$saddr}{$x}{$y}{$z}{$w}++; 
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

         for $x ( sort numerically keys(%{$items{$saddr} })) {
            if ( scalar(keys(%{$items{$saddr}{$x} })) > 0 ) {
               for $y ( sort numerically keys(%{$items{$saddr}{$x}})) {
                  if ( scalar(keys(%{$items{$saddr}{$x}{$y}})) > 0 ) {
                     for $z ( sort numerically keys(%{$items{$saddr}{$x}{$y}})) {
                        if ( scalar(keys(%{$items{$saddr}{$x}{$y}{$z}})) > 0 ) {
                           for $w ( sort numerically keys(%{$items{$saddr}{$x}{$y}{$z}})) {
                              my $addr = "$x.$y.$z.$w";
                              my $ipaddr = inet_aton($addr);
                              my $naddr = unpack "N", $ipaddr;

                              if ($startseries > 0) {
                                 if ($naddr == ($lastseries + 1)) {
                                    $lastseries = $naddr;  
                                 } else {
                                    my ($a1, $a2, $a3, $a4) = unpack('C4', pack("N", $lastseries));
                                    if ((($a4 == 254) && ($w == 0)) && (($a3 + 1) == $z)) {
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
