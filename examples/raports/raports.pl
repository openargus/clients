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
#  ra() based host port use report
#  
#  written by Carter Bullard
#  QoSient, LLC
#
# 
#  $Id: //depot/argus/clients/examples/raports/raports.pl#7 $
#  $DateTime: 2016/06/01 15:17:28 $
#  $Change: 3148 $
# 

#
# Complain about undeclared variables

use strict;

# Used modules
use POSIX;

# Global variables

my $Program = `which racluster`;
my $Options = " -nc , ";   # Default Options
my $VERSION = "4.0.0";                
my $format  = 'dst';
my $fields  = '-s daddr proto dport';
my $model   = '-m daddr proto dport';
my @arglist = ();

ARG: while (my $arg = shift(@ARGV)) {
   for ($arg) {
      /^-M/               && do {
         for ($ARGV[0]) {
            /src/  && do {
               $format = 'src'; 
               $fields = '-s saddr:15 proto sport:15'; 
               $model  = '-m saddr proto sport'; 
               shift (@ARGV); 
               next ARG; 
            };

            /dst/  && do {
               $format = 'dst'; 
               $fields = '-s daddr:15 proto dport:15'; 
               $model  = '-m daddr proto dport'; 
               shift (@ARGV); 
               next ARG; 
            };
         };
      };
   }

   $arglist[@arglist + 0] = $arg;
}

# Start the program
chomp $Program;
my @args = ($Program, $Options, $model, $fields, @arglist);
my (%items, %addrs, $addr, $proto, $port);

print " @args ";

open(SESAME, "@args |");
while (my $data = <SESAME>) {
   $data =~ s/^,//;
   ($addr, $proto, $port) = split(/,/, $data);
   chomp $port;
   if (!($addr eq "0.0.0.0")) {
      for ($proto) {
         /6/   && do { 
            $addrs{$addr}++; 
            $items{$addr}{$proto}{$port}++; 
         } ;
         /17/   && do { 
            $addrs{$addr}++; 
            $items{$addr}{$proto}{$port}++; 
         } ;
      }
   }
}
close(SESAME);

my $startseries = 0;
my $lastseries = 0;

for $addr ( keys %items ) {
   for $proto ( keys %{ $items{$addr} } ) {
      if ($proto == 6) {
         printf "$addr tcp: (%d) ", scalar(keys(%{$items{$addr}{$proto} }));
      } else {
         printf "$addr udp: (%d) ", scalar(keys(%{$items{$addr}{$proto} }));
      }

      $startseries = 0;
      $lastseries = 0;

      if ( scalar(keys(%{$items{$addr}{$proto} })) > 0 ) {
         for $port ( sort numerically keys %{ $items{$addr}{$proto} } ) {
            if ($startseries > 0) {
               if ($port == ($lastseries + 1)) {
                  $lastseries = $port;
               } else {
                  if ($startseries != $lastseries) {
                     print "$startseries - $lastseries, ";
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
               print "$startseries - $lastseries";
            } else {
               print "$startseries";
            }
         }
      }

      print "\n";
   }
}

exit 0;

sub numerically { $a <=> $b };

