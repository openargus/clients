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

