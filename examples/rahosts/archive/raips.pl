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
#  $Id: //depot/gargoyle/clients/examples/rahosts/raips.pl#6 $
#  $DateTime: 2015/07/08 12:33:29 $
#  $Change: 3040 $
# 

#
# Complain about undeclared variables

use strict;

# Used modules
use Socket;

# Global variables
my $Program = `which ra`;
my $Options = "-L -1 -n -s saddr:32 daddr:32 proto -c , ";
my $VERSION = "5.0.1";                
my @arglist = ();

chomp $Program;

my @args = ($Program, $Options, @ARGV);
our ($mode, %items, %addrs, $saddr, $daddr, $addr, $proto);
my ($x, $y, $z, $w);

# Start the program

open(SESAME, "@args |");
while (my $data = <SESAME>) {
   chomp $data;
   ($saddr, $daddr, $proto) = split (/,/, $data);

   if (!($proto eq "man")) {
      if (!($saddr eq "0.0.0.0")) {
         ($x, $y, $z, $w) = split(/\./, $saddr);
         $addrs{$saddr}++; 
         $items{$saddr}{$x}{$y}{$z}{$w}++;
      }

      if (!($daddr eq "0.0.0.0")) {
         ($x, $y, $z, $w) = split(/\./, $daddr);
         $addrs{$daddr}++; 
         $items{$daddr}{$x}{$y}{$z}{$w}++;
      }
   }
}

close(SESAME);

for $addr ( sort internet keys(%items) ) 
{
   my $startseries = 0;
   my $lastseries = 0;
   my $count = $addrs{$addr};

   print "$addr\n";
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
