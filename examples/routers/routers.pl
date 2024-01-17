#! /usr/bin/perl 
# 
#  Gargoyle Client Software. Tools to read, analyze and manage Argus data.
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
#  $Id: //depot/gargoyle/clients/examples/routers/routers.pl#2 $
#  $DateTime: 2014/10/07 15:35:03 $
#  $Change: 2940 $
# 

#
# Complain about undeclared variables

use strict;

# Used modules
use POSIX;

# Global variables

my $Racluster = "/home/carter/argus/clients/bin/racluster";
my $Rasort    = "/home/carter/argus/clients/bin/rasort";
my $Options   = "-nn";        # Default Options
my $RacOpts   = "-m inode -w - ";   # Default racluster Options
my $VERSION   = "4.0.6";                
my $format    = 'inode';
my $fields    = '-s stime dur inode ias sttl avgdur maxdur mindur trans';
my $model     = '-m trans sttl';
my $filter    = '- icmpmap';
my @arglist   = ();


ARG: while (my $arg = shift(@ARGV)) {
   for ($arg) {
   }
   $arglist[@arglist + 0] = $arg;
}

# Start the program
chomp $Racluster;
chomp $Rasort;

my @cargs = ($Racluster, $Options, $RacOpts, @arglist, $filter);
my @sargs = ($Rasort, $model, $fields, $Options, "-c ,");
my @args = (@cargs, " | ", @sargs);

my (%items, %addrs, $stime, $dur, $inode, $ias, $sttl, $avgdur, $maxdur, $mindur, $trans);

printf "%s", "@args\n";

my $count     = 0;

open(SESAME, "@args |");
my $label = <SESAME>; 
chomp $label;

while (my $data = <SESAME>) {
   ($stime, $dur, $inode, $ias, $sttl, $avgdur, $maxdur, $mindur, $trans) = split(/,/, $data);
   chomp $trans;
   printf "<node type=\"ROUTER\" id=\"$inode\" >\n";
   if ($ias eq "") {
   } else {
      printf "   <property name=\"iAS\" value=\"$ias\" />\n";
   }
   printf "   <property name=\"MinDur\" value=\"$mindur\" />\n";
   printf "   <property name=\"AvgDur\" value=\"$avgdur\" />\n";
   printf "</node>\n";
}
close(SESAME);
exit 0;
