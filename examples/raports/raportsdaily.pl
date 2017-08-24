#!/usr/bin/perl
# 
#  Gargoyle Client Software. Tools to read, analyze and manage Argus data.
#  Copyright (c) 2000-2017 QoSient, LLC
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
#  $Id: //depot/gargoyle/clients/examples/raports/raports.pl#5 $
#  $DateTime: 2014/10/07 15:00:33 $
#  $Change: 2938 $
# 

#
# Complain about undeclared variables

use strict;

# Used modules
use POSIX;
use POSIX qw(strftime);

use File::DosGlob qw/ bsd_glob /;
use File::Temp qw/ tempfile tempdir /;
use File::Which qw/ which /;
use Time::Local;
use Switch;

# Global variables
my $VERSION = "5.0,3";
my $done    = 0;
my $debug   = 0;
my $time;
my $archive;

# Parse the arguments if any

my @arglist;
ARG: while (my $arg = shift(@ARGV)) {
  if (!$done) {
     for ($arg) {
         s/^-debug$//  && do { $debug++; next ARG; };
         s/^-r$//      && do { $archive = shift(@ARGV); next ARG; };
         s/^-t$//      && do { $time = shift(@ARGV); next ARG; };
     }
  } else {
      for ($arg) {
         s/\(/\\\(/        && do { ; };
         s/\)/\\\)/        && do { ; };
      }
  }
  $arglist[@arglist + 0] = $arg;
}


print "DEBUG: raportsdaily: using $time as date adjustment\n" if $debug;

if (not defined ($archive)) {
  $archive = "/home/argus/\$sid/\$inf/%Y/%m/%d/argus.%Y.%m.%d.%H.%M.%S";
}
print "DEBUG: raportsdaily: archive: $archive\n" if $debug;

$archive =~ s/\/%d\/.*/\/%d/;
my @dirs = split ( /(\/)/, $archive);
$archive = "";
foreach my $i (@dirs) {
   if (index($i, "\$") != -1) {
      $archive .= "*";
   } else {
      $archive .= $i;
   }
}
print "DEBUG: raportsdaily: using $archive as source files.\n" if $debug;

my @time;
my ($sec, $min, $hour, $mday, $mon, $year) = localtime();

if ($time eq "") {
   my $yesterday = timelocal(0,0,12,$mday,$mon,$year) - 24*60*60;
   @time = localtime($yesterday);

} else {
   my $op = substr( $time, 0, 1 );

   if ($op == '-') {
      my $value = substr($time, 1);
      my $index = substr($time, -1);
      $value =~ /(\d+)/;

      switch ($index) {
         case 's' { }
         case 'm' { $value *= 60 }
         case 'h' { $value *= 60 * 60 }
         case 'd' { $value *= 24 * 60 * 60 }
         case 'w' { $value *= 7 * 24 * 60 * 60 }
         case 'M' { 
            $mon -= $value ;
            while ($mon < 0) {
               $year--;
               $mon += 12;
            }
            $value = 0 
         }
         case 'Y' { $year -= $value ; $value = 0 }
      }
      my $time = timelocal($sec,$min,$hour,$mday,$mon,$year) - $value;
      @time = localtime($time);

   } else {
      my ($year, $mon, $mday) = split ( '/', $time);
      my $time = timelocal(0,0,12,$mday,$mon-1,$year-1900);
      @time = localtime($time);
   }
}

my    $date = strftime '%Y/%m/%d', @time;
my  $dbdate = strftime '%Y_%m_%d', @time;
my $pattern = strftime $archive, @time;

chomp($date);
chomp($pattern);

print "DEBUG: raportsdaily: '$date' for date and '$pattern' for files\n" if $debug;

my $Program = which 'raports';
chomp $Program;

my $srcOptions = "-M src -w mysql://root\@localhost/portsInventory/srcPorts_$dbdate";
my $dstOptions = "-M dst -w mysql://root\@localhost/portsInventory/dstPorts_$dbdate";
my $filter     = "- src pkts gt 0 and dst pkts gt 0";

my @files   = glob $pattern; 

foreach my $file (@files) {
   if (index($file, "man") == -1) {
      if (index($file, "evt") == -1) {
         if (index($file, "rad") == -1) {
            my $cmd = $Program . " " . $srcOptions . " -r $file $filter";
            print "DEBUG: raportsdaily: $cmd\n" if $debug;
            if (system($cmd) != 0) {
               print "raportsdaily: error: $cmd failed\n";
               exit -1;
            }
            $cmd = $Program . " " . $dstOptions . " -r $file $filter";
            print "DEBUG: raportsdaily: $cmd\n" if $debug;
            if (system($cmd) != 0) {
               print "raportsdaily: error: $cmd failed\n";
               exit -1;
            }
         }
      }
   }
}
exit 0;
