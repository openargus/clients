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
#  $Id: //depot/gargoyle/clients/examples/rahosts/rahosts.pl#5 $
#  $DateTime: 2014/10/07 15:00:33 $
#  $Change: 2938 $
# 

#
# Complain about undeclared variables

use strict;

# Used modules
use POSIX;

use File::DosGlob qw/ bsd_glob /;
use File::Temp qw/ tempfile tempdir /;
use File::Which qw/ which /;
use Time::Local;

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

if (not defined ($time)) {
  $time = "-1d";
}
print "DEBUG: rahostsdaily: using $time as date adjustment\n" if $debug;

if (not defined ($archive)) {
  $archive = "/home/argus/\$sid/\$inf/%Y/%m/%d/argus.%Y.%m.%d.%H.%M.%S";
}
print "DEBUG: rahostsdaily: archive: $archive\n" if $debug;

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
print "DEBUG: rahostsdaily: using $archive as source files.\n" if $debug;

my $date    = `date -v $time "+%Y_%m_%d"`;
my $pattern = `date -v $time "+$archive"`;

chomp($date);
chomp($pattern);

print "DEBUG: rahostsdaily: '$date' for date and '$pattern' for files\n" if $debug;

my $Program = which 'rahosts';
chomp $Program;

my $Options = "-w mysql://root\@localhost/hostsInventory/host_$date";

my @files   = glob $pattern; 

foreach my $file (@files) {
   if (index($file, "man") == -1) {
      if (index($file, "evt") == -1) {
         if (index($file, "rad") == -1) {
            my $cmd = $Program . " " . $Options . " -r $file";
            print "DEBUG: rahostsdaily: $cmd\n" if $debug;
            if (system($cmd) != 0) {
               print "rahostsdaily: error: $cmd failed\n";
               exit -1;
            }
         }
      }
   }
}
exit 0;