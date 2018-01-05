#!/usr/bin/perl
# 
#   Gargoyle Client Software.  Tools to read, analyze and manage Argus data.
#   Copyright (c) 2000-2017 QoSient, LLC
#   All Rights Reserved
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
#   rascannerdaily - run the scanner logic for all four modes.
#
#
# % rascanner.pl -time -1d -thresh 64 -mode [local,remote,outsidein,insideout]
#
#

# Complain about undeclared variables
use v5.6.0;
use strict;
use warnings;

$ENV{'PATH'} = '/bin:/usr/bin:/usr/local/bin:/opt/local/lib/mariadb/bin';

# Used modules
use POSIX;

use File::Temp qw/ tempfile tempdir /;
use qosient::util;  # parsetime


# Global variables
my $VERSION = "5.0.3";

my $tdate        = `date`;

chomp $tdate;

my $time;
my $debug        = 0;
my $done         = 0;

my $cmd;
my $f;
my $fname;

($f,  $fname)    = tempfile();

# Parse the arguements if any

my @arglist = ();
ARG: while (my $arg = shift(@ARGV)) {
   for ($arg) {
      /^-debug$/  && do { $debug++; };
      s/^-t$//      && do { $time = shift(@ARGV); next ARG; };
      s/^-time$//   && do { $time = shift(@ARGV); next ARG; };
   }
   $arglist[@arglist + 0] = $arg;
}


if (not defined ($time)) {
   $time = "-1d";
}

my    @time = parsetime($time);
my    $date = strftime '%Y/%m/%d', @time;
my  $dbdate = strftime '%Y_%m_%d', @time;

chomp($date);

$cmd = "rascanner -time $date -local @arglist";
print "DEBUG: calling $cmd\n" if $debug;
system($cmd);

$cmd = "rascanner -time $date -remote @arglist";
print "DEBUG: calling $cmd\n" if $debug;
system($cmd);

$cmd = "rascanner -time $date -outsidein @arglist";
print "DEBUG: calling $cmd\n" if $debug;
system($cmd);

$cmd = "rascanner -time $date -insideout @arglist";
print "DEBUG: calling $cmd\n" if $debug;
system($cmd);

