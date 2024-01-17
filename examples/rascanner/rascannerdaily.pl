#!@PERLBIN@
# 
#  Gargoyle Client Software.  Tools to read, analyze and manage Argus data.
#  Copyright (c) 2000-2024 QoSient, LLC
#  All Rights Reserved
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
#   rascannerdaily - run the scanner logic for all four modes over a set of days.
#
#
# % rascanner.pl -time -1d -thresh 64 -mode [local,remote,outsidein,insideout]
#
#
# Complain about undeclared variables
use v5.6.0;
use strict;

$ENV{'PATH'} = '/bin:/usr/bin:/usr/local/bin';

# Used modules
use POSIX;
use qosient::XS::util;
use Time::Local;

use Switch;
use File::Temp qw/ tempfile tempdir /;
use File::Which qw/ which where /;
use CGI qw(:standard);
use Text::CSV_XS;
use Time::Local;


my $query = new CGI;
my ($val, $stime, $etime);

# Global variables
my $VERSION = "5.0.3";
my @arglist = ();

my $logfile     = "/tmp/cal.out";

my $tdate       = `date`;
my $remote      = $query->remote_host();
my $soname      = $query->server_name();
my $port        = $query->server_port();

chomp $tdate;

my @names       = $query->param;
my $dm          = $query->param('dm');
my $time        = $query->param('tm');
my $interval    = $query->param('in');
my $filter      = $query->param('fi');
my $option      = $query->param('op');
my $object      = $query->param('ob');
my $database    = $query->param('db');
my $search      = $query->param('se');
my $field       = $query->param('fd');
my $mode        = $query->param('mo');
my $uuid        = $query->param('uu');
my $thresh      = $query->param('th');

my $ra;
my $rascanner   = which 'rascanner';
my @dates;

my $f;
my $fname;

($f,  $fname)   = tempfile();

my $debug       = 0;
my $web         = 1;
my $quiet       = 0;
my $force       = 0;
my $done        = 0;
my $qstr        = "";

# Parse the arguements if any

ARG: while (my $arg = shift(@ARGV)) {
    if (!$done) {
      for ($arg) {
         s/^-thresh$//   && do { $thresh = shift(@ARGV); next ARG; };
         s/^-debug$//    && do { $debug++; next ARG; };
         s/^-quiet$//    && do { $quiet = 1; next ARG; };
         s/^-db$//       && do { $database = shift(@ARGV); next ARG; };
         s/^-dbase$//    && do { $database = shift(@ARGV); next ARG; };
         s/^-dm$//       && do { $dm = shift(@ARGV); next ARG; };
         s/^-t$//        && do { $time = shift(@ARGV); next ARG; };
         s/^-time$//     && do { $time = shift(@ARGV); next ARG; };
         s/^-search$//   && do { $search = shift(@ARGV); next ARG; };
         s/^-obj$//      && do { $object = shift(@ARGV); next ARG; };
         s/^-ob$//       && do { $object = shift(@ARGV); next ARG; };
         s/^-field$//    && do { $field = shift(@ARGV); next ARG; };
         s/^-filter$//   && do { $filter = shift(@ARGV); next ARG; };
         s/^-force$//    && do { $force++; next ARG; };
         s/^-uuid$//     && do { $uuid = shift(@ARGV); next ARG; };
         s/^-mode$//     && do { $mode = shift(@ARGV); next ARG; };
         s/^-web$//      && do { $web = 0; next ARG; };
      }
    } else {
      for ($arg) {
         s/\(/\\\(/        && do { ; };
         s/\)/\\\)/        && do { ; };
      }
   }
    $arglist[@arglist + 0] = $arg;
  }

  if ((not defined $time) || ($time eq "-1d") || ($time eq "Today")) {
     $time = RaTodaysDate();
  }

  RaScannerDailyProcessParameters($fname);
  RaScannerDailyRunRoutines($fname);
  RaScannerDailyCleanUp($fname);
  exit;


sub RaScannerDailyProcessParameters {
  if (defined $time) {
    ($val, $stime, $etime) = qosient::XS::util::ArgusParseTime($time);
    print "DEBUG: RaCalendarProcessParameters: time:'$time' val:'$val' stime:'$stime' etime:'$etime'\n" if $debug;

    @dates =  RaScannerDailyGetDates($stime,$etime);
  }
}

sub RaScannerDailyRunRoutines {
   my $file = shift;

   for my $i (0 .. $#dates) {
      my $time = $dates[$i];
      my $dbdate = $time;
      my $ra = "$rascanner -time $time";
      my $cmd = "";

      if ($debug > 0) {
         $ra .= " -debug ";
      }

      $cmd = $ra . " -local @arglist";
      print "DEBUG: calling $cmd\n" if $debug;
      system($cmd);

      $cmd = $ra . " -remote @arglist";
      print "DEBUG: calling $cmd\n" if $debug;
      system($cmd);

      $cmd = $ra . " -inside @arglist";
      print "DEBUG: calling $cmd\n" if $debug;
      system($cmd);

      $cmd = $ra . " -outside @arglist";
      print "DEBUG: calling $cmd\n" if $debug;
      system($cmd);
   }
}

sub RaScannerDailyCleanUp {
   my $file = shift;
   print "DEBUG: deleting '$file'\n" if $debug;
   unlink $file;
   exit 0;
}

sub RaScannerDailyGetDates {
   my $stime = shift;
   my $etime = shift;
   my @dates = ();

   print "DEBUG: RaScannerDailyGetDates: stime $stime etime $etime\n" if $debug;

   while ($stime <= $etime) {
      my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($stime);
      my $date = sprintf("%4d/%02d/%02d", $year+1900, $mon + 1, $mday);
      push @dates, $date;
      $stime += 86400;
   }

   my $dlen = scalar @dates;
   print "DEBUG: RaScannerDailyGetDates: found $dlen values\n" if $debug;
   return @dates;
}

sub RaTodaysDate {
  my($day, $month, $year)=(localtime)[3,4,5];
  return sprintf( "%04d/%02d/%02d", $year+1900, $month+1, $day);
}
