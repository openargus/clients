#!@PERLBIN@
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
#  
#   rahostsdaily - run rahosts to update the daily inventory tables.
#  
#  $Id: //depot/gargoyle/clients/examples/rahosts/rahosts.pl#5 $
#  $DateTime: 2014/10/07 15:00:33 $
#  $Change: 2938 $
# 
#
# Complain about undeclared variables
use v5.6.0;
use strict;

local $ENV{PATH} = "$ENV{PATH}:/bin:/usr/bin:/usr/local/bin";

# Used modules
use POSIX;
use POSIX qw(strftime);
use URI::URL;
use DBI;
use Switch;
use Net::IP;
use File::Which qw/ which /;
use Socket;

use File::Temp qw/ tempfile tempdir /;
use File::Which qw/ which where /;
use qosient::XS::util;  # parsetime

# Global variables
my $VERSION = "5.0.3";
my $done = 0;
my $debug = 0;
my $drop  = 0;
my $time;
my $database;

my ($val, $stime, $etime);
my ($user, $pass, $host, $port, $space, $db, $table);
my $dbh;
my $sth;

my $uri     = 0;
my $scheme;
my $netloc;
my $path;

my $datename    = "";
my @results     = ();
my $results_ref = \@results;
my $elements    = "";
my $object      = "";

my $ra;
my $rahosts     = which 'rahosts';

my @dates;

my $f;
my $fname;
($f,  $fname)   = tempfile();

# Parse the arguments if any

my @arglist;
  ARG: while (my $arg = shift(@ARGV)) {
    if (!$done) {
       for ($arg) {
           s/^-debug$//  && do { $debug++; next ARG; };
           s/^-drop//    && do { $drop = 1; next ARG; };
           s/^-dbase$//  && do { $database = shift(@ARGV); next ARG; };
           s/^-t$//      && do { $time = shift(@ARGV); next ARG; };
           s/^-time$//   && do { $time = shift(@ARGV); next ARG; };
           s/^-w//       && do { $uri = shift (@ARGV); next ARG; };
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

  RaHostsDailyProcessParameters($fname);
  RaHostsDailyRunRoutines($fname);
  RaHostsDailyCleanUp($fname);
  exit;


sub RaHostsDailyProcessParameters {
  if (defined $time) {
    ($val, $stime, $etime) = qosient::XS::util::ArgusParseTime($time);
    print "DEBUG: RaCalendarProcessParameters: time:'$time' val:'$val' stime:'$stime' etime:'$etime'\n" if $debug;

    @dates =  RaHostsDailyGetDates($stime,$etime);
  }
}

sub RaHostsDailyRunRoutines {
   for my $i (0 .. $#dates) {
      my $time = $dates[$i];
      my  $dbdate = $time;
      $dbdate =~ s/\//_/g;
      my $ra = "$rahosts -F /usr/argus/rarc -t $time -w mysql://root\@localhost/hostsInventory/host_$dbdate";

      if ($debug > 0) {
         $ra .= " -D3";
      }
      print "DEBUG: calling: $ra\n" if $debug;

      if (system($ra) != 0) {
         print "rahostsdaily: error: $ra failed\n";
         exit -1;
      }
   }
}


sub RaHostsDailyCleanUp {
   my $file = shift;
   print "DEBUG: deleting '$file'\n" if $debug;
   unlink $file;
   exit 0;
}


sub RaHostsDailyGetDates {
   my $stime = shift;
   my $etime = shift;
   my @dates = ();

   print "DEBUG: RaHostsDailyGetDates: stime $stime etime $etime\n" if $debug;

   while ($stime < $etime) {
      my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($stime);
      my $date = sprintf("%4d/%02d/%02d", $year+1900, $mon + 1, $mday);
      push @dates, $date;
      $stime += 86400;
   }

   my $dlen = scalar @dates;
   print "DEBUG: RaHostsDailyGetDates: found $dlen values\n" if $debug;
   return @dates;
}

sub RaTodaysDate {
  my($day, $month, $year)=(localtime)[3,4,5];
  return sprintf( "%04d/%02d/%02d", $year+1900, $month+1, $day);
}
