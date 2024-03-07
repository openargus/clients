#!@PERLBIN@
#
#  Gargoyle Software.  Argus Event scripts - lsof
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
#  Written by Carter Bullard
#  QoSient, LLC
#
#  rastatus-stat - Report a number of system status variables.
#
#

# Complain about undeclared variables
use v5.010;
use strict;
use warnings;

# Used modules
use POSIX;
use URI::URL;
use DBI;
use JSON;
use Switch;
use Net::IP;
use File::Temp qw/ tempfile tempdir /;
use File::Which qw/ which where /;;
use Time::Local;
use Socket;
use Data::Dumper;

local $ENV{PATH} = "$ENV{PATH}:/bin:/usr/bin:/usr/local/bin:/opt/local/lib/mariadb/bin";

# Global variables
my $VERSION = "5.0.3";
my @arglist = ();

my $file = "/proc/stat";
my %results_hash;

my $data;

my @results     = ();
my $results_ref = \@results;
my $elements    = "";

my $debug       = 0;
my $json        = 1;
my $done        = 0;
my $now         = time();

my $fields;
my $mode;
my $obj;

# Parse the arguments if any

ARG: while (my $arg = shift(@ARGV)) {
   if (!$done) {
      for ($arg) {
         s/^-debug$//      && do { $debug++; next ARG; };
         s/^-xml$//        && do { $json = 0; next ARG; };
         s/^-fields$//     && do { $fields = shift(@ARGV); next ARG; };
         s/^-mode$//       && do { $mode = shift(@ARGV); next ARG; };
         s/^-obj$//        && do { $obj = shift(@ARGV); next ARG; };
         s/^-obj$//        && do { $obj = shift(@ARGV); next ARG; };
      }
   } else {
      for ($arg) {
         s/\(/\\\(/        && do { ; };
         s/\)/\\\)/        && do { ; };
      }
   }

   $arglist[@arglist + 0] = $arg;
}


if ($json == 0) {
   print "<ArgusStatus>\n";
   print "  <ArgusStatusData Type = \"file: $file\">\n";
}

if (open(SESAME, $file)) {
   while ($data = <SESAME>) {
      if (length($data) > 0) {
         if ($data =~ /^cpu /) {
            my @fields = split(' ', $data);
            my $data_results = ();

            $data_results->{'stime'}    = $now;
            $data_results->{'name'}     = $fields[0];
            $data_results->{'user'}     = $fields[1];
            $data_results->{'nice'}     = $fields[2];

            $data_results->{'system'}   = $fields[3];
            $data_results->{'idle'}      = $fields[4];
            $data_results->{'iowait'}   = $fields[5];
            $data_results->{'irq'}      = $fields[6];
            $data_results->{'softirq'}  = $fields[7];

            push(@$results_ref, $data_results);
         }
      }
   }
   close(SESAME);
}

if ($json == 0) {
   foreach my $entry (@{ $results_ref }) {
      print "     <Data Date=\"$entry->{'date'}\" Dev=\"$entry->{'name'}\" Reads=\"$entry->{'reads'}\" Writes=\"$entry->{'writes'}\" SectorsRead=\"$entry->{'secread'}\" SectorsWrite=\"$entry->{'secwrite'}\" \\>\n"
   }

   print "  </ArgusStatusData>\n";
   print "</ArgusStatus>\n";

} else {
   print JSON->new->utf8->space_after->encode({cpu => $results_ref});
   print "\n";
}
