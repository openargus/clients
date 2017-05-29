#!@PERLBIN@
#
#  Gargoyle Client Software. Tools to read, analyze and manage Argus data.
#  Copyright (c) 2000-2014 QoSient, LLC
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
#  radnsdb - uses radns json data for database insertion
#
#  written by Carter Bullard
#  QoSient, LLC
#
#
# Complain about undeclared variables
use v5.6.0;
use strict;

$ENV{'PATH'} = '/bin:/usr/bin:/usr/local/bin';

# Used modules
use POSIX;
use URI::URL;

use JSON;
use DBI;
use Switch;
use File::Which qw/ which where /;;
use Time::Local;

# Global variables
my $VERSION = "5.0.3";

my $debug   = 0;
my $quiet   = 0;
my $uri     = 0;
my $time    = "-1d";

my $scheme;
my $netloc;
my $path;

my @arglist = ();

print "DEBUG: RaDNSDb: starting @ARGV\n" if $debug;

ARG: while (my $arg = shift(@ARGV)) {
   for ($arg) {
      s/^-debug//         && do { $debug++; next ARG; };
      s/^-t//             && do { $time = shift (@ARGV); next ARG; };
      s/^-q//             && do { $quiet++; next ARG; };
      s/^-w//             && do { $uri = shift (@ARGV); next ARG; };
      /^-M/               && do {
         for ($ARGV[0]) {
            /json/  && do {
               shift (@ARGV);
               next ARG;
            };
         };
      };
   }

   $arglist[@arglist + 0] = $arg;
}


# Start the program

my @results     = ();
my $results_ref = \@results;

my $rasql       = which 'rasql';
my $radns       = which 'radns';
my $options     = "-qM json search:0.0.0.0/0";

my $Program = "$rasql -t $time -r mysql://root\@localhost/dnsFlows/dns_%Y_%m_%d -M time 1d -w - | $radns $options";

my (%items, %addrs, $addr);

print "DEBUG: RaDNSDb: calling $Program\n" if $debug;
open(SESAME, "$Program |");

while (my $data = <SESAME>) {
   chomp($data);

   print "DEBUG: RaDnsDb:  radns returned: $data\n" if $debug;

   if (length($data)) {
      print "DEBUG: RaDNSDbFetchData: $data\n" if $debug;
      my $decoded = decode_json $data;
      push(@$results_ref, $decoded);
   }
}
close(SESAME);

my $startseries = 0;
my $lastseries = 0;
my ($user, $pass, $host, $port, $space, $db, $table);
my $dbh;


if ($uri) {
   my $url = URI::URL->new($uri);

   print "DEBUG: RaDNSDb: url is $url\n" if $debug;

   $scheme = $url->scheme;
   $netloc = $url->netloc;
   $path   = $url->path;

   if ($netloc ne "") {
      ($user, $host) = split /@/, $netloc;
      if ($user =~ m/:/) {
         ($user , $pass) = split/:/, $user;
      }
      if ($host =~ m/:/) {
         ($host , $port) = split/:/, $host;
      }
   }

   if ($path ne "") {
      ($space, $db, $table)  = split /\//, $path;
   }

   $dbh = DBI->connect("DBI:$scheme:;host=$host", $user, $pass) || die "Could not connect to database: $DBI::errstr";

   $dbh->do("CREATE DATABASE IF NOT EXISTS $db");
   $dbh->do("use $db");

   print "DEBUG: RaDnsDB: CREATE TABLE $table (addr VARCHAR(64) NOT NULL, names TEXT, PRIMARY KEY ( addr ))\n" if $debug;

   # Drop table 'foo'. This may fail, if 'foo' doesn't exist
   # Thus we put an eval around it.

   {
      local $dbh->{RaiseError} = 0;
      local $dbh->{PrintError} = 0;

      eval { $dbh->do("DROP TABLE $table") };
   }

   # Create a new table 'foo'. This must not fail, thus we don't catch errors.

   print "DEBUG: RaDnsDB: CREATE TABLE $table (addr VARCHAR(64) NOT NULL, names TEXT, PRIMARY KEY ( addr ))\n" if $debug;

   $dbh->do("CREATE TABLE $table (addr VARCHAR(64) NOT NULL, names TEXT, PRIMARY KEY ( addr ))");

   if ((length @results) > 0) {
      foreach my $n (@$results_ref) {
         my $addr = $n->{'addr'};
         my $data = JSON->new->utf8->space_after->encode($n);

         my $sql = "INSERT INTO $table VALUE('$addr', '$data')";
         print "DEBUG: RaDNSDbFetchData: $sql\n" if $debug;
         $dbh->do($sql);
      }

   } else {
      print "DEBUG: RaInventoryGenerateResults: no results\n" if $debug;
   }
 
   $dbh->disconnect();

} else {
   if ((length @results) > 0) {
      foreach my $n (@$results_ref) {
         my $data = JSON->new->utf8->space_after->encode($n);
         printf "$data\n";
      }
   }
}

exit 0;

sub numerically { $a <=> $b };

