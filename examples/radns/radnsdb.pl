#!/usr/bin/perl
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
use IO::Handle;
use URI::URL;

use JSON;
use DBI;
use Switch;
use File::Which qw/ which where /;;
use Time::Local;
use Data::Dumper;

# Global variables
my $VERSION = "5.0.3";

my $debug   = 0;
my $quiet   = 0;
my $uri     = 0;
my $time    = "-1d";
my $mtbl    = "";

my $mode    = 0;
my $node    = "";
my $flows   = "dnsFlows";

my $scheme;
my $netloc;
my $path;

my @arglist = ();

ARG: while (my $arg = shift(@ARGV)) {
   for ($arg) {
      s/^-debug//         && do { $debug++; next ARG; };
      s/^-t//             && do { $time = shift (@ARGV); next ARG; };

      s/^-time//          && do { $time = shift (@ARGV); next ARG; };
      s/^-mode//          && do { $mode = shift (@ARGV); next ARG; };
      s/^-node//          && do { $node = shift (@ARGV); next ARG; };
      s/^-flows//         && do { $flows = shift (@ARGV); next ARG; };

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

print "DEBUG: RaDNSDb: starting\n" if $debug;

# Start the program

my @results     = ();
my $results_ref = \@results;

my $rasql       = which 'rasql';
my $ra          = which 'ra';
my $radns       = which 'radns';

my $Program;
my $options;

my (%items, %addrs, $addr);

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

   print "DEBUG: RaDNSDb: access database host $host user $user using database $db table $table\n" if $debug;

   $dbh = DBI->connect("DBI:$scheme:;host=$host", $user, $pass) || die "Could not connect to database: $DBI::errstr";

   $dbh->do("CREATE DATABASE IF NOT EXISTS $db");
   $dbh->do("use $db");


   # Drop table 'foo'. This may fail, if 'foo' doesn't exist
   # Thus we put an eval around it.

   switch ($db) {
      case /^dnsNames/ {
         $options = "-f /usr/argus/radns.conf -qM json search:0.0.0.0/0";
         $Program = "$rasql -t $time -r mysql://root\@localhost/$flows/dns_%Y_%m_%d -M time 1d -w - | $radns $options";
      }
      case /^dnsAddrs/ {
         $options = "-f /usr/argus/radns.conf -qM json search:'.'";
         $Program = "$rasql -t $time -r mysql://root\@localhost/$flows/dns_%Y_%m_%d -M time 1d -w - | $radns $options";
      }
   }

   print "DEBUG: RaDNSDb: calling Program $Program\n" if $debug;
   open(SESAME, "$Program |");
   while (my $data = <SESAME>) {
      chomp($data);

      print "DEBUG: RaDnsDb:  radns returned: $data\n" if $debug;

      if (length($data)) {
         if ($data !~ /\^/) {
            eval {
               my $decoded = JSON->new->utf8->decode($data);
               push(@$results_ref, $decoded);
            } or do {
            }
         }
      }
   }
   close(SESAME);

   switch ($db) {
      case /^dnsNames/ {
         if (scalar(@{$results_ref}) > 0) {
            # Create a new table 'foo'. This must not fail, thus we don't catch errors.

            print "DEBUG: RaDnsDB: CREATE TABLE IF NOT EXISTS $table (addr VARCHAR(64) NOT NULL, names TEXT, PRIMARY KEY ( addr ))\n" if $debug;
            $dbh->do("CREATE TABLE IF NOT EXISTS $table (addr VARCHAR(64) NOT NULL, names TEXT, PRIMARY KEY ( addr ))");

            foreach my $n (@$results_ref) {
               my $addr = $n->{'addr'};
               my $data = JSON->new->utf8->space_after->encode($n);
 
               my $sql = "INSERT INTO $table (addr,names) VALUES('$addr', '$data') ON DUPLICATE KEY UPDATE names='$data'";
               print "DEBUG: RaDNSDbFetchData: $sql\n" if $debug;
               $dbh->do($sql);
            }
         } else {
            print "DEBUG: RaInventoryGenerateResults: no results\n" if $debug;
         }
      }
      case /^dnsAddrs/ {
         if (scalar(@{$results_ref}) > 0) {
            # Create a new table 'foo'. This must not fail, thus we don't catch errors.

            my $SQL  = "CREATE TABLE IF NOT EXISTS $table (";
               $SQL .= "`name` varchar(128) NOT NULL,";
               $SQL .= "`tld` varchar(64),";
               $SQL .= "`nld` varchar(64),";
               $SQL .= "`ref` INT,";
               $SQL .= "`stime` double(18,6) unsigned,";
               $SQL .= "`ltime` double(18,6) unsigned,";
               $SQL .= "`addrs` TEXT,";
               $SQL .= "`client` TEXT,";
               $SQL .= "`server` TEXT,";
               $SQL .= "`cname` TEXT,";
               $SQL .= "`ptr` TEXT,";
               $SQL .= "`ns` TEXT,";
               $SQL .= "PRIMARY KEY (`name`))";

            print "DEBUG: RaDnsDB: $SQL\n" if $debug;
            $dbh->do($SQL);

            my $str = sprintf "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=\"$db\" AND TABLE_NAME=\"$table\"";
            print "DEBUG: RaEsocFetchData: sql:$str\n" if $debug;

            my $sth = $dbh->prepare($str) or die "can't prepare: ", $DBI::errstr, "\n";
            $sth->execute() or die "can't execute: ", $DBI::errstr, "\n";

            my $stimetbl = 0;
            my $ltimetbl = 0;

            while(my @row = $sth->fetchrow_array()) {
               my $column = $row[0];
               switch ($column) {
                  case "stime"     {  $stimetbl = 1; }
                  case "ltime"     {  $ltimetbl = 1; }
              }
            }
            $sth->finish();
            if ($stimetbl == 0) {
               $str  = sprintf "ALTER TABLE $table ADD COLUMN `stime` double(18,6) AFTER `nld`";
               $dbh->do($str);
               print "DEBUG: sql '$str'\n" if $debug;
            }
            if ($ltimetbl == 0) {
               $str  = sprintf "ALTER TABLE $table ADD COLUMN `ltime` double(18,6) AFTER `stime`";
               $dbh->do($str);
               print "DEBUG: sql '$str'\n" if $debug;
            }

            foreach my $n (@$results_ref) {
               my ($name,$tld,$nld,$stime,$ltime,$ref,$addrs,$client,$server,$cname,$ptr,$ns);
               my ($tind,$nind);

               if (defined $n->{'name'}) {
                  $name = $n->{'name'};
                  my $slen = length($name);

                  $tind = rindex( $name, '.', $slen - 2 );
                  if ($tind > 0) {
                     $tld = substr( $name, $tind + 1);
                     if (defined $tld) {
                        $n->{'tld'} = $tld;
                        $tld   = '"' . $n->{'tld'} . '"';
                     }

                     $nind = rindex( $name, '.', $tind - 1);
                     if ($nind > 0) {
                        $nld = substr( $name, $nind + 1 );

                        if (defined $nld) {
                           $n->{'nld'} = $nld;
                           $nld   = '"' . $n->{'nld'} . '"';
                        }
                     }
                  }

                  if ((not defined $tld) || (length($tld) == 0)) { $tld = '"' . $name . '"'; $n->{'tld'} = $name; }
                  if ((not defined $nld) || (length($nld) == 0)) { $nld = '"' . $name . '"'; $n->{'nld'} = $name; }

                  print "DEBUG: RaDnsDB: name:$name length:$slen tind:$tind tld:$tld nind:$nind nld:$nld\n" if $debug;
                  $name  = '"' . $n->{'name'} . '"'
               }

               if (defined $n->{'stime'})  { $stime   = $n->{'stime'}};
               if (defined $n->{'ltime'})  { $ltime   = $n->{'ltime'}};
               if (defined $n->{'ref'})  { $ref   = $n->{'ref'}};

               if (defined $n->{'addr'}) { 
                  my $array = $n->{'addr'}; 
                  $addrs = "'" . JSON->new->utf8->encode($array) . "'";
               };
               if (defined $n->{'client'}) {
                  my $array = $n->{'client'};
                  $client = "'" . JSON->new->utf8->encode($array) . "'";
               };
               if (defined $n->{'server'}) { 
                  my $array = $n->{'server'};
                  $server = "'" . JSON->new->utf8->encode($array) . "'";
               };
               if (defined $n->{'cname'}) { 
                  my $array = $n->{'cname'};
                  $cname = "'" . JSON->new->utf8->encode($array) . "'";
               };
               if (defined $n->{'ptr'}) { 
                  my $array = $n->{'ptr'};
                  $ptr = "'" . JSON->new->utf8->encode($array) . "'";
               };
               if (defined $n->{'ns'}) { 
                  my $array = $n->{'ns'};
                  $ns = "'" . JSON->new->utf8->encode($array) . "'";
               };

               if (defined $addrs) { 
                  my @fields = ();
                  my @values = ();
                  my $str = "";

                  if (defined $name)   { push(@fields,"name");   push(@values, $name); }
                  if (defined $tld)    { push(@fields,"tld");    push(@values, $tld); }
                  if (defined $nld)    { push(@fields,"nld");    push(@values, $nld); }
                  if (defined $stime)  { push(@fields,"stime");  push(@values, $stime); }
                  if (defined $ltime)  { push(@fields,"ltime");  push(@values, $ltime); }
                  if (defined $ref)    { push(@fields,"ref");    push(@values, $ref); }
                  if (defined $addrs)  { push(@fields,"addrs");  push(@values, $addrs); }
                  if (defined $client) { push(@fields,"client"); push(@values, $client); }
                  if (defined $server) { push(@fields,"server"); push(@values, $server); }
                  if (defined $cname)  { push(@fields,"cname");  push(@values, $cname); }
                  if (defined $ptr)    { push(@fields,"ptr");    push(@values, $ptr); }
                  if (defined $ns)     { push(@fields,"ns");     push(@values, $ns); }

                  my $cols = join(",", @fields);
                  my $vals = join(",", @values);

                  my $SQL  = "INSERT INTO $table ($cols) VALUES ($vals) ";
                  my $dup = " ON DUPLICATE KEY UPDATE ";
                  my $fcnt = scalar @fields;

                  for (my $i = 0; $i < $fcnt; $i++) {
                     if ($i > 0) {
                        $dup .= ",";
                     }
                     $dup .= "`$fields[$i]`=$values[$i]";
                  }

                  $SQL .= $dup.";";
                  print "DEBUG: results: sql: '$SQL'\n" if $debug;

                  $dbh->do($SQL);
               }
            }
         } else {
            print "DEBUG: RaInventoryGenerateResults: no results\n" if $debug;
         }
      }
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

