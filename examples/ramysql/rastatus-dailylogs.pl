#!@PERLBIN@
#
#  Gargoyle Software.  Argus Event scripts - lsof
#  Copyright (c) 2000-2015 QoSient, LLC
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
#  rastatus-dailylogs - Generate summary of journalctl logs
#                          for a day and put them in a database table.
#
#

# Complain about undeclared variables
use v5.010;
use strict;
use warnings;
no if $] ge '5.018', warnings => "experimental::smartmatch";

$ENV{'PATH'} = '/bin:/usr/bin:/usr/local/bin:/opt/local/lib/mariadb/bin';

# Used modules
use POSIX;
use CGI qw(:standard);
use DBI;
use JSON;
use Switch;
use File::Temp qw/ tempfile tempdir /;
use File::Which qw/ which where /;
use Time::Local;

use Data::Dumper; 


my $logfile    = "/tmp/logs.out";
my $journalctl = which "journalctl";

my $query = new CGI;

# Global variables
my $VERSION = "5.0.3";
my @arglist = ();

my $remote      = $query->remote_host();
my $soname      = $query->server_name();
my $port        = $query->server_port();

my $time        = $query->param('tm');
my $crumb       = $query->param('bc');
my $score       = $query->param('sc');

my $ufilter     = "";
my $pfilter     = "";

my @results     = ();
my $results_ref = \@results;

my $f;
my $fh;
my $fname;

($f,  $fname)   = tempfile();

my $json        = 1;
my $debug       = 0;
my $dbh;

my $username    = "root";
my $password    = "";
my $database    = "";
my $table       = "";

my $quiet       = 0;
my $done        = 0;
my $qstr        = "";
my $stime       = "";
my $dtime       = "";
my $sepoch      = 0;
my $depoch      = 0;

my @priority  = ('emerg', 'alert', 'crit', 'error', 'warn', 'notice', 'info', 'debug');
my @entries   = ();
 
my $pcnt = @priority;
my $ecnt = @entries;
 
print "DEBUG: priorities $pcnt entries $ecnt\n" if $debug;

open ($fh, '>>', $logfile);

# Parse the arguements if any

ARG: while (my $arg = shift(@ARGV)) {
    if (!$done) {
      for ($arg) {
         s/^-debug$//      && do { $debug++; next ARG; };
         s/^-time$//       && do { $time = shift(@ARGV); next ARG; };
         s/^-dbase$//      && do { $database = shift(@ARGV); next ARG; };
         s/^-table$//      && do { $table = shift(@ARGV); next ARG; };
         s/^-t$//          && do { $time = shift(@ARGV); next ARG; };
         s/^-tm$//         && do { $time = shift(@ARGV); next ARG; };
         s/^-q$//          && do { $quiet = 1; next ARG; };
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

  $time =~ s/\//-/g;
  $stime = $time;

  print "DEBUG: RaLogsProcessParameters: time $time stime $stime\n" if $debug;

  my ($sec, $min, $hour, $mday, $mon, $year);
  ($year,$mon,$mday) = split /-/, $stime;

  print "DEBUG: RaLogsProcessParameters: date split to $year $mon $mday\n" if $debug;

  $sepoch=timelocal(0,0,0,$mday,$mon-1,$year-1900);
  $depoch=timelocal(0,0,0,$mday,$mon-1,$year-1900) + 24*60*60;

  my $nextday=timelocal(0,0,12,$mday,$mon-1,$year-1900) + 24*60*60;
  ($sec, $min, $hour, $mday, $mon, $year) = localtime($nextday);
  $dtime = sprintf '%04d-%02d-%02d', $year+1900, $mon+1, $mday;

  print $fh "RaLogsProcessParameters: remote $remote soname $soname port $port time $time \n";

  RaLogsFetchData($fname);
  RaLogsGenerateOutput($fname);
  RaLogsCleanUp($fname);


sub RaLogsFetchData {
   my $file = shift;
   my ($i, $k, $v, $data);
   my $input = 0;
   my $info;

   chomp($file);

   if (length($journalctl) > 0) {
      for ($i = 0; $i < 8; $i++) {
         my $cmd  = "$journalctl --since $stime --until $dtime -p $i | fgrep -iv \"no entries\" | fgrep -iv \"begin\" | wc ";
         my $retn = qx($cmd);
         $retn =~ s/^\s+//;
         my @nums = split (/ /, $retn);

         $entries[$i] = $nums[0];
         print "DEBUG: called $cmd result '$entries[$i]'\n" if $debug;
      }

      my %data_results;
      @data_results{@priority} = @entries;
      $data_results{'stime'} =  $sepoch;
      push(@$results_ref, \%data_results);
   }
}

sub RaLogsGenerateOutput {
   if (length($database) || length($table)) {
      if (length($database) && length($table)) {
         RaInitializeStatusDatabase();
         RaInsertStatusDatabase();
      } else {
         print "must provide both database and table names\n";
         exit 0;
      }
   } else {
      if ($json == 0) {
      } else {
         print JSON->new->utf8->space_after->encode({logs => $results_ref});
         print "\n";
      }
   }
}

sub RaInitializeStatusDatabase {
   my $dsn = "DBI:mysql:";
   my $user = "root";
   my $pass = '';
   my %attr = ( PrintError=>1, RaiseError=>1 );

   print "DEBUG: RaCreateStatusDatabase: DBI->connect($dsn,$user,$pass, \%attr)\n" if $debug;
   $dbh = DBI->connect($dsn,$username,$password, \%attr)|| die "Could not connect to database: $DBI::errstr";

   $dbh->{'mysql_enable_utf8'}=1; #enable

   print $fh "RaCreateStatusDatabase: db $database user $user\n";
   $dbh->do("CREATE DATABASE IF NOT EXISTS $database");
   $dbh->do("use $database");

   my $SQL = "CREATE TABLE IF NOT EXISTS `$table` (";
      $SQL .= "`stime` double(18,6) unsigned, ";
      $SQL .= "`emerg` bigint(1) unsigned, ";
      $SQL .= "`alert` bigint(1) unsigned, ";
      $SQL .= "`crit` bigint(1) unsigned, ";
      $SQL .= "`error` bigint(1) unsigned, ";
      $SQL .= "`warn` bigint(1) unsigned, ";
      $SQL .= "`notice` bigint(1) unsigned, ";
      $SQL .= "`info` bigint(1) unsigned, ";
      $SQL .= "`debug` bigint(1) unsigned, ";
      $SQL .= "PRIMARY KEY (`stime`) ";
      $SQL .= ") ENGINE=InnoDB DEFAULT CHARSET=utf8; ";

   print "DEBUG: RaInitializeStatusDatabase: SQL: $SQL\n" if $debug;
   $dbh->do($SQL);
}

sub RaInsertStatusDatabase {
   my $data_results;

   $data_results = pop($results_ref);

   if (defined $dbh) {
      my $SQL = "INSERT INTO `$table` (";
         $SQL .= "`stime`, ";
         $SQL .= "`emerg`, ";
         $SQL .= "`alert`, ";
         $SQL .= "`crit`, ";
         $SQL .= "`error`, ";
         $SQL .= "`warn`, ";
         $SQL .= "`notice`, ";
         $SQL .= "`info`, ";
         $SQL .= "`debug` ";
         $SQL .= ") VALUES (";
         $SQL .= "$data_results->{'stime'},";
         $SQL .= "$data_results->{'emerg'},";
         $SQL .= "$data_results->{'alert'},";
         $SQL .= "$data_results->{'crit'},";
         $SQL .= "$data_results->{'error'},";
         $SQL .= "$data_results->{'warn'},";
         $SQL .= "$data_results->{'notice'},";
         $SQL .= "$data_results->{'info'},";
         $SQL .= "$data_results->{'debug'} ) ";

         $SQL .= "ON DUPLICATE KEY UPDATE ";
         $SQL .= "emerg=$data_results->{'emerg'}, ";
         $SQL .= "alert=$data_results->{'alert'}, ";
         $SQL .= "crit=$data_results->{'crit'}, ";
         $SQL .= "error=$data_results->{'error'}, ";
         $SQL .= "error=$data_results->{'error'}, ";
         $SQL .= "warn=$data_results->{'warn'}, ";
         $SQL .= "notice=$data_results->{'notice'}, ";
         $SQL .= "info=$data_results->{'info'}, ";
         $SQL .= "debug=$data_results->{'debug'}; ";

      print "DEBUG: insert statement '$SQL'\n" if $debug;
      $dbh->do($SQL);
   }
}

sub RaLogsCleanUp {
   my $file = shift;
   print "DEBUG: deleting '$file'\n" if $debug;
   unlink $file;
   exit 0;
}

sub RaLogsError {
   my $msg = shift;
   my $file = shift;
   print $fh $msg;
   unlink $file;
   exit 1;
}

sub RaTodaysDate {
  my($day, $month, $year)=(localtime)[3,4,5];
  return sprintf( "%04d-%02d-%02d", $year+1900, $month+1, $day);
}
