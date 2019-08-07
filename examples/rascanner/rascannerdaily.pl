#!@PERLBIN@
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

$ENV{'PATH'} = '/bin:/usr/bin:/usr/local/bin';

# Used modules
use POSIX;
use DBI;
use JSON;
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

my @selectItems = ();

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

my $stype       = "";
my $datename    = "";
my @results     = ();
my $results_ref = \@results;
my @matchAddress;
my $elements    = "";

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

  open (my $fh, '>>', $logfile);

  my $dsn = "DBI:mysql:";
  my $username = "root";
  my $password = '';
  my %attr = ( PrintError=>0, RaiseError=>0 );
  my $dbh = DBI->connect($dsn,$username,$password, \%attr);

  RaScannerProcessParameters();
  RaScannerFetchData($fname);
  RaScannerGenerateOutput($fname);
  RaScannerCleanUp($fname);
  $dbh->disconnect();
  exit;

sub RaScannerProcessParameters {
  if (not defined ($time)) {
     $time = "-2d";
  }

  if (defined ($thresh)) {
    $arglist[@arglist + 0] = "-thresh ".$thresh;
  }

  if ($debug > 0) {
    $arglist[@arglist + 0] = "-debug";
  }

  if (defined $time) {
    ($val, $stime, $etime) = qosient::XS::util::ArgusParseTime($time);
  }

  if (not defined ($database)) {
     $database = "hostsInventory";
  }
  print "DEBUG: RaScannerProcessParameters: dbase:'$database' time:'$time' val:'$val' stime:'$stime' etime:'$etime'\n" if $debug;
}


sub RaScannerGetTables {
   my $dbase = shift;
   my $stime = shift;
   my $etime = shift;

   my $dates = 1;
   my $tableFormat;
   my @tables = ();
   my %hash = {};

   $dbh->do("use $dbase;");

   my $sth = $dbh->prepare("show tables;");
   $sth->execute();
   while(my @row = $sth->fetchrow_array()) {
      $hash{@row[0]}++;
   }
   $sth->finish();

   switch ($dbase) {
      case "inventory"         { $tableFormat = "ipAddrs"; }
      case "ether"             { $tableFormat = "ether"; }
      case "dnsAddrs"          { $tableFormat = "dns"; }
      case "dnsNames"          { $tableFormat = "dns"; }
      case "ipMatrix"          { $tableFormat = "ip"; }
      case "etherMatrix"       { $tableFormat = "ether"; }
      case "ntpMatrix"         { $tableFormat = "ntp"; }
      case "dnsMatrix"         { $tableFormat = "dns"; }
      case "ldapMatrix"        { $tableFormat = "ldap"; }
      case "imapsMatrix"       { $tableFormat = "imaps"; }
      case "hostsInventory"    { $tableFormat = "host"; }
      else                     { $dates = 0; }
   }

   if ($dates) {
      while ($stime < $etime) {
         my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($stime);
         my $tableName = sprintf("%s_%4d_%02d_%02d", $tableFormat, $year+1900, $mon + 1, $mday);
         my $date = sprintf("%4d/%02d/%02d", $year+1900, $mon + 1, $mday);

         if ($hash{$tableName} > 0) {
            my @trow = ($date, $tableName);
            push @tables, \@trow;
            print "DEBUG: RaScannerGetTables: pushd ('$date', '$tableName') to tables\n" if $debug;
         }
         $stime += 86400;
      }
   }
   my $count = scalar @tables;
   print "DEBUG: RaScannerGetTables: db:$dbase table:$tableFormat stime:$stime etime:$etime found ($count) tables\n" if $debug;
   return @tables;
}


sub RaScannerFetchData {
   my $file = shift;
   my @tables;

   @tables = RaScannerGetTables($database, $stime, $etime);

   foreach my $tr (@tables) {
      my $date = $tr->[0];
      my $table = $tr->[1];
      my $found = 0;
      my @row;
      my $cmd;

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
   }
}

sub RaScannerGenerateOutput {
   if (!$quiet) {
      if ($web) {
         print header(-type=>'application/json');
      }
      print encode_json $results_ref;
      print "\n";
   }
}

sub RaScannerCleanUp {
   my $file = shift;

   print "DEBUG: calling RaScannerCleanUp\n" if $debug;
   unlink $file;
}

sub RaScannerGetStartTime {
   my $etime = shift;
   my $stime = 0;
   my ($interval) = $time =~ /(\d+)/;

   my $scale = substr $time, -1;
   $interval =~ /(\d+)/;

   switch ($scale) {
      case "s" {
         my $inc = ($interval);
         $stime = $etime - $inc;
         print "DEBUG: RaScannerGetStartTime: scale $scale interval $interval stime $stime etime $etime\n" if $debug;
      }
      case "m" {
         my $inc = ($interval*60);
         $stime = $etime - $inc;
         print "DEBUG: RaScannerGetStartTime: scale $scale interval $interval stime $stime etime $etime\n" if $debug;
      }
      case "h" {
         my $inc = ($interval*60*60);
         $stime = $etime - $inc;
         print "DEBUG: RaScannerGetStartTime: scale $scale interval $interval stime $stime etime $etime\n" if $debug;
      }
      case "d" {
         my $inc = ($interval*60*60*24);
         $stime = $etime - $inc;
         print "DEBUG: RaScannerGetStartTime: scale $scale interval $interval stime $stime etime $etime\n" if $debug;
      }
   }
   return $stime;
}


sub RaGenerateDomainStrategy {
   my $list = shift;
   my $cnt = ($list =~ tr/,//);
   my $sterms;

   $database = "dnsAddrs";
   $dm = "dnsAddrs";
   $object = "Names";

   $dbh->do("use dnsAddrs;");

   my $SQL = "CREATE TABLE IF NOT EXISTS `dnsNamesTable` (";
   $SQL .= "`name` varchar(128),";
   $SQL .= "PRIMARY KEY (`name`))";

   $dbh->do($SQL) or die "Can't do '$SQL'";

   $SQL = "TRUNCATE dnsNamesTable;";
   $dbh->do($SQL) or die "Can't do '$SQL'";

   my @names = split(/,/, $list);

   foreach my $tobj (@names) {
      $tobj =~ s/\.$//;
      $tobj =~ s/$/\./;
      my $sql = "INSERT INTO dnsNamesTable(`name`) VALUES ('$tobj') ON DUPLICATE KEY UPDATE `name`='$tobj';";
      $dbh->do($sql) or die "Can't execute '$sql'";
   }
   
   return $sterms;
}


sub RaGenerateNameAddrStrategy {
   my $list = shift;
   my $cnt = ($list =~ tr/,//);
   my $table = "dns_$time";
   my ($alist, $clist, $slist);

   print "DEBUG: RaGenerateDomainStrategy: dlist '$list'\n" if $debug;

   $database = "dnsAddrs";
   $dm = "dnsAddrs";
   $object = "Names";

   $dbh->do("use dnsAddrs;");

   my $SQL = "CREATE TEMPORARY TABLE IF NOT EXISTS `dnsNameAddrTable` (";
   $SQL .= "`addr` varchar(128),";
   $SQL .= "PRIMARY KEY (`addr`))";

   if ($dbh->do($SQL)) {
     $SQL = "TRUNCATE dnsNameAddrTable;";
     $dbh->do($SQL) or die "Can't do '$SQL'";

     my @addrs = split(/,/, $list);

     foreach my $tobj (@addrs) {
        $tobj =~ s/ //g;
        my $sql = "INSERT INTO dnsNameAddrTable(`addr`) VALUES ('$tobj') ON DUPLICATE KEY UPDATE `addr`='$tobj';";
        $dbh->do($sql);
     }

     my $ssql = "SELECT t1.name,t1,addrs,t1.client,t1.server FROM $database.$table t1 INNER JOIN dnsNamesTable t2 ON ((t1.name = t2.name) or (t1.name LIKE CONCAT('%.', t2.name)))";
     print "DEBUG: RaGenerateDomainStrategy: domain match sql '$ssql'\n" if $debug;
     my $ssth = $dbh->prepare($ssql);

     $ssth->execute();

     while (my $hashref = $ssth->fetchrow_hashref()) {
       my $name = $hashref->{name};
       my $addr = decode_json $hashref->{"addrs"};
       my $client = decode_json $hashref->{"client"};
       my $server = decode_json $hashref->{"server"};

       if (defined $addr) {
         my %hash;
         $hash{'name'} = $hashref->{name};
         $hash{'addrs'} = $addr;

         push @matchAddress, \%hash;

         $alist = join(',', @$addr);
         $clist = join(',', @$client);
         $slist = join(',', @$server);
       }
       print "DEBUG: RaGenerateDomainStrategy: domain match name: '$hashref->{name}' addrs: '$alist' client: '$clist' server: '$slist'\n" if $debug;
     }
     $ssth->finish();
   }
   return $alist;
}

exit 0;
