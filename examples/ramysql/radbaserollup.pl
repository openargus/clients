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
#   radbaserollup.pl - rollup Argus Databases.
#        This routine will establish the rollup databases for a system.
#        Need to be passed a range of days, and the routine will drop the
#        rollup databases, if they exist, then for each database, it will
#        create the rollup datatbases, (yearly, monthly) and then merge
#        the daily tables into them.
#        
#        These will then be used by daseRollup-nightly to merge a new
#        day's data into the rollup tables.
#
#
# Complain about undeclared variables
use v5.6.0;
use strict;
use warnings;
use Carp;

use POSIX;
use DBI;
use qosient::XS::util;
use Time::Local;

use Switch;
use File::Temp qw/ :POSIX /;
use File::Which qw/ which where /;
use CGI qw(:standard);

my $query = new CGI;

# Global variables
my $VERSION = "5.0.3";
my @arglist = ();

my $remote      = $query->remote_host();
my $soname      = $query->server_name();
my $port        = $query->server_port();

my ($val, $stime, $etime);

my @names       = $query->param;
my $time        = $query->param('tm');
my $object      = $query->param('ob');
my $database    = $query->param('db');
my $mode        = $query->param('mo');

my $debug       = 0;
my $quiet       = 0;
my $force       = 0;
my $done        = 0;

$ENV{PATH} = "$ENV{PATH}:/bin:/usr/bin:/usr/sbin:/usr/local/bin";

my ($dtime, $mtime, $ytime);
my $tmpfile = tmpnam();

my %annualTables  = ();
my %monthlyTables = ();

# Parse the arguments if any

ARG: while (my $arg = shift(@ARGV)) {
    if (!$done) {
      for ($arg) {
         s/^-debug$//    && do { $debug++; next ARG; };
         s/^-db$//       && do { $database = shift(@ARGV); next ARG; };
         s/^-dbase$//    && do { $database = shift(@ARGV); next ARG; };
         s/^-force$//    && do { $force++; next ARG; };
         s/^-mode$//     && do { $mode = shift(@ARGV); next ARG; };
         s/^-object$//   && do { $object = shift(@ARGV); next ARG; };
         s/^-obj$//      && do { $object = shift(@ARGV); next ARG; };
         s/^-ob$//       && do { $object = shift(@ARGV); next ARG; };
         s/^-quiet$//    && do { $quiet = 1; next ARG; };
         s/^-t$//        && do { $time = shift(@ARGV); next ARG; };
         s/^-time$//     && do { $time = shift(@ARGV); next ARG; };
      }
    } else {
      for ($arg) {
         s/\(/\\\(/        && do { ; };
         s/\)/\\\)/        && do { ; };
      }
    }
    $arglist[@arglist + 0] = $arg;
  }

  if (not defined $time) {
     $time = "-182d";
  }

  ($val, $stime, $etime) = qosient::XS::util::ArgusParseTime($time);
  my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($stime);
  my $sdate = sprintf("%4d/%02d/%02d", $year+1900, $mon+1, $mday);

  ($sec, $min, $hour, $mday, $mon, $year) = localtime();
  my  $yesterday = timelocal(0,0,12,$mday,$mon,$year) - 24*60*60;

  if ($etime > $yesterday) {
     $etime = $yesterday;
  }
  ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($etime);
  my $edate = sprintf("%4d/%02d/%02d", $year+1900, $mon+1, $mday);

  print "DEBUG: using stime:$stime sdate:$sdate etime:$etime edate:$edate\n" if $debug;

  my $dsn = "DBI:mysql:";
  my $username = "root";
  my $password = '';
  my %attr = ( PrintError=>0, RaiseError=>0 );
  my $dbh = DBI->connect($dsn,$username,$password, \%attr);

my $fname        = tmpnam();
my $rasql        = which 'rasql';
my $racluster    = which 'racluster';
my $rasqlinsert  = which 'rasqlinsert';

my @db1 = ( "inventory", "ipAddrs", "smac saddr sid inf", "stime dur sid inf smac saddr sco spkts dpkts sbytes dbytes pcr state trans");
my @db2 = ( "ipMatrix", "ip", "daddr saddr sid inf", "stime ltime sid inf saddr daddr spkts dpkts sbytes dbytes pcr trans");
my @db3 = ( "dnsMatrix", "dns", "daddr saddr sid inf", "stime ltime sid inf saddr daddr spkts dpkts sbytes dbytes pcr trans");
my @db4 = ( "etherMatrix", "ether", "dmac smac sid inf", "stime ltime sid inf smac dmac spkts dpkts sbytes dbytes pcr trans");
my @db5 = ( "ntpMatrix", "ntp", "daddr saddr sid inf", "stime ltime sid inf saddr daddr spkts dpkts sbytes dbytes pcr trans");
my @db6 = ( "ldapMatrix", "ldap", "daddr saddr sid inf", "stime ltime sid inf saddr daddr spkts dpkts sbytes dbytes pcr trans");
my @db7 = ( "arpMatrix", "arg", "daddr saddr sid inf", "stime ltime sid inf saddr daddr spkts dpkts sbytes dbytes pcr trans");
my @db8 = ( "ether", "ether", "smac etype sid inf", "stime ltime sid inf smac etype spkts dpkts sbytes dbytes pcr trans state");

my @databases = \(@db1, @db2);
#my @databases = \(@db1, @db2, @db3, @db4, @db5, @db6, @db7, @db8);

# Now generate yearly and monthly tables

foreach my $i (0 .. $#databases) {
   my %hash = ();

   my ($db, $table, $keys, $fields) = @{$databases[$i]};
   my @tables = RaDbaseRollupGetTables($db, $stime, $etime);

   foreach my $tbl (keys %annualTables) {
      drop_table( $dbh, $tbl );
   }

   foreach my $tbl (keys %monthlyTables) {
      drop_table( $dbh, $tbl );
   }

   foreach my $i (0 .. $#tables) {
     my ($dbase, $table, $monthly, $annual, $date) = @{$tables[$i]};
     my ($db, $tbl, $keys, $fields);
     my $found = 0;

     foreach my $i (0 .. $#databases) {
        ($db, $tbl, $keys, $fields) = @{$databases[$i]};
        if ($db eq $dbase) {
           $found = 1;
           last;
        }
     }

     if ($found > 0) {
        print "DEBUG: process db:$dbase table:$table annual:$annual monthly:$monthly date:$date\n" if $debug;

        my $cmd = "$rasql -r mysql://root\@localhost/".$dbase."/".$table." -w ".$tmpfile;
        print "DEBUG: $cmd \n" if $debug;
        `$cmd`;

        if (-e $tmpfile) {
           my $minsert = "$rasqlinsert -M cache time 1M -r ".$tmpfile." -m $keys -w mysql://root\@localhost/".$db."/".$monthly." -s ".$fields;
           my $yinsert = "$rasqlinsert -M cache time 1y -r ".$tmpfile." -m $keys -w mysql://root\@localhost/".$db."/".$annual." -s ".$fields;

           print "DEBUG: $minsert \n" if $debug;
           `$minsert`;

           print "DEBUG: $yinsert \n" if $debug;
           `$yinsert`;

           print "DEBUG: rm -f $tmpfile\n" if $debug;
           `rm -f $tmpfile`;
        }
     }
   }
}
exit;


# opendb("databasename")
sub opendb {
    my ($dbase)  = @_;
    my %attr     = ( PrintError => $debug, RaiseError => 0 );
    my $dbuser   = 'root';
    my $password = q{};
    my $dsn      = "DBI:mysql:$dbase";
    my $dbh      = DBI->connect( $dsn, $dbuser, $password, \%attr );
    return $dbh;                     # undefined on error
}

sub closedb {
    my ($dbh) = @_;

    $dbh->disconnect();
    return 0;
}

# return the number of rows in table.  return 0 if table is empty
# or an error ocurred.
sub row_count {
    my ($dbh, $table) = @_;
    my $query = "SELECT COUNT(*) from $table";
    my $sth = $dbh->prepare($query);
    if ( !defined $sth ) {
        my $sub_name = ( caller(0) )[3];
        carp "$sub_name: unable to prepare SQL statement";
        return 0;
    }

    my $res = $sth->execute;
    if ( !defined $res ) {
        $sth->finish;
        return 0;
    }

    my $aryref = $sth->fetchrow_arrayref;
    $sth->finish;
    if ( $debug > 0 ) {
        print "DEBUG: table $table has @${aryref[0]} rows\n";
    }
    return @$aryref[0];
}

# return 0 on success, undefined otherwise
sub drop_table {
    my ($dbh, $table) = @_;
    my $query = "DROP TABLE $table";
    my $sth = $dbh->prepare($query);

    if ( !defined $sth ) {
        my $sub_name = ( caller(0) )[3];
        carp "$sub_name: unable to prepare SQL statement";
        return;
    }

    my $res = $sth->execute;
    if ( !defined $res ) {
       $sth->finish;
       return;
    }

    $sth->finish;
    return 0;
}

# return 0 on success, undefined otherwise
sub rename_table {
    my ($dbh, $oldname, $newname) = @_;
    my $query = "RENAME TABLE $oldname TO $newname";
    my $sth = $dbh->prepare($query);

    if ( !defined $sth ) {
        my $sub_name = ( caller(0) )[3];
        carp "$sub_name: unable to prepare SQL statement";
        return;
    }

    my $res = $sth->execute;
    if ( !defined $res ) {
        $sth->finish;
        return;
    }

    $sth->finish;
    return 0;
}

# $dbaref is an array reference containing
#   (database, base table name, primary key columns, all columns)
# $dtime is a string representation of the table name's date component
#   e.g., 2018_02_12 if operating on the table for Feb 12, 2018.
sub score_one_table {
    my ($dbaref, $dtime) = @_;

    my ($db, $table_bn, $keys, $fields) = @$dbaref;
    my $dburi = "mysql://root\@localhost/$db";
    my $table = "${table_bn}_${dtime}";
    my $scorecmd = "rasql -r ${dburi}/${table} -w - | "
                 . "rascore -f /usr/share/argus-clients/emerging-threats-current.conf"
                 . "        -r - -r $dburi -m saddr -w - | "
                 . "rasqlinsert -M time 1d -m $keys -s $fields -w ${dburi}/${table}_rascore";
    print "DEBUG: ${scorecmd}\n" if $debug;
    if ( system($scorecmd) != 0 ) {
        warn "Unable to add score to table ${table}\n";
        return;
    }

    my $dbh = opendb($db);
    if ( ! $dbh ) {
        warn "Unable to open database $db\n";
        return;
    }

    if ( row_count( $dbh, "${table}_rascore" ) > 0 ) {
        drop_table( $dbh, $table );
        if ( !defined rename_table( $dbh, "${table}_rascore", $table ) ) {
            closedb($dbh);
            return;
        }
    } else {
        warn "rascore generated no output\n";
    }

    closedb($dbh);
    return 1;
}

sub RaTodaysDate {
  my($day, $month, $year)=(localtime)[3,4,5];
  return sprintf( "%04d/%02d/%02d", $year+1900, $month+1, $day);
}

sub RaDbaseRollupGetTables {
   my $dbase = shift;
   my $stime = shift;
   my $etime = shift;

   my $dates = 1;
   my $tableFormat;
   my @tables = ();
   my %hash = ();

   %annualTables  = ();
   %monthlyTables = ();

   $dbh->do("use $dbase;");

   my $sth = $dbh->prepare("show tables;");
   $sth->execute();

   while(my @row = $sth->fetchrow_array()) {
      $hash{$row[0]}++;
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
      case "arpMatrix"         { $tableFormat = "arp"; }
      case "dnsMatrix"         { $tableFormat = "dns"; }
      case "ldapMatrix"        { $tableFormat = "ldap"; }
      case "imapsMatrix"       { $tableFormat = "imaps"; }
      case "hostsInventory"    { $tableFormat = "host"; }
      case "scanners"          { $tableFormat =  $mode; }
      else                     { $dates = 0; }
   }

   print "DEBUG: RaDbaseRollupGetTables: db $dbase table $tableFormat stime $stime etime $etime\n" if $debug;

   if ($dates) {
      while ($stime <= $etime) {
         my @tnames = split(',', $tableFormat);
         my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($stime);
         my $date = sprintf("%4d-%02d-%02d", $year+1900, $mon + 1, $mday);

         foreach my $tab (@tnames) {
            my $tableName = sprintf("%s_%4d_%02d_%02d", $tab, $year+1900, $mon + 1, $mday);
            my $monthlyTable = sprintf("%s_%4d_%02d", $tab, $year+1900, $mon + 1);
            my $annualTable = sprintf("%s_%4d", $tab, $year+1900);

            $monthlyTables{$monthlyTable}++;
            $annualTables{$annualTable}++;

            if ($hash{$tableName}) {
               my @trow = ($dbase, $tableName, $monthlyTable, $annualTable, $date);
               push @tables, \@trow;
            }
         }
         $stime += 86400;
      }
   }

   my $tlen = scalar @tables;
   print "DEBUG: RaDbaseRollupGetTables: found $tlen tables\n" if $debug;
   return @tables;
}
