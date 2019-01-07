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
#   scanner - 
#
#
# % scanner.pl -time -1d -thresh 64
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
use Time::Local;
use qosient::util;  # parsetime

# Global variables
my @arglist = ();

my $tdate        = `date`;
chomp $tdate;

my $time;
my $thresh;
my $database;
my $filter;
my $cidr         = "24";
my $debug        = 0;
my $done         = 0;
my $mode         = "local";

my $f;
my $fname;

($f,  $fname)    = tempfile();

# Parse the arguements if any

ARG: while (my $arg = shift(@ARGV)) {
    if (!$done) {
      for ($arg) {
         s/^-debug$//      && do { $debug++; next ARG; };
         s/^-t$//          && do { $time = shift(@ARGV); next ARG; };
         s/^-time$//       && do { $time = shift(@ARGV); next ARG; };
         s/^-dbase$//      && do { $database = shift(@ARGV); next ARG; };
         s/^-thresh$//     && do { $thresh = shift(@ARGV); next ARG; };
         s/^-cidr$//       && do { $cidr = shift(@ARGV); next ARG; };

         s/^-local$//      && do { $mode = "local"; $filter = "src loc gte 3 and dst loc gte 3"; next ARG; };
         s/^-remote$//     && do { $mode = "remote"; $filter = "src loc lt 3 and dst loc lt 3"; next ARG; };
         s/^-outsidein$//  && do { $mode = "outside"; $filter = "src loc lt 3 and dst loc gte 3"; next ARG; };
         s/^-insideout$//  && do { $mode = "inside"; $filter = "src loc gte 3 and dst loc lt 3"; next ARG; };

      }
    } else {
      for ($arg) {
         s/\(/\\\(/        && do { ; };
         s/\)/\\\)/        && do { ; };
      }
    }
    $arglist[@arglist + 0] = $arg;
}

my $dburl  = "mysql://root\@localhost/scanners/".$mode."_%Y_%m_%d -M time 1d";

  print "DEBUG: dburl is: '$dburl' arglist is: '@arglist'\n" if $debug;

  if (not defined $time) {
     $time = RaTodaysDate();
  }

my       @time = parsetime($time);
my       $date = strftime '%Y/%m/%d', @time;
my  $tabletime = strftime '%Y_%m_%d', @time;

  chomp($date);

  my $hosttable = "";

  if (not defined $filter) {
     $mode = "outside";
     $filter = "src loc lt 3 and dst loc gte 3";
  }
  if (not defined $thresh) {
     $thresh = 128;
  }
  $filter = $filter." and trans gte ".$thresh;
  if ($hosttable eq "") {
     $hosttable = "host_$tabletime";
  }


  my $cmd = "";

  RaStatusProcessParameters();
  RaStatusFetchData($fname);
  RaStatusCleanUp($fname);

sub RaStatusProcessParameters {
   if (! $database) {
      $database = "hostsInventory";
   }
   $cmd = "mysql -u root $database -NBe \"select saddr,count from $hosttable where count > $thresh order by count desc;\"";
   return;
}

sub RaStatusFetchData {
   my $file = shift;
   my ($i, $k, $v, $data);
   chomp($file);
   my $ips = $file.".ips";
   my $qcmd = "";

   $cmd  = "$cmd > $ips";

   print "DEBUG: RaStatusFetchData: cmd: $cmd\n" if $debug;
   system($cmd);

   chmod 0644, $ips;

   $qcmd = "rasql -r mysql://root\@localhost/ipMatrix/ip_$tabletime -w - @arglist | rafilteraddr -f $ips -m saddr -w - | racluster -m saddr daddr -w - | ralabel -f /usr/argus/ralabel.local.conf -w - | racluster -m saddr daddr/$cidr -M dsrs='-agr' -w - | rasort -w $file -m saddr trans daddr - $filter; rasqlinsert -r $file  -w $dburl -t $time -m saddr daddr/$cidr -M drop -s stime dur saddr daddr spkts dpkts trans -p3";

   print "DEBUG: RaStatusFetchData: query: $qcmd\n" if $debug;
   system($qcmd);
   return;
}

sub RaStatusCleanUp {
   my $file = shift;
   my $ips = $file.".ips";
   print "DEBUG: deleting '$file $ips'\n" if $debug;
   unlink($file);
   unlink($ips);
   exit 0;
}

sub RaStatusError {
   my $msg = shift;
   my $file = shift;
   my $ips = $file.".ips";
   unlink($file);
   unlink($ips);
   exit 1;
}

sub RaTodaysDate {
  my($day, $month, $year)=(localtime)[3,4,5];
  return sprintf( "%04d/%02d/%02d", $year+1900, $month+1, $day);
}
