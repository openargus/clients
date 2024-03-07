#! /usr/bin/perl 
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
#  racluster() based address inventory
#  
#  written by Carter Bullard
#  QoSient, LLC
#

#
# Complain about undeclared variables

use strict;

# Used modules
use POSIX;
use File::Temp qw/ tempfile tempdir /;
use File::Which qw/ which /;

# Global variables

my $inputFile;

my $f;
my $fname;

($f,  $fname)   = tempfile();

my $VERSION   = "5.0.3";                
my @arglist   = ();
my $debug     = 0;
my $done      = 0;
my $dbase     = "inventory";

ARG: while (my $arg = shift(@ARGV)) {
  if (!$done) {
    for ($arg) {
       s/^-dbase$//  && do { $dbase = shift(@ARGV); next ARG; };
       s/^-r$//      && do { $inputFile = shift(@ARGV); next ARG; };
       s/^-debug$//  && do { $debug++; next ARG; };
       s/^-help$//   && do { RaPrintHelpScreen(); };
    }
  } else {
    for ($arg) {
      s/\(/\\\(/        && do { ; };
      s/\)/\\\)/        && do { ; };
    }
  }
  $arglist[@arglist + 0] = $arg;
}

if (defined $inputFile) {
   RaGenerateClusteredFile($inputFile, $fname);
   RaInsertClusteredFile($fname);
   RaCleanUp($fname);
} else {
   print "DEBUG: no input file ... use -r option\n" if $debug;
}

sub RaPrintHelpScreen {
   print "help: \n";
   exit 0;
}

sub RaGenerateClusteredFile {
   my $input = shift;
   my $output = shift;

   my $racluster  = which 'racluster';
   my $options    = "-M rmon -m sid inf smac saddr";
   my $filter     = '- ip';

   chomp($input);
   chomp($output);

   my $ra = "$racluster -R $input $options @arglist -w $output $filter";
   print "DEBUG: RaGenerateClusteredFile: calling $ra\n" if $debug;
   system($ra);
   chmod 0644, $output;
}

sub RaInsertClusteredFile {
   my $input = shift;
   chomp($input);

   if (-e $input) {
      my $rasqlinsert  = which 'rasqlinsert';
      my $options      = "-M rmon time 1d -m saddr smac sid inf -s stime ltime dur sid inf smac saddr sco spkts dpkts sbytes dbytes pcr -w 'mysql://root\@localhost/$dbase/ipAddrs_%Y_%m_%d'";        # Default Options

      my $ra = "$rasqlinsert -r $input $options";
      print "DEBUG: RaInsertClusteredFile: calling $ra\n" if $debug;
      system($ra);
   } else {
      print "DEBUG: RaInsertClusteredFile: no input: $input\n" if $debug;
   }
}

sub RaCleanUp {
   my $file = shift;
   print "DEBUG: deleting '$file'\n" if $debug;
   `rm -r $file`;
   exit 0;
}

exit 0;
