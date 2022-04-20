#! /usr/bin/perl 
#  Argus Software
#  Copyright (c) 2000-2022 QoSient, LLC
#  All rights reserved.
#
#  Modified from rahosts command
# 
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2, or (at your option)
#  any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
# 
#  
#   ra() based host use report
#  
#
# Complain about undeclared variables
use strict;

# Used modules
use POSIX;
use Socket;

# Global variables
my $tmpfile = tmpnam();
my $tmpconf = $tmpfile . ".conf";

my $Program = `which ra`;
my $Options = "-L -1 -nn -s saddr:32 daddr:32 proto -c , ";
my $VERSION = "3.0.1";                
my @arglist = ();

chomp $Program;

my @args = ($Program, $Options, ' "'.join('" "',@ARGV).'"');
our ($mode, %addrs, $saddr, $daddr, $addr, $proto);


# Start the program

open(SESAME, "@args |");
while (my $data = <SESAME>) {
   chomp $data;
   ($saddr, $daddr, $proto) = split (/,/, $data);

   if (!(($proto == 0) || ($proto > 255))) {
#      if ((!($saddr eq "0.0.0.0")) && (!($daddr eq "0.0.0.0"))) {
#         ($x, $y, $z, $w) = split(/\./, $daddr);
         $addrs{$saddr} = 1;
         $addrs{$daddr} = 1;
#         $items{$saddr}{$x}{$y}{$z}{$w}++; 
#      //}
   }
}

close(SESAME);

for $addr ( sort keys (%addrs) ) 
{
	print $addr,"\n";   
}   
