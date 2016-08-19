#!@PERLBIN@
# Argus Software
# Copyright (c) 2000-2016 QoSient, LLC
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
#
# radecode use tshark tools to decode user data 
#    
#  $Id: //depot/argus/clients/examples/radecode/radecode.pl#6 $
#  $DateTime: 2016/06/01 15:17:28 $
#  $Change: 3148 $
#
# written by Carter Bullard and Dave Edelman
# QoSient, LLC
#

use strict;

use POSIX;

#
#
# Since ~.rarc may modify the default settings, I use -X to reset everything to a known value before I use -n which cycles
# through the options based on the number of 'n's that it has seen and can lead to very strange results in some instances
# The other ra parameters that I use:
# -n do not translate port numbers to service names
# -u use UNIX time (seconds since the epoc)
# -p 6 use 6 digits of precision after the decimal point in the timestamp and anywhere else that it applies
# -M printer='hex' output the user data in the format that I need for this program
# -L -1 do not output any column headers
# -s proto sport dport stime saddr daddr smac dmac sttl stcpb suser:2000 output the following fields:
#    protocol as a protocol name (tcp, udp, icmp ...)
#    source port number
#    destination port number
#    start time for the flow record as a UNIX time and date stamp with six digits after the decimal point
#    source address
#    destination address
#    source MAC address
#    destination MAC address
#    source time to live
#    source base sequence number (only for TCP flows)
#    Source user data (a maximum of 2000 bytes which may inlcude full or partial data from one or more of the packets that make
#           up the flow all depending on the configuration of the capturing Argus (Argii) text2pcap and tshark deal with the
#           variations of user data with a pretty impressive amount of grace, the people attempting to read the output, not so much.
#
#
my $raoptions = " -X -n -u -p 3  -M printer='hex' -L -1 -s proto sport dport stime saddr daddr smac dmac sttl stcpb suser:2000";

my $lines = 0;
my $content = '';
my $cmd;

my $tmpFile = tmpnam();
my $ra = `which ra`;
my $tshark = `which tshark`;
my $text2pcap = `which text2pcap`;

# If requested to do so, text2pcap will generate mock headers for specified protocol stack layers that are not present in the hex dump
# there are no provisions for specifying much more than source and destination port which are then inserted into the created pcap
# Rather than modify the text2pcap source (easy enough to do but change coordination may be a problem) I modify the easy to identify
# fields in the decoded tshark output replacing the placeholder values with the actual values.
#
# as of this version, the replaced values are:
#       saddr
#       daddr
#       smac
#       dmac
#       sttl
#       stcbp
#
# Since text2pcap is able to deal with timestamp information, I use stime in the appropriate format
#
my $stime;
my $saddr;
my $daddr;
my $smac;
my $dmac;
my $sttl;
my $stcpb;
my $output;
my $ttlStr = "Time to live: ";

my $VERSION = "3.0.7.8";

chomp $ra;
chomp $tshark;
chomp $text2pcap;

my @args = ($ra, $raoptions, ' "'.join('" "',@ARGV).'"');
open(SESAME, "@args |");
while (<SESAME>) {
        chomp;
        if (/^\s*tcp\s+(\d+)\s+(\d+)\s+(\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.d+)\s+([0-9a-f\:]{17})\s+([0-9a-f\:]{17})\s+(\d+)\s+(\d+)/) {
                $cmd = "$text2pcap -T $1,$2 - $tmpFile \n ";
                $stime = $3;
                $saddr = $4;
                $daddr = $5;
                $smac = $6;
                $dmac = $7;
                $sttl = $8;
                $stcpb = $9;
                if ($lines > 0) {
                        $content .= "\n";
                        $lines = 0;
                }
                next;
        }
        if (/^\s*udp\s+(\d+)\s+(\d+)\s+(\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f\:]{17})\s+([0-9a-f\:]{17})\s+(\d+)/) {
#       if (/^\s*udp\s+(\d+)\s+(\d+)/) {
                $cmd = "$text2pcap -u $1,$2 - $tmpFile \n ";
                $stime = $3;
                $saddr = $4;
                $daddr = $5;
                $smac = $6;
                $dmac = $7;
                $sttl = $8;
                if ($lines > 0) {
                        $content .= "\n";
                        $lines = 0;
                }
                next;
        }
        if (/^\s*0x([0-9a-f]{4,})\s+(..)(..)\s+(..)(..)\s+(..)(..)\s+(..)(..)\s+(..)(..)\s+(..)(..)\s+(..)(..)\s+(..)(..)\s+/) {
                if ($lines == 0) {$content .= "$1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 $17 ";
                $lines++;
                }
                else {
                $content .= " $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 $17 ";
                }
        }
}
$content .= "\n\n";
if ($lines > 0) {
        $ttlStr .= $sttl;
        system "echo \"$content\" \| $cmd";
        $cmd = "$tshark -V -r $tmpFile";
        $output = qx/$cmd/;
        unlink $tmpFile;
        $output =~ s/10.1.1.1/$saddr/g;
        $output =~ s/10.2.2.2/$daddr/g;
        $output =~ s/0a\:01\:01\:01\:01\:01/$smac/g;
        $output =~ s/0a\:02\:02\:02\:02\:02/$dmac/g;
        $output =~ s/Time to live\: 255/$ttlStr/g;
        print "$output";
}



