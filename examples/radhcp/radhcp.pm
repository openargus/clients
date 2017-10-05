package qosient::radhcp;

#   Gargoyle Client Software.  Tools to read, analyze and manage Argus data.
#   Copyright (c) 2017 QoSient, LLC
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
#  This library contains routines for accessing the DHCP SQL tables.

use POSIX qw(strftime floor ceil);
use Time::Local;
use qosient::util;
use DBI qw(:sql_types);
use Carp;
use strict;
use warnings;
use Try::Tiny;

use strict;
use Exporter;
use vars qw($VERSION @ISA @EXPORT);
$VERSION = "1.00";
@ISA     = qw(Exporter);
@EXPORT  = qw(dhcp_gethostbyaddr
  dhcp_gethostbyaddr_from_table
  dhcp_gethostbyname
  dhcp_gethostbyname_from_table
  dhcp_getleasebyaddr_from_table
  dhcp_getleasebyaddr
  dhcp_getleasebyname_from_table
  dhcp_getleasebyname
  dhcp_opendb
  dhcp_closedb);

my $debug = 0;
my $time  = q{};    # "yesterday" according to parsetime()
my @time;
my $dbase         = q{dhcpFlows};
my $dbase_matrix  = q{dhcpMatrix};
my $table_summary = q{summary_%Y_%m_%d};
my $table_detail  = q{detail_%Y_%m_%d};
my $table_matrix  = q{matrix_%Y_%m_%d};
my $table_ethers  = q{ethers_%Y_%m_%d};
my $dsn;
my $dbuser   = 'root';
my $password = q{};
my %attr     = ( PrintError => 1, RaiseError => 0 );
my $errcount = 0;

# regular expressions to ensure user-provided address have only
# valid characters.  Since we are using these in SQL expressions
# where positional parameters cannot be explicitly bound (no question
# mark substitution) any values added to this hash that allow parens
# or semicolons must be checked very carefully.  So far, nothing
# of that sort here.
my %addr_valid_characters = (
    '4' => q{^[0-9.]+$},             # IPv4
    '6' => q{^[0-9a-fA-F:]+$},       # IPv6
    'h' => q{^[0-9a-fA-F:]+$},       # hardware address (oui48)
    'n' => q{^[0-9a-zA-Z_._\-]+},    # name
);

my %addr_search_field = (
    '4' => q{clientaddr},
    '6' => q{clientaddr},
    'h' => q{clientmac},
    'n' => q{requested_hostname},    # although q{hostname} should
                                     # also be checked.  Maybe
                                     # qw(hostname requested_hostname)
);

sub dhcp_opendb {
    @time = parsetime(q{});
    $dsn  = "DBI:mysql:$dbase";
    my $dbh = DBI->connect( $dsn, $dbuser, $password, \%attr );
    return $dbh;                     # undefined on error
}

sub dhcp_closedb {
    my ($dbh) = @_;

    $dbh->disconnect();
    return 0;
}

# Build an array of hash references from SQL query results.
# Return a reference to the array.
my $_result_list = sub {
    my $sth = shift(@_);
    my @arr;
    my $done = 0;
    while ( $done == 0 ) {
        my $href = $sth->fetchrow_hashref;
        if ( !defined $href ) {
            $done = 1;
            next;
        }
        push @arr, $href;
    }
    return \@arr;
};

# dhcp_gethostbyaddr_from_table
# args: <database-handle> <table> <addr> [<addr> [<addr> ...] ...]
# returns reference to array of hash references
sub dhcp_gethostbyaddr_from_table {
    my $dbh   = shift(@_);
    my $table = shift(@_);
    my $addrs = join( q{','}, @_ );

    if ( !( $table =~ /[0-9a-zA-Z_]+/ ) ) {
        my $sub_name = ( caller(0) )[3];
        carp "$sub_name: table name contains invalid characters";
        return;
    }

    for my $tmpaddr (@_) {
        if ( !( $tmpaddr =~ /$addr_valid_characters{'4'}/ ) ) {
            my $sub_name = ( caller(0) )[3];
            carp "$sub_name: address contains invalid characters";
            return;
        }
    }

    my $query =
        'SELECT clientaddr, requested_hostname, domainname '
      . "FROM $table WHERE clientaddr IN ('$addrs') "
      . 'AND requested_hostname <> "" '
      . 'GROUP BY clientaddr, requested_hostname, domainname';
    my $sth = $dbh->prepare($query);

    if ( !defined $sth ) {
        my $sub_name = ( caller(0) )[3];
        carp "$sub_name: unable to prepare SQL statement";
        return;
    }

    my $res = $sth->execute;

    if ( !defined $res ) {
        return;
    }

    my $aryref = $_result_list->($sth);

    $sth->finish;
    return $aryref;
}

# args: <database-handle> <when> <addr> [<addr> [<addr> ...] ...]
# returns reference to array of hash references
sub dhcp_gethostbyaddr {
    my $dbh        = shift(@_);
    my $when       = shift(@_);
    my $paramcount = @_;

    if ( $paramcount < 1 ) {

        # no addresses or insufficient args
        return;
    }

    my @whenary = parsetime($when);
    my $table = strftime $table_summary, @whenary;

    return dhcp_gethostbyaddr_from_table( $dbh, "$dbase.$table", @_ );
}

# args: <database-handle> <table> <name> [<name> [<name> ...] ...]
# returns reference to array of hash references
sub dhcp_gethostbyname_from_table {
    my $dbh   = shift(@_);
    my $table = shift(@_);
    my $names = join( q{','}, @_ );

    if ( !( $table =~ /[0-9a-zA-Z_]+/ ) ) {
        my $sub_name = ( caller(0) )[3];
        carp "$sub_name: table name contains invalid characters";
        return;
    }

    for my $tmpname (@_) {
        if ( !( $tmpname =~ /$addr_valid_characters{'n'}/ ) ) {
            my $sub_name = ( caller(0) )[3];
            carp "$sub_name: hostname contains invalid characters";
            return;
        }
    }

    my $query =
        'SELECT clientaddr, hostname, requested_hostname, domainname '
      . "FROM $table WHERE requested_hostname IN ('$names') "
      . "OR hostname IN ('$names') "
      . 'GROUP BY clientaddr, hostname, requested_hostname, domainname';
    my $sth = $dbh->prepare($query);

    if ( !defined $sth ) {
        my $sub_name = ( caller(0) )[3];
        carp "$sub_name: unable to prepare SQL statement";
        return;
    }

    my $res = $sth->execute;

    if ( !defined $res ) {
        return;
    }

    my $aryref = $_result_list->($sth);

    $sth->finish;
    return $aryref;
}

# args: <database-handle> <when> <name> [<name> [<name> ...] ...]
# returns reference to array of hash references
sub dhcp_gethostbyname {
    my $dbh        = shift(@_);
    my $when       = shift(@_);
    my $paramcount = @_;

    if ( $paramcount < 1 ) {

        # no addresses or insufficient args
        return;
    }

    my @whenary = parsetime($when);
    my $table = strftime $table_summary, @whenary;

    return dhcp_gethostbyname_from_table( $dbh, "$dbase.$table", @_ );
}

# args: <database-handle> <table> <addr-type> <addr> [<addr> ...]
# <addr-type> := "4"|"6"|"h"
#   ipv4, ipv6 or hardware (ethernet oui48 for most cases)
# returns reference to array of hash references.  Each hash contain
# the entire row from the specified table (detail or summary).
my $_dhcp_getlease_from_table = sub {
    my $dbh      = shift(@_);
    my $table    = shift(@_);
    my $addrtype = shift(@_);
    my $addrs    = join( q{','}, @_ );

    if ( !defined $addrtype ) {
        my $sub_name = ( caller(0) )[3];
        carp "$sub_name: need an address type";
        return;
    }

    if ( !( $addrtype =~ /[46hn]/ ) ) {
        my $sub_name = ( caller(0) )[3];
        carp qq{$sub_name: address type must be one of "4", "6" or "h".};
        return;
    }

    if ( !( $table =~ /[0-9a-zA-Z_]+/ ) ) {
        my $sub_name = ( caller(0) )[3];
        carp "$sub_name: table name contains invalid characters";
        return;
    }

    my $pattern = $addr_valid_characters{$addrtype};

    for my $tmpaddr (@_) {
        if ( !( $tmpaddr =~ /$pattern/ ) ) {
            my $sub_name = ( caller(0) )[3];
            carp "$sub_name: address contains invalid characters";
            return;
        }
    }

    my $addrfield = $addr_search_field{$addrtype};

    # SELECT * FROM $table WHERE $addrfield IN (...)
    # ORDER BY clientmac, clientaddr, stime ;
    my $query = qq{SELECT * FROM $table WHERE $addrfield IN ('$addrs') }
      . q{ORDER BY clientmac, clientaddr, stime};
    my $sth = $dbh->prepare($query);

    if ( !defined $sth ) {
        my $sub_name = ( caller(0) )[3];
        carp "$sub_name: unable to prepare SQL statement";
        return;
    }

    my $res = $sth->execute;

    if ( !defined $res ) {
        return;
    }

    my $aryref = $_result_list->($sth);

    $sth->finish;
    return $aryref;
};

sub dhcp_getleasebyaddr_from_table {
    return $_dhcp_getlease_from_table->(@_);
}

# args: <database-handle> <when> <addr-type> <addr> [<addr> [<addr> ...] ...]
# returns reference to array of hash references
sub dhcp_getleasebyaddr {
    my $dbh        = shift(@_);
    my $when       = shift(@_);
    my $addrtype   = shift(@_);
    my $paramcount = @_;

    if ( $paramcount < 1 ) {

        # no addresses or insufficient args
        return;
    }

    my @whenary = parsetime($when);
    my $table = strftime $table_summary, @whenary;

    return $_dhcp_getlease_from_table->( $dbh, "$dbase.$table", $addrtype, @_ );
}

# args: <database-handle> <table> <name> [<name> [<name> ...] ...]
# returns reference to array of hash references.  Each hash contain
# the entire row from the specified table (detail or summary).
sub dhcp_getleasebyname_from_table {
    my ( $dbh, $table ) = @_;
    shift(@_);
    shift(@_);
    return $_dhcp_getlease_from_table->( $dbh, $table, 'n', @_ );
}

# args: <database-handle> <when> <name> [<name> [<name> ...] ...]
# returns reference to array of hash references
sub dhcp_getleasebyname {
    my $dbh        = shift(@_);
    my $when       = shift(@_);
    my $paramcount = @_;

    if ( $paramcount < 1 ) {

        # no addresses or insufficient args
        return;
    }

    my @whenary = parsetime($when);
    my $table = strftime $table_summary, @whenary;

    return $_dhcp_getlease_from_table->( $dbh, "$dbase.$table", 'n', @_ );
}

sub dhcp_lease_expand_one {
    my ( $dbh, $href ) = @_;

    if ( !defined $href ) {
        return;
    }

    # take a lease summarization as generated by dhcp_getleasebyaddr*
    # or dhcp_getleasebyname* and use the detail SQL tables to find
    # the leases that contributed to the summary.

    # summary lease start and last times
    my $date_range_stime = POSIX::floor( $href->{'stime'} );
    my $date_range_ltime = POSIX::ceil( $href->{'ltime'} );
    my $duration         = $date_range_ltime - $date_range_stime;
    my $seconds          = $date_range_stime;
    my $seconds_in_day   = 86400;
    my $results_aref;

    # Step through the range of lease times one 24-hour period at a
    # time and format the year-month-day table name for each.
    # Search those tables for matching clients and times.
    while ( $duration > 0 ) {
        my $table = strftime $table_detail, localtime($seconds);
        my $query = qq{SELECT * FROM $table WHERE }
          . q{(clientmac=? AND clientaddr=? AND stime=? AND ltime=?)};
        my $sth = $dbh->prepare($query);

        if ( !defined $sth ) {
            print STDERR "Unable to prepare $query";
            return;
        }

        $sth->bind_param( 1, $href->{'clientmac'} );
        $sth->bind_param( 2, $href->{'clientaddr'} );
        $sth->bind_param( 3, $href->{'stime'}, { TYPE => SQL_DOUBLE } );
        $sth->bind_param( 4, $href->{'ltime'}, { TYPE => SQL_DOUBLE } );

        my $res = $sth->execute;

        if ( !defined $res ) {
            $sth->finish;
            return;
        }

        my $tmp = $_result_list->($sth);

        # keep appending to the array reference returned from the
        # first call to execute()
        if ( defined $results_aref ) {
            push $results_aref, @$tmp;
        }
        else {
            $results_aref = $tmp;
        }

        $duration -= $seconds_in_day;
        $seconds += $seconds_in_day;
        $sth->finish;
    }

    return $results_aref;
}

# Return an array (reference) of array references.  Each array
# reference points to an array of hash references.  Each hash
# reference points to a lease record.
#
# for example, two leases might expand to a structure like this:
# \[ \[ \% \% ] \[ \% ] ]
#
# where the outer array contains two inner arrays and where each
# inner array contains references to hashes with the detailed lease
# data.  If there are no search results, return a reference to an
# empty list.

sub dhcp_lease_expand {
    my ( $dbh, $aref ) = @_;
    my @reslist = ();

    for my $href (@$aref) {
        my $aref = dhcp_lease_expand_one( $dbh, $href );

        if ( !defined $aref ) {
            next;
        }

        push @reslist, $aref;
    }
    return \@reslist;
}

1;
