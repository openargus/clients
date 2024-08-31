package qosient::radhcp;

#   Gargoyle Client Software.  Tools to read, analyze and manage Argus data.
#   Copyright (c) 2017-2018 QoSient, LLC
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
use IO::Socket::INET;
use JSON;

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
  dhcp_insert_fqdn
  dhcp_opendb
  dhcp_closedb
  dhcp_opensocket
  dhcp_closesocket);

my $debug = 0;
my $time  = q{};    # "yesterday" according to parsetime()
my @time;
my $dbase         = q{dhcpFlows};
my $dbase_matrix  = q{dhcpMatrix};
my $table_summary = q{dhcp_summary_%Y_%m_%d};
my $table_detail  = q{dhcp_detail_%Y_%m_%d};
my $table_matrix  = q{matrix_%Y_%m_%d};
my $table_ethers  = q{dhcp_ethers_%Y_%m_%d};
my $dsn;
my $dbuser   = 'root';
my $password = q{};
my %attr     = ( PrintError => $debug, RaiseError => 0 );
my $errcount = 0;

# regular expressions to ensure user-provided address have only
# valid characters.  Since we are using these in SQL expressions
# where positional parameters cannot be explicitly bound (no question
# mark substitution) any values added to this hash that allow parens
# or semicolons must be checked very carefully.  So far, nothing
# of that sort here.
my %addr_valid_characters = (
    '4' => q{^[0-9./]+$},            # IPv4
    '6' => q{^[0-9a-fA-F:/]+$},      # IPv6
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

my %addr_socket_search_field = (
    '4' => q{addr},
    '6' => undef,
    'h' => q{chaddr},
    'n' => undef,
);

my $canonicalize_oui48 = sub {
    my ($str) = @_;
    my @bytes = split(/:/, $str);

    if (scalar(@bytes) != 6) {
        return;
    }

    my @num = map { hex($_) } @bytes;
    return sprintf('%02x:%02x:%02x:%02x:%02x:%02x', @num);
};

my %addr_canon_func = (
    'h' => $canonicalize_oui48,
);

sub dhcp_opensocket {
    my $socket = IO::Socket::INET->new(
        PeerHost => 'localhost',
        PeerPort => '9999',
        Proto    => 'tcp',
        Timeout  => 1,
    );

    if ( !$socket ) {
        return;
    }

    $socket->timeout(5);

    my $start = "START: \n";
    my $bytes = $socket->send($start);

    if ( $bytes != length($start) ) {
        carp "could not send start command";
        $socket->close();
        return;
    }

    return $socket;
}

sub dhcp_closesocket {
    my ($socket) = @_;

    my $done  = "DONE: \n";
    my $bytes = $socket->send($done);

    if ( $bytes != length($done) ) {
        carp "could not send done command";
    }

    $socket->close();
}

# The control channel code in the clients is a little broken when
# the callback that generates the response needs to report an error.
# The data from the control channel may end with "FAIL\nOK\n".
# _response_complete can always check for a string ending in "OK\n"
# to figure out if the response is finished, but will also have to
# check for a preceding "FAIL\n" to know if the response is valid.
my $_response_complete = sub {
    my ($str) = @_;
    my $last3 = substr $str, -3;    # OK

    if ( not ( $last3 eq "OK\n" ) ) {
        return;
    }

    return 1;
};

# $str must be a completed response (ends in OK)
my $_response_success = sub {
    my ($str) = @_;
    my $prev5 = substr $str, -8, 5;    # FAIL (maybe);

    if ( $prev5 eq "FAIL\n" ) {
        return;
    }

    return 1;
};

my $MAX_SOCKET_READ    = 4096;
my $MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

my $_read_response = sub {
    my ($socket) = @_;
    my $resp = q{};
    my $tmpstr;
    my $tmpbytes;
    my $bytes = 0;

    do {
        $tmpbytes = $socket->sysread( $tmpstr, $MAX_SOCKET_READ );
        if ( $tmpbytes && $tmpstr && $tmpbytes > 0 ) {
            $resp .= $tmpstr;
            $bytes += $tmpbytes;
        }
      } while ( defined($tmpbytes)
        && !$_response_complete->($resp)
        && $bytes < $MAX_RESPONSE_BYTES );

    if ( $bytes == 0 ) {
        return;
    }

    if ( !$_response_success->($resp) ) {
        return;
    }

    $resp = substr $resp, 0, -3;    # remove "OK\n"
    return $resp;
};

my $dhcp_getleasebyaddr_from_socket = sub {
    my $socket     = shift(@_);
    my $when       = shift(@_);
    my $summary    = shift(@_);
    my $addrtype   = shift(@_);
    my $paramcount = @_;
    my @results;

    if ( $paramcount < 1 ) {
        return;
    }

    chomp $when;
    my $json = JSON->new->allow_nonref;

    # To make these queries match the behavior of the database queries,
    # search for an entire day if nothing but the date was supplied.
    if ( $when =~ /^[1-9][0-9][0-9][0-9]\/[0-9][0-9]\/[0-9][0-9]$/ ) {
        $when .= '+1d';
    }

    my $addrfield = $addr_socket_search_field{$addrtype};
    if ( !$addrfield ) {
        return;
    }

    foreach my $addr (@_) {
        my $query = "SEARCH: when=$when,$addrfield=$addr";

        if ( defined($summary) && $summary != 0 ) {
            $query .= ',pullup';
        }
        $query .= "\n";

        my $bytes = $socket->send($query);

        if ( $bytes != length($query) ) {
            carp "could not send entire SEARCH string?";
            return;
        }

        # _read_search_response needs to strip "OK" from the end
        # and return undef on any error
        my $resp = $_read_response->($socket);
        if ( !$resp ) {
            carp "did not receive response to SEARCH";
            return;
        }

        my $resp_href = $json->decode($resp);
        if ( !$resp_href ) {
            carp "received invalid JSON in response to SEARCH";
            return;
        }

        foreach my $idx ( keys %$resp_href ) {

            # assemble an array of hash references, assuming that JSON
            # builds nested hashes
            push @results, $resp_href->{$idx};
        }
    }

    if ( !@results ) {
        return;
    }

    return \@results;
};

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
        if ( length($tmpaddr) > 0 ) {
            if ( !( $tmpaddr =~ /$addr_valid_characters{'4'}/ ) ) {
                my $sub_name = ( caller(0) )[3];
                carp "$sub_name: address contains invalid characters";
                return;
            }
        }
    }

    my $query =
        "SELECT clientaddr, hostname, requested_hostname, domainname FROM $table WHERE";

    if ( length($addrs) > 0 ) {
        $query .= " clientaddr IN ('$addrs') AND"
    }

    $query .= ' ( requested_hostname <> "" OR hostname <> "" )'
           .  ' GROUP BY clientaddr, hostname, requested_hostname, domainname';
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

# args: <database-handle> <table> [<name> [<name> [<name> ...] ...]]
# returns reference to array of hash references.
# If no name specified, returns all names in table.  Leases without a hostname
# are ignored.
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
        if ( length($tmpname) > 0 ) {
            if ( !( $tmpname =~ /$addr_valid_characters{'n'}/ ) ) {
                my $sub_name = ( caller(0) )[3];
                carp "$sub_name: hostname contains invalid characters";
                return;
            }
        }
    }

    my $query =
        'SELECT clientaddr, hostname, requested_hostname, domainname '
      . "FROM $table";

    if ( length($names) > 0 ) {
        $query .= " WHERE requested_hostname IN ('$names')"
          . " OR hostname IN ('$names')";
    }
    else {
        $query .= ' WHERE requested_hostname <> "" OR hostname <> ""';
    }
    $query .= ' GROUP BY clientaddr, hostname, requested_hostname, domainname';
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
        if ( length($tmpaddr) > 0 ) {
            if ( !( $tmpaddr =~ /$pattern/ ) ) {
                my $sub_name = ( caller(0) )[3];
                carp "$sub_name: address contains invalid characters";
                return;
            }
        }
    }

    my $addrfield = $addr_search_field{$addrtype};

    # SELECT * FROM $table WHERE $addrfield IN (...)
    # ORDER BY clientmac, clientaddr, stime ;
    my $query = qq{SELECT * FROM $table};

    if ( length($addrs) > 0 ) {
        $query .= qq{ WHERE $addrfield IN ('$addrs')};
    }

    $query .= q{ ORDER BY clientmac, clientaddr, stime};
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
    my $func       = $addr_canon_func{$addrtype};
    my @addrs;

    if ( $func ) {
        # canonicalize the address strings
        @addrs = map { $func->($_) } @_;
    } else {
        @addrs = @_;
    }

    my @whenary = parsetime($when);
    my $whensec        = timelocal(@whenary);
    my $now            = timelocal( localtime() );
    my $seconds_in_day = 86400;
    if ( $whensec > $now || ( $now - $whensec ) <= $seconds_in_day ) {
        my $socket = dhcp_opensocket;
        if ( defined($socket) ) {
            my $rv = $dhcp_getleasebyaddr_from_socket->( $socket, $when, 1, $addrtype, @addrs );

            dhcp_closesocket($socket);
            return $rv;
        }
    }

    my $table = strftime $table_summary, @whenary;
    return $_dhcp_getlease_from_table->( $dbh, "$dbase.$table", $addrtype, @addrs );
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

    my @whenary = parsetime($when);
    my $table = strftime $table_summary, @whenary;

    return $_dhcp_getlease_from_table->( $dbh, "$dbase.$table", 'n', @_ );
}

sub dhcp_lease_expand_one {
    my ( $dbh, $href, $now ) = @_;

    if ( !defined $href ) {
        return;
    }

    # take a lease summarization as generated by dhcp_getleasebyaddr*
    # or dhcp_getleasebyname* and use the detail SQL tables to find
    # the leases that contributed to the summary.

    # summary lease start and last times
    my $seconds_in_day   = 86400;
    my $date_range_stime = POSIX::floor( $href->{'stime'} );
    my $date_range_ltime = POSIX::ceil( $href->{'ltime'} );

    if ( $date_range_ltime > ( $now + $seconds_in_day ) ) {
        # DHCP Precognition is not a supported feature
        $date_range_ltime = $now + $seconds_in_day;
    }

    if ( $date_range_stime > $date_range_ltime ) {
        # something went wrong
        return;
    }

    my $duration         = $date_range_ltime - $date_range_stime;
    my $seconds          = $date_range_stime;
    my $results_aref;

    # Step through the range of lease times one 24-hour period at a
    # time and format the year-month-day table name for each.
    # Search those tables for matching clients and times.
    while ( $duration > 0 ) {
        my $table = strftime $table_detail, localtime($seconds);
        my $query = qq{SELECT * FROM $table WHERE }
          . q{(clientmac=? AND clientaddr=? AND stime>=? AND ltime<?)};
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
            goto ADVANCE;
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

ADVANCE:
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
    my @time = localtime();
    my $now = timegm(@time);

    for my $href (@$aref) {
        my $aref = dhcp_lease_expand_one( $dbh, $href, $now );

        if ( !defined $aref ) {
            next;
        }

        push @reslist, $aref;
    }
    return \@reslist;
}

# dhcp_insert_fqdn takes an array reference as returned by dhcp_gethostby* and
# adds an fqdn entry to each hash if enough information is present.
sub dhcp_insert_fqdn {
    my ($aref) = @_;

    for my $href (@$aref) {
        my $have_domainname = 0;
        my $domainname      = $href->{'domainname'};
        my $hostname;

        if ( defined $href->{'hostname'} && length( $href->{'hostname'} ) > 0 )
        {
            $hostname = $href->{'hostname'};
        }
        else {
            if ( defined $href->{'requested_hostname'}
                && length( $href->{'requested_hostname'} ) > 0 )
            {
                $hostname = $href->{'requested_hostname'};
            }
        }

        if ( !defined $hostname ) {
            $href->{'fqdn'} = "";
            next;
        }

        # If the hostname (requested or otherwise) has a period in it,
        # most likely it is something like .local or .home and was put
        # there by a residential router, cablemodem, etc.  In this case
        # assume that there is no effect on DNS and that the hostname we
        # already have is as "fully qualified" as it is going to get.
        if ( $hostname =~ /\./ ) {
            $href->{'fqdn'} = $hostname;
            next;
        }

        if ( defined $href->{'domainname'}
            && length( $href->{'domainname'} ) > 0 )
        {
            $hostname .= ".$domainname";
        }

        $href->{'fqdn'} = $hostname;
    }
    return;
}

1;
