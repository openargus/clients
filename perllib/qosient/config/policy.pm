package qosient::config::policy;

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

use Carp;
use strict;
use warnings;
use DBI qw(:sql_types);
use Try::Tiny;
use Exporter;
use vars qw($VERSION @ISA @EXPORT);
$VERSION = "1.00";
@ISA     = qw(Exporter);
@EXPORT  = qw(
 policy_opendb
 policy_closedb
 policy_find_version
 policy_find_active
 policy_remove_older
 policy_insert_policyset
 policy_create_configuration_table
);

my $debug = 0;
my $dbase         = q{policy};
my $table_ethers  = q{configuration};
my $dsn;
my $dbuser   = 'root';
my $password = q{};
my %attr     = ( PrintError => $debug, RaiseError => 0 );
my $errcount = 0;


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

sub policy_create_configuration_table {
    my ($dbh) = @_;
    my $query = q{CREATE TABLE IF NOT EXISTS configuration (}
              . q{policy_set VARCHAR(64),      uuid VARCHAR(37), }
              . q{stime DOUBLE(18,6) UNSIGNED, ltime DOUBLE(18,6) UNSIGNED, }
              . q{version INTEGER UNSIGNED,    config TEXT, }
              . q{PRIMARY KEY(policy_set, version), }
              . q{KEY stime (stime), }
              . q{KEY ltime (ltime))};

    if (!$dbh) {
        carp "database handle is undefined";
        return;
    }

    if ( !$dbh->do($query) ) {
        return;
    }
    return 1;
}

sub policy_opendb {
    $dsn  = "DBI:mysql:";
    my $dbh = DBI->connect( $dsn, $dbuser, $password, \%attr );
    if ($dbh) {
        if ( !$dbh->do("CREATE DATABASE IF NOT EXISTS $dbase") ) {
            policy_closedb($dbh);
            $dbh = undef;
        } else {
            $dbh->do("USE $dbase");
            policy_create_configuration_table($dbh);
        }
    }
    return $dbh;                     # undefined on error
}

sub policy_closedb {
    my ($dbh) = @_;

    if (!$dbh) {
        carp "database handle is undefined";
        return;
    }

    $dbh->disconnect();
    return 0;
}

#+------------+-----------------------+------+-----+---------+-------+
#| Field      | Type                  | Null | Key | Default | Extra |
#+------------+-----------------------+------+-----+---------+-------+
#| policy_set | varchar(64)           | NO   | PRI | NULL    |       |
#| uuid       | varchar(37)           | YES  | MUL | NULL    |       |
#| stime      | double(18,6) unsigned | YES  | MUL | NULL    |       |
#| ltime      | double(18,6) unsigned | YES  |     | NULL    |       |
#| version    | int(10) unsigned      | NO   | PRI | NULL    |       |
#| config     | text                  | YES  |     | NULL    |       |
#+------------+-----------------------+------+-----+---------+-------+

# Close the time interval on some previous version of the policy described
# by $policy_set.  Set the ltime column to the specified (usually current)
# time.
#
# Return the number of rows changed (should be zero or one).  Return
# undefined on failure.
#
# $policy_set is a hash reference with keys:
#   policy_set  (the policy-set name)
#   uuid
#   stime
#   ltime
#   version
#   config
# $oldver is an integer value
# $when is the closing time in seconds after the Unix Epoch UTC.
sub policy_invalidate_policyset {
    my ($dbh, $policy_set, $oldver, $when) = @_;
    my $query =
        q{UPDATE configuration SET ltime = ? WHERE policy_set = ? }
      . q{AND version = ?};
    my @params = ($when, $policy_set->{'policy_set'}, $oldver);

    if (!$dbh) {
        carp "database handle is undefined";
        return;
    }

    my $sth = $dbh->prepare($query);
    if (!$sth) {
        return;
    }

    my $res = $sth->execute(@params);
    $sth->finish;
    if ($res && $res > 1) {
        carp "Too many policy-sets invalidated?";
    }
    return $res;
}

# $policy_set is a hash reference with keys:
#   policy_set  (the policy-set name)
#   uuid
#   stime
#   ltime
#   version
#   config
sub policy_insert_policyset {
    # TODO: use transaction to roll back after partial failure
    my ($dbh, $policy_set) = @_;
    my $query =
        q{INSERT INTO configuration (policy_set, version, uuid, stime, }
      . q{config) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE ltime=?};
    my @params = ($policy_set->{'policy_set'}, $policy_set->{'version'},
                  $policy_set->{'uuid'}, $policy_set->{'stime'},
                  $policy_set->{'config'}, $policy_set->{'ltime'});

    if (!$dbh) {
        carp "database handle is undefined";
        return;
    }

    my $stmt = $dbh->prepare($query);
    if (!$stmt) {
        return;
    }

    my $res = $stmt->execute(@params);
    $stmt->finish;
    if (!$res) {
        return;
    }

    # Now invalidate the previous version, if any.
    my $ver = $policy_set->{'version'};
    if ($ver > 1) {
        my $num = policy_invalidate_policyset($dbh, $policy_set, $ver - 1,
            $policy_set->{'stime'});
    }
    return 1;
}

# remove policy-sets from the configuration table that are older than
# the specified date/time.
#
# $when is specified in seconds after the Unix Epoch UTC
# Important to only remove those with ltime > 0 since newly added rows
# may have a zero value for ltime.
sub policy_remove_older {
    my ($dbh, $when) = @_;
    my $query = q{DELETE FROM configuration WHERE ltime > 0 AND ltime < ?};
    my @params = ($when);

    if (!$dbh) {
        carp "database handle is undefined";
        return;
    }

    my $stmt = $dbh->prepare($query);
    if (!$stmt) {
        return;
    }

    my $res = $stmt->execute(@params);
    $stmt->finish;
    if ($debug) {
        if (!$res) {
            print STDERR "Removal of rows from configuration table failed\n";
        }
        else {
            print STDERR "Removed $res rows from the configuration table\n";
        }
    }
    return $res;
}

# Find the policies that were active during a particular period of time
# $begin and $end are times specified in seconds after the Unix Epoch UTC.
#
# Returns a reference to an array of hashrefs with a key for each column of
# the configuration SQL table.
sub policy_find_active {
    my ($dbh, $begin, $end) = @_;
    my $query =
        # WHERE $begin <= ltime && $end >= stime
        q{SELECT * FROM configuration WHERE ? <= ltime && ? >= stime};
    my @params = ($begin, $end);

    if (!$dbh) {
        carp "database handle is undefined";
        return;
    }

    my $stmt = $dbh->prepare($query);
    if (!$stmt) {
        return;
    }

    my $res = $stmt->execute(@params);
    if (!$res) {
        $stmt->finish;
        return;
    }

    my $aref = $_result_list->($stmt);
    $stmt->finish;
    return $aref;
}

# Find the latest version number for a policy-set
sub policy_find_version {
    my ($dbh, $policy_set_name) = @_;
    my $query = q{SELECT MAX(version) FROM configuration WHERE policy_set = ?};
    my @params = ($policy_set_name);

    if (!$dbh) {
        carp "database handle is undefined";
        return;
    }

    my $sth = $dbh->prepare($query);
    if (!$sth) {
        return;
    }

    my $res = $sth->execute(@params);
    if (!$res) {
        $sth->finish;
        return;
    }

    my $aref = $sth->fetchrow_arrayref;
    if (!$aref) {
        # No policy-set by this name, start at zero
        $sth->finish;
        return 0;
    }

    $sth->finish;
    return $aref->[0];
}

1;
