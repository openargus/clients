package qosient::rahisto;

#   Argus-5.0 Client Software.  Tools to read, analyze and manage Argus data.
#   Copyright (c) 2017-2024 QoSient, LLC
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
#  This library contains routines for accessing the rahisto SQL tables.

use strict;
use warnings;
use Carp;
use DBI;
use POSIX qw(strftime);
use Try::Tiny;
use Net::IP;
use Math::BigInt;
use Exporter;
use vars qw($VERSION @ISA @EXPORT);
$VERSION = "1.00";
@ISA     = qw(Exporter);
@EXPORT  = qw(
  DURATION_SEC
  DURATION_MIN
  DURATION_HOUR
  DURATION_DAY
  DURATION_WEEK
  DURATION_MONTH
  DURATION_YEAR
  ONE_MINUTE
  ONE_HOUR
  ONE_DAY
  ONE_WEEK
  ONE_MONTH
  ONE_YEAR
  TIMEFMT_YEAR
  TIMEFMT_MONTH
  TIMEFMT_WEEK
  TIMEFMT_DAY
  TIMEFMT_HOUR
  TIMEFMT_MINUTE
  rahisto_metric_by_name
  rahisto_metric_by_num
  rahisto_get_model
  rahisto_get_range
  rahisto_get_bincount
  rahisto_get_logscale
  rahisto_opendb
  rahisto_closedb
  rahisto_create_index_table
  rahisto_update_index_table
  rahisto_create_values_table
  rahisto_update_values_table
  strs2prefix_array
  rahisto_index_search_prefixes
  rahisto_aggregate_query
  rahisto_stimes_query
  rahisto_kldiv
  rahisto_jsdiv
  rahisto_jsdist
);

my $debug    = 0;            # print debugging messages (includes DBI messages)
my $dbuser   = 'root';
my $dbase    = 'baseline';
my $password = q{};
my %attr     = ( PrintError => $debug, RaiseError => 0 );
my $errcount = 0;

sub rahisto_opendb {
    my $dsn = "DBI:mysql:";
    my $dbh = DBI->connect( $dsn, $dbuser, $password, \%attr );

    if (defined $dbh) {
        $dbh->do("CREATE DATABASE IF NOT EXISTS $dbase");
        $dbh->do("USE $dbase");
    }
    return $dbh;             # undefined on error
}

sub rahisto_closedb {
    my ($dbh) = @_;

    $dbh->disconnect();
    return 0;
}

use constant {
    DURATION_SEC   => 0,
    DURATION_MIN   => 1,
    DURATION_HOUR  => 2,
    DURATION_DAY   => 3,
    DURATION_WEEK  => 4,
    DURATION_MONTH => 5,
    DURATION_YEAR  => 6,
};

use constant {
    ONE_MINUTE => 60,
    ONE_HOUR   => 3600,
    ONE_DAY    => 86400,
    ONE_WEEK   => 86400 * 7,
    ONE_MONTH  => 86400 * 28,
    ONE_YEAR   => 86400 * 365,
};

use constant {
    TIMEFMT_YEAR   => '%Y',
    TIMEFMT_MONTH  => '%Y_%m',
    TIMEFMT_WEEK   => '%Y_w%W',
    TIMEFMT_DAY    => '%Y_%m_%d',
    TIMEFMT_HOUR   => '%Y_%m_%d_%H',
    TIMEFMT_MINUTE => '%Y_%m_%d_%H_%M',
};

# This is a bit less than the max double value (inf), but all arithmetic
# on inf always results in inf.
my $DBL_MAX = 1.7e+308;


# Based on the ARGUSPRINT* C macros
my %metric_by_name = (
    'stime'         => 0,
    'ltime'         => 1,
    'trans'         => 2,
    'dur'           => 3,
    'mean'          => 4,
    'min'           => 5,
    'max'           => 6,
    'saddr'         => 7,
    'daddr'         => 8,
    'proto'         => 9,
    'sport'         => 10,
    'dport'         => 11,
    'stos'          => 12,
    'dtos'          => 13,
    'sdsb'          => 14,
    'ddsb'          => 15,
    'sttl'          => 16,
    'dttl'          => 17,
    'bytes'         => 18,
    'sbytes'        => 19,
    'dbytes'        => 20,
    'appbytes'      => 21,
    'sappbytes'     => 22,
    'dappbytes'     => 23,
    'pkts'          => 24,
    'spkts'         => 25,
    'dpkts'         => 26,
    'load'          => 27,
    'sload'         => 28,
    'dload'         => 29,
    'loss'          => 30,
    'sloss'         => 31,
    'dloss'         => 32,
    'ploss'         => 33,
    'sploss'        => 34,
    'dploss'        => 35,
    'rate'          => 36,
    'srate'         => 37,
    'drate'         => 38,
    'srcid'         => 39,
    'flgs'          => 40,
    'smac'          => 41,
    'dmac'          => 42,
    'dir'           => 43,
    'sintpkt'       => 44,
    'dintpkt'       => 45,
    'sintpktact'    => 46,
    'dintpktact'    => 47,
    'sintpktidl'    => 48,
    'dintpktidl'    => 49,
    'sintpktmax'    => 50,
    'sintpktmin'    => 51,
    'dintpktmax'    => 52,
    'dintpktmin'    => 53,
    'sintpktactmax' => 54,
    'sintpktactmin' => 55,
    'dintpktactmax' => 56,
    'dintpktactmin' => 57,
    'sintpktidlmax' => 58,
    'sintpktidlmin' => 59,
    'dintpktidlmax' => 60,
    'dintpktidlmin' => 61,
    'xxx'           => 62,
    'sjit'          => 63,
    'djit'          => 64,
    'sjitact'       => 65,
    'djitact'       => 66,
    'sjitidl'       => 67,
    'djitidl'       => 68,
    'state'         => 69,
    'dldur'         => 70,
    'dlstime'       => 71,
    'dlltime'       => 72,
    'dlspkt'        => 73,
    'dldpkt'        => 74,
    'dspkts'        => 75,
    'ddpkts'        => 76,
    'dsbytes'       => 77,
    'ddbytes'       => 78,
    'pdspkts'       => 79,
    'pddpkts'       => 80,
    'pdsbytes'      => 81,
    'pddbytes'      => 82,
    'suser'         => 83,
    'duser'         => 84,
    'tcpext'        => 85,
    'swin'          => 86,
    'dwin'          => 87,
    'jdelay'        => 88,
    'ldelay'        => 89,
    'seq'           => 90,
    'bins'          => 91,
    'binnum'        => 92,
    'smpls'         => 93,
    'dmpls'         => 94,
    'svlan'         => 95,
    'dvlan'         => 96,
    'svid'          => 97,
    'dvid'          => 98,
    'svpri'         => 99,
    'dvpri'         => 100,
    'sipid'         => 101,
    'dipid'         => 102,
    'srng'          => 103,
    'erng'          => 104,
    'stcpb'         => 105,
    'dtcpb'         => 106,
    'tcprtt'        => 107,
    'stddev'        => 109,
    'rtime'         => 110,
    'offset'        => 111,
    'snet'          => 112,
    'dnet'          => 113,
    'sdur'          => 114,
    'ddur'          => 115,
    'stcpmax'       => 116,
    'dtcpmax'       => 117,
    'synack'        => 118,
    'ackdat'        => 119,
    'sstime'        => 120,
    'sltime'        => 121,
    'dstime'        => 122,
    'dltime'        => 123,
    'senc'          => 124,
    'denc'          => 125,
    'spktsz'        => 126,
    'smaxsz'        => 127,
    'sminsz'        => 128,
    'dpktsz'        => 129,
    'dmaxsz'        => 130,
    'dminsz'        => 131,
    'sco'           => 132,
    'dco'           => 133,
    'shops'         => 134,
    'dhops'         => 135,
    'icmpid'        => 136,
    'label'         => 137,
    'sas'           => 169,
    'das'           => 170,
    'ias'           => 171,
    'cause'         => 172,
    'bssid'         => 173,
    'ssid'          => 174,
    'nstroke'       => 175,
    'snstroke'      => 176,
    'dnstroke'      => 177,
    'smeansz'       => 178,
    'dmeansz'       => 179,
    'rank'          => 180,
    'sum'           => 181,
    'runtime'       => 182,
    'idle'          => 183,
    'tcpopt'        => 184,
    'resp'          => 185,
    'sgap'          => 186,
    'dgap'          => 187,
    'soui'          => 188,
    'doui'          => 189,
    'cor'           => 190,
    'laddr'         => 191,
    'raddr'         => 192,
    'lnet'          => 191,
    'rnet'          => 192,
    'abr'           => 195,
    'pcr'           => 196,
    'tf'            => 197,
    'stf'           => 198,
    'dtf'           => 199,
    'ico'           => 200,
    'slat'          => 201,
    'slon'          => 202,
    'dlat'          => 201,
    'dlon'          => 202,
    'ilat'          => 201,
    'ilon'          => 202,
    'sloc'          => 207,
    'dloc'          => 208,
    'loc'           => 209,
    'sid'           => 210,
    'node'          => 211,
    'inf'           => 212,
    'status'        => 213,
    'sgrp'          => 214,
    'dgrp'          => 215,
    'hash'          => 216,
    'ind'           => 217,
    'score'         => 218,
    'sname'         => 219,
    'dname'         => 220,
    'etype'         => 221,
);

my %metric_by_num = (
    0   => 'stime',
    1   => 'ltime',
    2   => 'trans',
    3   => 'dur',
    4   => 'mean',
    5   => 'min',
    6   => 'max',
    7   => 'saddr',
    8   => 'daddr',
    9   => 'proto',
    10  => 'sport',
    11  => 'dport',
    12  => 'stos',
    13  => 'dtos',
    14  => 'sdsb',
    15  => 'ddsb',
    16  => 'sttl',
    17  => 'dttl',
    18  => 'bytes',
    19  => 'sbytes',
    20  => 'dbytes',
    21  => 'appbytes',
    22  => 'sappbytes',
    23  => 'dappbytes',
    24  => 'pkts',
    25  => 'spkts',
    26  => 'dpkts',
    27  => 'load',
    28  => 'sload',
    29  => 'dload',
    30  => 'loss',
    31  => 'sloss',
    32  => 'dloss',
    33  => 'ploss',
    34  => 'sploss',
    35  => 'dploss',
    36  => 'rate',
    37  => 'srate',
    38  => 'drate',
    39  => 'srcid',
    40  => 'flgs',
    41  => 'smac',
    42  => 'dmac',
    43  => 'dir',
    44  => 'sintpkt',
    45  => 'dintpkt',
    46  => 'sintpktact',
    47  => 'dintpktact',
    48  => 'sintpktidl',
    49  => 'dintpktidl',
    50  => 'sintpktmax',
    51  => 'sintpktmin',
    52  => 'dintpktmax',
    53  => 'dintpktmin',
    54  => 'sintpktactmax',
    55  => 'sintpktactmin',
    56  => 'dintpktactmax',
    57  => 'dintpktactmin',
    58  => 'sintpktidlmax',
    59  => 'sintpktidlmin',
    60  => 'dintpktidlmax',
    61  => 'dintpktidlmin',
    62  => 'xxx',
    63  => 'sjit',
    64  => 'djit',
    65  => 'sjitact',
    66  => 'djitact',
    67  => 'sjitidl',
    68  => 'djitidl',
    69  => 'state',
    70  => 'dldur',
    71  => 'dlstime',
    72  => 'dlltime',
    73  => 'dlspkt',
    74  => 'dldpkt',
    75  => 'dspkts',
    76  => 'ddpkts',
    77  => 'dsbytes',
    78  => 'ddbytes',
    79  => 'pdspkts',
    80  => 'pddpkts',
    81  => 'pdsbytes',
    82  => 'pddbytes',
    83  => 'suser',
    84  => 'duser',
    85  => 'tcpext',
    86  => 'swin',
    87  => 'dwin',
    88  => 'jdelay',
    89  => 'ldelay',
    90  => 'seq',
    91  => 'bins',
    92  => 'binnum',
    93  => 'smpls',
    94  => 'dmpls',
    95  => 'svlan',
    96  => 'dvlan',
    97  => 'svid',
    98  => 'dvid',
    99  => 'svpri',
    100 => 'dvpri',
    101 => 'sipid',
    102 => 'dipid',
    103 => 'srng',
    104 => 'erng',
    105 => 'stcpb',
    106 => 'dtcpb',
    107 => 'tcprtt',
    109 => 'stddev',
    110 => 'rtime',
    111 => 'offset',
    112 => 'snet',
    113 => 'dnet',
    114 => 'sdur',
    115 => 'ddur',
    116 => 'stcpmax',
    117 => 'dtcpmax',
    118 => 'synack',
    119 => 'ackdat',
    120 => 'sstime',
    121 => 'sltime',
    122 => 'dstime',
    123 => 'dltime',
    124 => 'senc',
    125 => 'denc',
    126 => 'spktsz',
    127 => 'smaxsz',
    128 => 'sminsz',
    129 => 'dpktsz',
    130 => 'dmaxsz',
    131 => 'dminsz',
    132 => 'sco',
    133 => 'dco',
    134 => 'shops',
    135 => 'dhops',
    136 => 'icmpid',
    137 => 'label',
    169 => 'sas',
    170 => 'das',
    171 => 'ias',
    172 => 'cause',
    173 => 'bssid',
    174 => 'ssid',
    175 => 'nstroke',
    176 => 'snstroke',
    177 => 'dnstroke',
    178 => 'smeansz',
    179 => 'dmeansz',
    180 => 'rank',
    181 => 'sum',
    182 => 'runtime',
    183 => 'idle',
    184 => 'tcpopt',
    185 => 'resp',
    186 => 'sgap',
    187 => 'dgap',
    188 => 'soui',
    189 => 'doui',
    190 => 'cor',
    191 => 'laddr',
    192 => 'raddr',
    191 => 'lnet',
    192 => 'rnet',
    195 => 'abr',
    196 => 'pcr',
    197 => 'tf',
    198 => 'stf',
    199 => 'dtf',
    200 => 'ico',
    201 => 'slat',
    202 => 'slon',
    201 => 'dlat',
    202 => 'dlon',
    201 => 'ilat',
    202 => 'ilon',
    207 => 'sloc',
    208 => 'dloc',
    209 => 'loc',
    210 => 'sid',
    211 => 'node',
    212 => 'inf',
    213 => 'status',
    214 => 'sgrp',
    215 => 'dgrp',
    216 => 'hash',
    217 => 'ind',
    218 => 'score',
    219 => 'sname',
    220 => 'dname',
    221 => 'etype',
);

sub rahisto_metric_by_name {
    my ($name) = @_;

    return $metric_by_name{$name};
}

sub rahisto_metric_by_num {
    my ($num) = @_;

    return $metric_by_num{$num};
}

my %range = (
    rahisto_metric_by_name('dur') =>
      '0-5',    # appliances use a 5 second status interval
    rahisto_metric_by_name('spkts') =>
      '0-1500000',    # slightly over 1 gbps of 64-byte packets
    rahisto_metric_by_name('dpkts') =>
      '0-1500000',    # slightly over 1 gbps of 64-byte packets
    rahisto_metric_by_name('sbytes') => '0-125000000',    # 1 gbps / 8 bits
    rahisto_metric_by_name('dbytes') => '0-125000000',    # 1 gbps / 8 bits
    rahisto_metric_by_name('pcr')    => '-1-1',           # -1 to +1
);

my %bincount = (
    rahisto_metric_by_name('dur')    => 25,
    rahisto_metric_by_name('spkts')  => 25,
    rahisto_metric_by_name('dpkts')  => 25,
    rahisto_metric_by_name('sbytes') => 25,
    rahisto_metric_by_name('dbytes') => 25,
    rahisto_metric_by_name('pcr')    => 25,
);

my %logscale = (
    rahisto_metric_by_name('dur')    => 1,
    rahisto_metric_by_name('spkts')  => 1,
    rahisto_metric_by_name('dpkts')  => 1,
    rahisto_metric_by_name('sbytes') => 1,
    rahisto_metric_by_name('dbytes') => 1,
    rahisto_metric_by_name('pcr')    => 0,
);

my $_rahisto_get_config = sub {
    my ( $href, $mod ) = @_;

    if ( !exists $href->{$mod} ) {
        return;
    }
    return $href->{$mod};
};

# $datum is an href containing one json-decoded histogram from rahisto
my $_rahisto_parse_instance = sub {
    my ($datum) = @_;
    my @failure = (undef, undef);
    my $instance = $datum->{'instance'};

    if ( exists( $instance->{'saddr'} ) ) {
        my $saddr = $instance->{'saddr'};
        chomp $saddr;
        $saddr =~ s/  *$//;

        my $prefix = Net::IP->new($saddr);

        if ( defined $prefix ) {
            return ($prefix->ip(), $prefix->prefixlen());
        }
        else {
            carp "Invalid IP address '$saddr' found in json data";
            return @failure;
        }
    }
    return @failure;
};

# from the Perl Maven:
sub uniq {
    keys { map { $_ => 1 } @_ };
}

# mostly the same as rahisto_metric_by_num
sub rahisto_get_model {
    my ($mod) = @_;
    return $_rahisto_get_config->( \%metric_by_num, $mod );
}

sub rahisto_get_range {
    my ($mod) = @_;
    return $_rahisto_get_config->( \%range, $mod );
}

sub rahisto_get_bincount {
    my ($mod) = @_;
    return $_rahisto_get_config->( \%bincount, $mod );
}

sub rahisto_get_logscale {
    my ($mod) = @_;
    return $_rahisto_get_config->( \%logscale, $mod );
}

sub rahisto_create_index_table {
    my ($dbh) = @_;

  # previous_stime is used to find prevous entry when adding new histogram data.
  # histo_bins and histo_size cannot change from one run of rahisto to the next.
    my $query =
        q{CREATE TABLE IF NOT EXISTS histograms (}
      . q{address VARBINARY(16),       masklen INTEGER UNSIGNED, }
      . q{model TINYINT UNSIGNED, }
      . q{sid VARCHAR(64),             tablename VARCHAR(64),}
      . q{inf VARCHAR(4),              previous_stime DOUBLE(18,6) UNSIGNED, }
      . q{histo_bins INTEGER UNSIGNED, histo_size DOUBLE, }
      . q{PRIMARY KEY (address, masklen, model, tablename))};
    my $sth = $dbh->prepare($query);

    if ( !defined $sth ) {
        carp "unable to prepare SQL create table statement";
        return;
    }

    my $res = $sth->execute;

    $sth->finish;
    if ( !defined $res ) {
        return;
    }
    return 1;
}

# These can go in yet another table . . . if needed, that has one row
# per histogram (one row per rahisto run)
#             . q{histo_mean DOUBLE, histo_stddev DOUBLE, }
#             . q{histo_min DOUBLE,  histo_max DOUBLE))};

sub rahisto_update_index_table {
    my ( $dbh, $address, $masklen, $sidinf_href, $times_aref, $histo_href,
        $tablename, $model )
      = @_;
    my $query =
        q{INSERT INTO histograms (address, masklen, model, sid, tablename, }
      . q{inf, previous_stime, histo_bins, histo_size) VALUES }
      . q{(INET6_ATON(?), ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE }
      . q{previous_stime=?};

    my $sth = $dbh->prepare($query);

    if ( !defined $sth ) {
        carp "unable to prepare SQL create table statement";
        return;
    }

    my $aref   = [$histo_href];    # reference to array of one href element
    my $_model = $model;
    my $_address = $address;
    my $_masklen = $masklen;

    if ( ref $histo_href eq 'ARRAY' ) {

        # the json data already contains the array.  use it and
        # assume that each element is a hash reference.
        $aref = $histo_href;
    }

    for my $datum ( @{$aref} ) {

        # rahisto adds a key named "metric" when generating histograms
        # for multiple metrics.
        if ( exists( $datum->{'metric'} ) ) {
            $_model = rahisto_metric_by_name( $datum->{'metric'} );

            # the try/catch block will turn croak into a SQL rollback
            if ( !defined $_model ) {
                croak "invalid metric found in rahisto output";
            }
        }
        if ( !defined $_model ) {
            croak "no model found for histogram";
        }

        if ( exists( $datum->{'instance'} ) ) {
            ($_address, $_masklen) = $_rahisto_parse_instance->($datum);
            if ( !defined $_address || !defined $_masklen ) {
                carp "No address found for histogram";
                $sth->finish;
                return;
            }
        }

        my @params = ( $_address, $_masklen, $_model, $sidinf_href->{'sid'} );
        push @params, $tablename;
        push @params, ( $sidinf_href->{'inf'}, $times_aref->[0] );
        push @params, ( $datum->{'bins'},      $datum->{'size'} );
        push @params, $times_aref->[0];

        my $res = $sth->execute(@params);

        $sth->finish;
        if ( !defined $res ) {
            carp "Unable to update histograms index";
            return;
        }
    }

    return 1;
}

# times_aref is an array of (start, end) times in seconds since unix
# epoch, utc
# Many SELECT statements filter by stime which go MUCH faster with
# an index containing only stime (PRIMARY is not used when only one
# of the columns from the PRIMARY KEY is used).
sub rahisto_create_values_table {
    my ( $dbh, $times_aref, $sidinf_href ) = @_;
    my $sidinfstr = $sidinf_href->{'sid'} . '_' . $sidinf_href->{'inf'};

    $sidinfstr =~ s/-//g;

    # Add win_mean, win_stddev, win_variance when we're ready to calculate
    # running stddev, etc.  For now leave them out because rahisto-update
    # does not populate these columns but they still use a lot of disk.
    my $timestr = strftime( TIMEFMT_MONTH, gmtime $times_aref->[0] );
    my $tablename = "histo_${sidinfstr}_${timestr}";
    my $query =
        qq{CREATE TABLE IF NOT EXISTS $tablename (}
      . q{masklen INTEGER UNSIGNED,     address VARBINARY(16),       }
      . q{model TINYINT UNSIGNED,       stime DOUBLE(18,6) UNSIGNED, }
      . q{ltime DOUBLE(18,6) UNSIGNED,  samples INTEGER UNSIGNED,    }
      . q{class INT,                                                 }
      . q{bin_interval DOUBLE,          freq BIGINT,                 }
      . q{min DOUBLE,                   max DOUBLE,                  }
      . q{PRIMARY KEY (address, masklen, class, model, stime),       }
      . q{INDEX start_time (stime))                                  };
    my $sth = $dbh->prepare($query);

    if ( !defined $sth ) {
        carp "unable to prepare SQL create table statement";
        return;
    }

    my $res = $sth->execute;

    if ( !defined $res ) {
        return;
    }
    $sth->finish;

    return $tablename;
}

sub rahisto_update_values_table {
    my ( $dbh, $tablename, $data, $model, $address, $masklen, $times ) = @_;
    my $query =
        qq{INSERT INTO $tablename (masklen, address, model, }
      . q{stime, ltime, class, bin_interval, freq, }
      . q{samples, min, max) VALUES (?, INET6_ATON(?), }
      . q{?, ?, ?, ?, ?, ?, ?, ?, ?)};

    # +--------------+-----------------------+------+-----+---------+-------+
    # | Field        | Type                  | Null | Key | Default | Extra |
    # +--------------+-----------------------+------+-----+---------+-------+
    # | masklen      | int(10) unsigned      | NO   | PRI | NULL    |       |
    # | address      | varbinary(16)         | NO   | PRI | NULL    |       |
    # | model        | tinyint(4)            | NO   | PRI | NULL    |       |
    # | stime        | double(18,6) unsigned | NO   | PRI | NULL    |       |
    # | ltime        | double(18,6) unsigned | YES  |     | NULL    |       |
    # | samples      | int(10) unsigned      | YES  |     | NULL    |       |
    # | class        | int(11)               | NO   | PRI | NULL    |       |
    # | bin_interval | double                | YES  |     | NULL    |       |
    # | freq         | bigint(20)            | YES  |     | NULL    |       |
    # | min          | double                | YES  |     | NULL    |       |
    # | max          | double                | YES  |     | NULL    |       |
    # +--------------+-----------------------+------+-----+---------+-------+

    my $sth = $dbh->prepare($query);

    if ( !defined $sth ) {
        carp "unable to prepare SQL create table statement";
        return;
    }

    $dbh->{AutoCommit} = 0;
    $dbh->{RaiseError} = 1;

    # rahisto's json output is an object (record / struct / dictionary
    # / etc.) when there is only one metric (one -H option) and is an
    # array of objects when multiple metrics are requested.  Create our
    # own array by default and if the parsed json output is an array,
    # use it instead.

    my $success = 1;
    try {
        my $aref   = [$data];    # reference to array of one href element
        my $_model = $model;
        my $_address = $address;
        my $_masklen = $masklen;

        if ( ref $data eq 'ARRAY' ) {

            # the json data already contains the array.  use it and
            # assume that each element is a hash reference.
            $aref = $data;
        }

        for my $datum ( @{$aref} ) {

            # rahisto adds a key named "metric" when generating histograms
            # for multiple metrics.
            if ( exists( $datum->{'metric'} ) ) {
                $_model = rahisto_metric_by_name( $datum->{'metric'} );

                # the try/catch block will turn croak into a SQL rollback
                if ( !defined $_model ) {
                    croak "invalid metric found in rahisto output";
                }
            }
            if ( !defined $_model ) {
                croak "no model found for histogram";
            }

            if ( exists( $datum->{'instance'} ) ) {
                ($_address, $_masklen) = $_rahisto_parse_instance->($datum);
                if ( !defined $_address || !defined $_masklen ) {
                    carp "No address found for histogram";
                    $sth->finish;
                    return;
                }
            }

            for my $value ( @{ $datum->{'values'} } ) {
                my $interval = $value->{'Interval'};
                if ( $interval =~ /-inf/ ) {
                    $interval = -1 * $DBL_MAX;
                }

                my @params =
                  ( $_masklen, $_address, $_model, $times->[0], $times->[2] );
                push @params, $value->{'Class'};
                push @params, $interval;
                push @params, $value->{'Freq'};

                # InnoDB, using the compact row format, uses less space to
                # store NULL values than non-NULL values.  We only need one
                # copy of the N, min and max values.
                if ( $value->{'Class'} == 1 ) {
                    push @params, $datum->{'N'};
                    push @params, $datum->{'min'};
                    push @params, $datum->{'max'};
                }
                else {
                    push @params, undef;
                    push @params, undef;
                    push @params, undef;
                }
                $sth->execute(@params);
            }
        }
        $dbh->commit;
    }
    catch {
        carp "Transaction aborted because $_";
        eval { $dbh->rollback };
        $success = undef;
    };

    $dbh->{AutoCommit} = 1;
    $dbh->{RaiseError} = 0;
    return $success;
}

# given an array of IP prefix strings, return reference to an array of
# Net::IP objects.
sub strs2prefix_array {
    my ($prefixstr_aref) = @_;
    my $prefixes = [];

    if ( defined $prefixstr_aref ) {
        my @addresses;    # remove the prefix for now
        my $oneprefix;

        for my $oneprefix (@$prefixstr_aref) {
            my $ip = Net::IP->new($oneprefix);

            if ( !defined $ip ) {
                carp( Net::IP::Error() );
                return;
            }
            push $prefixes, $ip;
        }
    }
    return $prefixes;
}

my $_format_query_address_clause = sub {
    my ($prefixstr_aref) = @_;
    my $addresses = strs2prefix_array($prefixstr_aref);
    my $hostonly = 1;
    my @result = ();

    if ( !defined $addresses ) {
        return;
    }

    for my $pfx (@{ $addresses }) {
        if (($pfx->version == 4 && $pfx->prefixlen < 32)
            || ($pfx->version == 6 && $pfx->prefixlen < 128)) {
            $hostonly = undef;
            last;
        }
    }

    if ($hostonly) {
        my $addresses_str = 'address IN ('
          . join( ',', map( 'INET6_ATON(?)', @$addresses ) )
          . ')';
        push @result, $addresses_str;
        push @result, map( $_->ip(), @$addresses );
        return @result;
    }

    # Only ipv4 prefixes are handled, for now.
    my $pfxcount = 0;
    my $where = q{};
    for my $pfx (@{ $addresses }) {
        if ($pfxcount > 0) {
            $where .= ' OR ';
        }

        if ($pfx->version == 6) {
           # Carve up the 128-bit address into 64-bit chunks so that MariaDB
           # deal with it as VARBINARY.  MySQL 8 doesn't have this problem. . .
           my $mask_upper = Math::BigInt->new($pfx->hexmask)->brsft(64);
           my $mask_lower = Math::BigInt->new($pfx->hexmask)
                              ->band(Math::BigInt->new('0xffffffffffffffff'));
           my $prefix_upper = $pfx->intip()->copy()->brsft(64);
           my $prefix_lower = $pfx->intip()->copy()
                                ->band(Math::BigInt->new('0xffffffffffffffff'));

           $where .= '(LENGTH(address) = 16 AND ('
                  .  '(CAST(CONV(HEX(SUBSTRING(address, 1, 8)), 16, 10) AS UNSIGNED) '
                  .  ' & ' . $mask_upper->as_hex . ' = (0 | ' . $prefix_upper->as_hex . '))'
                  .  ' AND '
                  .  '(CAST(CONV(HEX(SUBSTRING(address, 9, 8)), 16, 10) AS UNSIGNED) '
                  .  ' & ' . $mask_lower->as_hex . ' = (0 | ' . $prefix_lower->as_hex . '))'
                  .  '))';
        } else {
           $where .= '(LENGTH(address) = 4 AND '
                  .  '(CAST(conv(HEX(address), 16, 10) AS UNSIGNED) & '
                  .  $pfx->hexmask . ') = (0 | ' . $pfx->hexip . '))';
        }
        $pfxcount++;
    }

    if ($pfxcount > 0) {
        $where = "($where" . ')';
    }

    return ($where, ());
};

# $dbh                  DBI handle
# $prefixstr_aref       reference to array of IP prefix strings
# $sidstr_aref          reference to array of Argus SIDs (UUIDs)
# $infstr_aref          reference to array of Argus interface names
#
# Returns a hash reference containing the tablenames, sids and infs.  The
# hash is keyed by tablename.
sub rahisto_index_search_prefixes {
    my ( $dbh, $prefixstr_aref, $sidstr_aref, $infstr_aref, $model ) = @_;
    my $addresses;
    my $usewhere;
    my $where  = q{ WHERE};
    my @params = ();

    if ( $prefixstr_aref && scalar(@$prefixstr_aref) > 0 ) {
        my ($addresses_str, my @aparams) =
          $_format_query_address_clause->( $prefixstr_aref );

        if (length($addresses_str) > 0) {
            $where = " $addresses_str";
            $usewhere = 1;
            if (@aparams) {
                push @params, @aparams;
            }
        }
    }

    if ($sidstr_aref) {
        if ( scalar(@$sidstr_aref) > 0 ) {
            if ($usewhere) {
                $where .= q{ AND};
            }
            my $template = join( ',', map( '?', @$sidstr_aref ) );
            push @params, @$sidstr_aref;
            $usewhere = 1;
            $where .= " sid IN ($template)";
        }
    }

    if ($infstr_aref) {
        if ( scalar(@$infstr_aref) > 0 ) {
            if ($usewhere) {
                $where .= q{ AND};
            }
            my $template = join( ',', map( '?', @$infstr_aref ) );
            push @params, @$infstr_aref;
            $usewhere = 1;
            $where .= " inf IN ($template)";
        }
    }

    my $query = qq{SELECT tablename, sid, inf FROM  histograms};
    if ($usewhere) {
        $query .= " WHERE $where";
    }
    $query .= qq{ GROUP BY tablename};
    if ($debug) {
        print STDERR "$query\n";
        print STDERR "VALUES @params\n";
    }

    my $sth = $dbh->prepare($query);

    if ( !defined $sth ) {
        carp "unable to prepare SQL create select statement";
        return;
    }

    my $res = $sth->execute(@params);

    if ( !defined $res ) {
        return;
    }
    my $hash_ref = $sth->fetchall_hashref('tablename');
    $sth->finish;

    return $hash_ref;
}

use constant {
    QUERY_STIMES    => 0,
    QUERY_AGGREGATE => 1,
};

# results of prepare() indexed by table name, #prefixes, #times
# sql_statements->{$tablename}->{$num_prefixes}->{$num_times} = $dbh->prepare()
my $sql_statements = {};

my $find_sql_statement = sub {
    my ( $tablename, $num_prefixes, $num_times ) = @_;
    if ( exists $sql_statements->{$tablename}->{$num_prefixes}->{$num_times} ) {
        return $sql_statements->{$tablename}->{$num_prefixes}->{$num_times};
    }
    return;
};

my $insert_sql_statement = sub {
    my ( $tablename, $num_prefixes, $num_times, $stmt ) = @_;
    if ( !exists $sql_statements->{$tablename}->{$num_prefixes}->{$num_times} )
    {
        $sql_statements->{$tablename}->{$num_prefixes}->{$num_times} = $stmt;
    }
    return;
};

my $_format_query_histo_values = sub {
    my ( $querytype, $dbh, $prefixstr_aref, $tablename, $times, $model ) = @_;
    my $query =
      qq{SELECT class, bin_interval, SUM(freq) as freq from $tablename};
    my $where   = q{ WHERE model = ?};
    my $groupby = q{ GROUP BY class WITH ROLLUP};
    my @params  = ($model);
    my $addresses;

    if ( $querytype == QUERY_STIMES ) {
        $query   = qq{SELECT DISTINCT stime from $tablename};
        $groupby = q{};
    }

    if ( $prefixstr_aref && scalar(@$prefixstr_aref) > 0 ) {
        my ($addresses_str, @aparams) = $_format_query_address_clause->( $prefixstr_aref );
        if (length($addresses_str) > 0) {
            $where .= " AND $addresses_str";
            if (@aparams) {
                push @params, @aparams;
            }
        }
    }

    if ( defined $times ) {
        my $cnt    = scalar(@$times);
        my $clause = q{};

        $clause .= q{ AND};

        if ( $cnt > 0 ) {
            $clause .= qq{ stime >= ?};
            push @params, $times->[0];
            if ( $cnt > 2 ) {
                $clause .= qq{ AND stime < ?};
                push @params, $times->[2];
            }
            $where .= $clause;
        }
    }

    $query .= $where;
    $query .= $groupby;
    if ($debug) {
        print STDERR "$query\n";
        print STDERR "VALUES " . join( ', ', @params ) . "\n";
    }
    return ( $query, \@params );
};

my $_aggregate_histo_values = sub {
    my ( $dbh, $prefixstr_aref, $tablename, $times, $model ) = @_;
    if ( !defined $times ) {
        $times = [];
    }
    if ( !defined $prefixstr_aref ) {
        $prefixstr_aref = [];
    }

    my $num_prefixes = scalar( @{$prefixstr_aref} );
    my $num_times    = scalar( @{$times} );

    my $sth = $find_sql_statement->( $tablename, $num_prefixes, $num_times );

    my ( $query, $params ) = $_format_query_histo_values->( QUERY_AGGREGATE, @_ );
    if ( !$sth ) {
        $sth = $dbh->prepare($query);
        if ( !defined $sth ) {
            carp "unable to prepare SQL create select statement";
            return;
        }
        $insert_sql_statement->( $tablename, $num_prefixes, $num_times, $sth );
    }

    my $res = $sth->execute( @{$params} );

    if ( !defined $res ) {
        return;
    }
    my $hash_ref = $sth->fetchall_hashref('class');
    $sth->finish;

    return $hash_ref;
};

my $_query_histo_stimes = sub {
    my ( $dbh, $prefixstr_aref, $tablename, $times, $model ) = @_;
    my ( $query, $params ) = $_format_query_histo_values->( QUERY_STIMES, @_ );
    my $sth = $dbh->prepare($query);

    if ( !defined $sth ) {
        carp "unable to prepare SQL create select statement";
        return;
    }

    my $res = $sth->execute( @{$params} );

    if ( !defined $res ) {
        return;
    }
    my $aref = $sth->fetchall_arrayref;
    $sth->finish;

    return $aref;
};



# aggregate_histo_results: sum up the values from all of the tables
#
# $results_href         a hash reference containing one or more histograms
#                       (which are, in turn, also hash refs) keyed by SQL
#                       table name, although any unique value will do.
#
# returns a hash reference containing a single histogram
my $aggregate_histo_results = sub {
    my ($results_href) = @_;
    my %agg = ();
    for my $tbl ( keys $results_href ) {
        my $href = $results_href->{$tbl};
        for my $class ( keys $href ) {
            if ( exists $agg{$class} ) {
                $agg{$class}->{'freq'} += $href->{$class}->{'freq'};
            }
            else {
                $agg{$class} = { %{ $href->{$class} } };  # shallow copy of hash
            }
        }
    }
    return \%agg;
};

# rahisto_aggregate_query parameters:
#   $dbh                DBI handle as returned by rahisto_opendb()
#   $index_href         hash reference returned by rahisto_index_search_prefixes()
#   $query_prefixes     array reference to IP address prefixes
#   $query_times        array reference to start and stop times in seconds GMT.
#                       Second element is '-'.
#   $metric             hash table metric specified with -H on rahisto commandline
#
# returns a hash ref containing a single histogram that represents the aggregate
# of all histograms found for the requested prefixes during the requested times
# in all of the tables listed in $index_href.
sub rahisto_aggregate_query {
    my ( $dbh, $index_href, $query_prefixes, $query_times, $metric ) = @_;
    my %results_hash = ();

    for my $tbl ( keys $index_href ) {
        my $results =
          $_aggregate_histo_values->( $dbh, $query_prefixes, $tbl, $query_times,
            $metric );
        if ($results) {
            $results_hash{$tbl} = $results;
        }
    }
    return $aggregate_histo_results->( \%results_hash );
}

#   $dbh                DBI handle as returned by rahisto_opendb()
#   $index_href         hash reference returned by rahisto_index_search_prefixes()
#   $query_prefixes     array reference to IP address prefixes
#   $query_times        array reference to start and stop times in seconds GMT.
#                       Second element is '-'.
#   $metric             hash table metric specified with -H on rahisto commandline
sub rahisto_stimes_query {
    my ( $dbh, $index_href, $query_prefixes, $query_times, $metric ) = @_;
    my @results_array = ();

    for my $tbl ( keys $index_href ) {
        my $results =
          $_query_histo_stimes->( $dbh, $query_prefixes, $tbl, $query_times,
            $metric );
        if ($results) {

            # fetchall_arrayref returns an array ref of array refs.
            # For this query, each inner arrayref has only one element.
            push @results_array, map( $_->[0], @{$results} );
        }
    }

    # pick out the distinct values and sort in ascending numeric order
    my @uniq_values = sort { $a <=> $b } uniq(@results_array);
    return \@uniq_values;
}


# equal(NUM1, NUM2, ACCURACY) : returns true if NUM1 and NUM2 are
# equal to ACCURACY number of decimal places
# Borrowed from Perl Cookbook by Nathan Torkington, Tom Christiansen
# Seems like it will be slow.  maybe (abs($A-$B) < .0000001) instead?
sub float_equal {
    my ( $A, $B, $dp ) = @_;

    return sprintf( "%.${dp}g", $A ) eq sprintf( "%.${dp}g", $B );
}

# Determine if the two histograms / frequency distributions have the
# same number of bins and that each bin in $A represents the same range
# of values as its corresponding bin in $B.
my $_rahisto_are_similar = sub {
    my ( $A, $B ) = @_;
    my $acount = scalar( keys($A) );
    my $bcount = scalar( keys($B) );

    if ( $acount != $bcount ) {
        return;
    }

    my $i;
    for ( $i = 1 ; $i <= $acount ; $i++ ) {
        if ( !exists $A->{$i} ) {
            if ( !exists $B->{$i} ) {

                # this will skip the "rollup" hash
                next;
            }

            # found a mismatch in class values
            return;
        }
        if (
            !float_equal(
                $A->{$i}->{'bin_interval'},
                $B->{$i}->{'bin_interval'}, 6
            )
          )
        {
            return;
        }
    }
    return 1;
};

# Calculating the Kullback-Leibler Divergence requires that if there
# are zero values in the Q(i) frequency distribution, the corresponding
# frequencies in P(i) must also be zero, else the resulting divergence
# in undefined.  In terms of just arithmetic this is a problem with
# dividing by zero -- ln(P[i]/Q[i]).  However, simply skipping the
# offending term(s) in Q removes one of the basic properties of the KL
# divergence: that it is always non-negative.
#
# The approach to work around this problem tried here, since many of the
# frequency distributions generated from flow data will have such "zero
# entries", is to sub-sample the data; neighboring probabilities (bins
# in the histogram) will be combined, in pairs, until there are no 0%
# probabilities left.  A lower limit can be provided to this function to
# prevent the algorithm continuing all the way to a single bin of 100%.
# In the event there are an odd number of bins, the center bin will be
# carved in twain and, if non-zero, half of its value will be contributed
# to each of its two neighbors.
my $_rahisto_subsample = sub {
    my ( $P, $Q, $lowerlimit_param ) = @_;
    my $lowerlimit = 4;

    if ( defined $lowerlimit_param ) {
        $lowerlimit = $lowerlimit_param;
    }

    if ($debug) {
        if ( !$_rahisto_are_similar->( $P, $Q ) ) {
            carp "Q and P must be similar";
            return ( undef, undef );
        }
    }

    my $pcount     = scalar( keys($P) );
    my $qcount     = scalar( keys($Q) );
    my $qzerocount = 0;

    for my $val ( values $P ) {
        if ( !defined $val->{'class'} ) {
            $pcount --;   # don't count the rollup value
            next;
        }
    }

    for my $val ( values $Q ) {
        if ( !defined $val->{'class'} ) {
            $qcount --;   # don't count the rollup value
            next;
        }
        if ( $val->{'freq'} == 0 ) {
            $qzerocount++;
        }
    }

    if ( $qzerocount == 0 || $qcount < ( $lowerlimit * 2 ) ) {
        return ( undef, undef );
    }

    my $splitbin;
    my $psplitval;
    my $qsplitval;
    my $Pnew = {};
    my $Qnew = {};

    if ( $qcount % 2 == 1 ) {
        $splitbin  = ( $qcount >> 1 ) + 1;
        $psplitval = $P->{$splitbin}->{'freq'} / 2.0;
        $qsplitval = $Q->{$splitbin}->{'freq'} / 2.0;
    }

    my $i;
    my $off = 1;
    for ( $i = 1 ; $i < $pcount ; ) {
        if ( $splitbin && $i == $splitbin ) {

            # skip this one for now
            $i++;
            $off = 0;
            next;
        }

        my $class = ( $i >> 1 ) + $off;
        my $bin_interval =
          ( $P->{$i}->{'bin_interval'} + $P->{ $i + 1 }->{'bin_interval'} ) /
          2.0;

        $Pnew->{$class} = {
            'class'        => $class,
            'freq'         => $P->{$i}->{'freq'} + $P->{ $i + 1 }->{'freq'},
            'bin_interval' => $bin_interval,
        };
        $Qnew->{$class} = {
            'class'        => $class,
            'freq'         => $Q->{$i}->{'freq'} + $Q->{ $i + 1 }->{'freq'},
            'bin_interval' => $bin_interval,
        };

        $i += 2;
    }

    # Now carve up the center bin and give each of the two center-most
    # bins in $Pnew half.  A subsampled histo will always have an even
    # number of bins, numbered from bin "1".

    if ( defined $splitbin ) {
        my $newcenter = ( $pcount >> 2 );
        $Pnew->{$newcenter}->{'freq'}       += $psplitval;
        $Pnew->{ $newcenter + 1 }->{'freq'} += $psplitval;
        $Qnew->{$newcenter}->{'freq'}       += $qsplitval;
        $Qnew->{ $newcenter + 1 }->{'freq'} += $qsplitval;
    }

    my $class = ( $i >> 1 ) + $off;
    $Pnew->{''}     = $P->{''};
    $Qnew->{''}     = $Q->{''};
    $Pnew->{$class} = $P->{$pcount};
    $Qnew->{$class} = $Q->{$qcount};

    return ( $Pnew, $Qnew );
};

# Kullback-Leibler Divergence
# Calculates D_{KL}(P||Q)
# P and Q are references to hashes as returned by $_aggregate_histo_values()
#   in rahisto-querysql  (should that function be moved here?)
# P is assumed to be the "true" distribution.
my $_rahisto_kldiv = sub {
    my ( $P, $Q ) = @_;
    my $diverg = 0;
    my $P_total;
    my $Q_total;

    if ( scalar( keys $Q ) != scalar( keys $P ) ) {
        carp "Q and P must have the same number of bins";
        return;
    }

    # rollup value, including outliers
    $P_total = 1.0 * $P->{''}->{'freq'};
    $Q_total = 1.0 * $Q->{''}->{'freq'};

    for my $k ( keys($P) ) {

        # The hash contains a "ROLLUP" of all frequencies with an
        # undefined class, as returned by the sql query.  Skip this
        # element.
        if ( !defined $P->{$k}->{'class'} ) {
            next;
        }

        my $p    = $P->{$k}->{'freq'};
        my $q    = $Q->{$k}->{'freq'};
        my $term = 0;

        if ( $q == 0 && $p != 0 ) {

            # KL Divergence is undefined for this case.  Attempt to
            # sub-sample and try again.
            my ( $Pss, $Qss ) = $_rahisto_subsample->( $P, $Q );
            if ( defined $Pss && defined $Qss ) {
                return rahisto_kldiv( $Pss, $Qss );
            }

            if ($debug) {
                print STDERR "subsample FAILED!!\n";
            }

            # Unable to subsample.  Give up.
            return;
        }

        if ( $p != 0 && $q != 0 ) {

            # here we can also be sure that P_total and Q_total are
            # not zero.
            $p /= $P_total;
            $q /= $Q_total;
            $term = $p * log( $p / $q );
            $diverg += $term;
        }
    }
    return $diverg;
};

sub rahisto_kldiv {
    my ( $P, $Q ) = @_;

    if ( !$_rahisto_are_similar->( $P, $Q ) ) {
        carp "Q and P must be similar";
        return;
    }
    return $_rahisto_kldiv->( $P, $Q );
}

# $A and $B are histograms -- references to hashes as returned by
# $_aggregate_histo_values().
#
# Returns $scale * ($A + $B)
my $_rahisto_add = sub {
    my ( $A, $B, $scale ) = @_;
    my $res = { %{$A} };

    for my $class ( keys $A ) {
        $res->{$class} = { %{ $A->{$class} } };    # shallow copy of has
        $res->{$class}->{'freq'} += $B->{$class}->{'freq'};
        if ( defined $scale ) {
            $res->{$class}->{'freq'} *= $scale;
        }
    }

    # adjust min, max, times?
    return $res;
};

# Jensen–Shannon divergence
sub rahisto_jsdiv {
    my ( $P, $Q ) = @_;

    if ( !$_rahisto_are_similar->( $P, $Q ) ) {
        carp "P and Q must be similar";
        return;
    }

    my $M = $_rahisto_add->( $P, $Q, 0.5 );
    my $P_M = $_rahisto_kldiv->( $P, $M );
    my $Q_M = $_rahisto_kldiv->( $Q, $M );

    if ( !defined $P_M || !defined $Q_M ) {
        carp "Jensen-Shannon divergence failed??";
        return;
    }

    return ( ( $P_M + $Q_M ) * 0.5 );
}

# Jensen-Shannon distance
sub rahisto_jsdist {
    my ( $P, $Q ) = @_;
    my $div = rahisto_jsdiv( $P, $Q );

    if ( !defined $div ) {
        return;
    }
    return sqrt($div);
}

1;
