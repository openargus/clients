package qosient::config;

use strict;
use Exporter;
use vars qw($VERSION @ISA @EXPORT);
use Parse::DMIDecode qw();

$VERSION = "1.00";
@ISA     = qw(Exporter);
@EXPORT  = qw(read_sys_uuid generate_sys_uuid read_os_release netconf_connect
              systype2name write_srcid_aliases);

my $QOSIENT_SYSTEM_TYPE_COLLECTOR = 1;
my $QOSIENT_SYSTEM_TYPE_SENSOR    = 2;
my $QOSIENT_SYSTEM_TYPE_DISTRIBUTOR = 3;

my %qosient_system_type = (
    'collector'   => $QOSIENT_SYSTEM_TYPE_COLLECTOR,
    'devel'       => $QOSIENT_SYSTEM_TYPE_COLLECTOR,
    'sensor'      => $QOSIENT_SYSTEM_TYPE_SENSOR,
    'distributor' => $QOSIENT_SYSTEM_TYPE_DISTRIBUTOR
);

our %qosient_system_name = (
    $QOSIENT_SYSTEM_TYPE_COLLECTOR   => 'collector',
    $QOSIENT_SYSTEM_TYPE_SENSOR      => 'sensor',
    $QOSIENT_SYSTEM_TYPE_DISTRIBUTOR => 'distributor'
);

sub systype2name {
    my ($systype) = @_;

    return $qosient_system_name{$systype};
}

sub read_sys_uuid {
    my $filename = '/var/cache/argus/monitor-id';
    my $fh;

    if ( !open( $fh, '<', $filename ) ) {
        print STDERR "Could not open file '$filename' $!\n";
        return;
    }

    my $line = <$fh>;
    close $fh;
    chomp $line;
    return lc "$line";
}

sub generate_sys_uuid {
    my $dmi = Parse::DMIDecode->new( nowarnings => 1 );
    $dmi->probe;

    my $uuid = $dmi->keyword('system-uuid');
    if ( !defined $uuid ) {
         return;
    }

    if ( $uuid =~ /^[A-F0-9]+-[A-F0-9]+-[A-F0-9]+-[A-F0-9]+-[A-F0-9]+$/ ) {
        return lc $uuid;
    }

    $uuid = `uuidgen -t`;
    if ( $? != 0 ) {
        return;
    }

    return $uuid;
}

# href is a hash ref: srcid => name
# config is a hash ref that can contain the keys: ReplaceFile, Filename
#   If ReplaceFile is defined and non-zero the existing file, if any, will be
#   overwritten.
#   If Filename is defined the specified name will be used instead of the
#   default.
sub write_srcid_aliases {
    my ($href, $config) = @_;
    my $filename;
    my $replace_file = 0;

    if ( $config ) {
        if ( exists $config->{'ReplaceFile'} ) {
            $replace_file = $config->{'ReplaceFile'};
        }
        if ( exists $config->{'Filename'} ) {
            $filename = $config->{'Filename'};
        }
    }

    if ( !defined $filename ) {
        $filename = '/usr/argus/srcid.alias.txt';
    }

    if ( $replace_file == 0 && -f $filename ) {
        return 0;
    }

    my $fh;
    if ( !open( $fh, '>', $filename ) ) {
        print STDERR "Could not open file '$filename' $!\n";
        return;
    }

    for my $srcid (keys %{ $href }) {
        print $fh "$srcid " . $href->{$srcid} . "\n";
    }

    close $fh;
    return 1;
}

sub read_os_release {
    my $filename = '/etc/os-release';
    my $fh;
    my $QOSIENT_SYSTEM_TYPE = $QOSIENT_SYSTEM_TYPE_COLLECTOR;

    if ( !open( $fh, '<', $filename ) ) {
        print STDERR "Could not open file '$filename' $!\n";
        return;
    }

    while ( my $line = <$fh> ) {
        chomp $line;
        my ( $col1, $col2 ) = split /=/, $line;
        if ( !( $col1 eq 'QOSIENT_SYSTEM_TYPE' ) ) {
            next;
        }

        $col2 =~ s/"//g;    # get rid of double-quotes
        my $systype = $qosient_system_type{$col2};
        if ( !defined $systype ) {
            print STDERR "Unknown qosient system type\n";
            close $fh;
            return;
        }
        $QOSIENT_SYSTEM_TYPE = $systype;
        last;
    }
    close $fh;
    return lc $QOSIENT_SYSTEM_TYPE;
}

1;
