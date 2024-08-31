package qosient::config::firewall;

use strict;
use Exporter;
use Scalar::Util qw(looks_like_number);
use vars qw($VERSION @ISA @EXPORT);

$VERSION = "1.00";
@ISA     = qw(Exporter);
@EXPORT  = qw(firewall_add_port
              firewall_remove_port
              firewall_add_drop_all
              firewall_remove_drop_all);

sub firewall_port {
    my ($port, $proto, $add) = @_;

    if ( !looks_like_number($port) ) {
        return;
    }

    if ( ! ($proto eq 'tcp' or $proto eq 'udp' ) ) {
        return ;
    }

    my $option;
    if ( $add ) {
        $option = '--add-port';
    } else {
        $option = '--remove-port';
    }

    my @cmd = qw('firewall-cmd', "$option=${port}/${proto}");
    if ( system(@cmd) != 0 ) {
        return;
    }

    return 1;
}

sub firewall_add_port {
    my ($port, $proto) = @_;
    return firewall_port($port, $proto, 1);
}

sub firewall_remove_port {
    my ($port, $proto) = @_;
    return firewall_port($port, $proto);
}


sub firewall_cmd_drop {
    my ($itf, $opt) = @_;
    my $rulecmd = '--add-rule';

    if ( $opt eq 'remove' ) {
        $rulecmd = '--remove-rule';
    }

    # "eb" doesn't work in proto for --direct configs, even though
    # it's documented.
    for my $proto (qw(ipv4 ipv6)) {
        my @cmd_out =  ('firewall-cmd', '--direct', ${rulecmd}, ${proto},
                        'filter', 'OUTPUT', '0', '--out-interface', ${itf},
                        '-j', 'DROP');

        my @cmd_in  =  ('firewall-cmd', '--direct', ${rulecmd}, ${proto},
                        'filter', 'INPUT', '0', '--in-interface', ${itf},
                        '-j', 'DROP');

        if (system(@cmd_out) != 0) {
            print "failed command: " . join(' ', @cmd_out) . "\n";
        }
        if (system(@cmd_in) != 0) {
            print "failed command: " . join(' ', @cmd_in) . "\n";
        }
    }
    return 1;
}

sub firewall_add_drop_all {
    my ($itf) = @_;
    return firewall_cmd_drop($itf, 'add');
}
sub firewall_remove_drop_all {
    my ($itf) = @_;
    return firewall_cmd_drop($itf, 'remove');
}

1;
