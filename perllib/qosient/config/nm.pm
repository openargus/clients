package qosient::config::nm;

use strict;
use warnings;
use Exporter;
use Scalar::Util qw(looks_like_number);
use vars qw($VERSION @ISA @EXPORT);

$VERSION = "1.00";
@ISA     = qw(Exporter);
@EXPORT  = qw(nm_setup_monitor_dev
  nm_disable_dev
  nm_setup_mgmt_dev
  nm_setup_directattach_dev);

my @modify = qw/nmcli con modify --temporary/;
my @conup  = qw/nmcli --wait 0 con up/;
my @condown  = qw/nmcli con down/;
my @disablev4 = ('ipv4.addresses', '', 'ipv4.gateway', '', 'ipv4.dns', '', 'ipv4.method', 'disabled');
my @disablev6 = ('ipv6.addresses', '', 'ipv6.gateway', '', 'ipv4.dns', '', 'ipv6.method', 'ignore');
my @llv6 = ('ipv6.addresses', '', 'ipv6.gateway', '', 'ipv6.method', 'link-local');

# Prepare an interface for use as a monitoring device.  Disable both
# address families, set mtu to 9000 and bring the interface up in this
# new configuration.  The interface name is really the networkmanager
# connection name.  Will need to add some magic for the cases where that
# is not the same as the interface name.
sub nm_setup_monitor_dev {
    my ($itf) = @_;

    system(@modify, ${itf}, @disablev4);
    system(@modify, ${itf}, @disablev6);
    system(@modify, ${itf}, '802-3-ethernet.mtu', '9000');
    system(@modify, ${itf}, 'connection.autoconnect', 'yes');
    system(@conup, ${itf});
    return 1;
}

sub nm_disable_dev {
    my ($itf) = @_;

    system(@modify, ${itf}, 'connection.autoconnect', 'no');
    system(@modify, ${itf}, @disablev4);
    system(@modify, ${itf}, @disablev6);
    system(@condown, ${itf});
    return 1;
}

# $ipv4_addrs and $ipv6_addrs are array references
sub nm_setup_mgmt_dev {
    my ($itf, $ipv4_addrs, $ipv6_addrs, $ipv4_next_hop, $ipv6_next_hop,
        $ipv4_disable, $ipv6_disable, $ipv4_dns, $ipv6_dns) = @_;

    my @ipv4_gateway = ();
    if (scalar @$ipv4_next_hop == 1) {
        @ipv4_gateway = ('ipv4.gateway', @$ipv4_next_hop);
    }

    my @ipv6_gateway = ();
    if (scalar @$ipv6_next_hop == 1) {
        @ipv6_gateway = ('ipv6.gateway', @$ipv6_next_hop);
    }

    if ( !$ipv4_disable ) {
        if (scalar(@$ipv4_addrs) > 0) {
            my @args = ('ipv4.method', 'manual',
                        'ipv4.addresses', join(', ', @$ipv4_addrs),
                        @ipv4_gateway);
            if ( defined $ipv4_dns && scalar($ipv4_dns) > 0 ) {
                push @args, 'ipv4.dns', join(',', @$ipv4_dns);
            }
            system(@modify, ${itf}, @args);
        } else {
            system(@modify, ${itf}, 'ipv4.method', 'auto', 'ipv4.addresses', '');
        }
    }

    if ( !$ipv6_disable ) {
        if (scalar(@$ipv6_addrs > 0)) {
            my @args = ('ipv6.method', 'manual',
                        'ipv6.addresses', join(', ', @$ipv6_addrs),
                        @ipv6_gateway);
            if ( defined $ipv6_dns && scalar(@$ipv6_dns) > 0 ) {
                push @args, 'ipv6.dns', join(', ', @$ipv6_dns);
            }
            system(@modify, ${itf}, @args);
        } else {
            system(@modify, ${itf}, 'ipv6.method', 'auto', 'ipv6.addresses', '');
        }
    }

    system(@conup, ${itf});
    return 1;
}

sub nm_setup_directattach_dev {
    my ($itf) = @_;

    system(@modify, ${itf}, @disablev4);
    system(@modify, ${itf}, @llv6);
    system(@modify, ${itf}, '802-3-ethernet.mtu', '1500');
    system(@modify, ${itf}, 'connection.autoconnect', 'yes');
    system(@conup, ${itf});
    return 1;
}

1;
