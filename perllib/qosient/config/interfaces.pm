package qosient::config::interfaces;

use strict;
use Exporter;
use vars qw($VERSION @ISA @EXPORT);
use Parse::DMIDecode qw();
use Scalar::Util qw(looks_like_number);

$VERSION = "1.00";
@ISA     = qw(Exporter);
@EXPORT  = qw(find_pci_ethdevs
              index_by_slotport
              is_collector_monitor_device
              is_sensor_monitor_device
              find_monitor_ethdevs);

my $PCI_VENDOR_INTEL='0x8086';
my $PCI_DEVICE_INTEL_I350='0x1521';
my $PCI_DEVICE_INTEL_X710='0x1572';

# returns a hash reference containing: name, busaddr, vendor, device,
# acpi_index
sub device_info {
    my ($devname) = @_;
    my $sysfs = '/sys/class/net/' . $devname;
    my $fh;
    my %hash = ();
    my @attrs = ( '/vendor', '/device', '/acpi_index' );

    my $devlink = readlink $sysfs;
    if ( !defined $devlink ) {
        return;
    }

    if ( ! ( $devlink =~ /devices.pci/ ) ) {
        # only deal with pci devices from here
        return;
    }

    my @devlinkparts = split '/', $devlink;
    my $busaddr = $devlinkparts[ $#devlinkparts - 2 ];

    $hash{'name'} = $devname;
    $hash{'busaddr'} = $busaddr;
    for my $attr (@attrs) {
	    my $filename = $sysfs . "/device" . $attr;
	    if ( !open( $fh, '<', $filename ) ) {
		next;
	    }
	    my $line = <$fh>;
	    close $fh;
	    chomp $line;
            $hash{substr $attr, 1} = $line;
    }
    return \%hash;
}

# Use dmidecode(8) to gather vendor-supplied information about the PCIe slots.
# Return a hash reference with bus-address -> slot-number mappings.
sub find_pci_slotnums {
    my $dmi = Parse::DMIDecode->new( nowarnings => 1 );
    $dmi->probe;

    my %hash = ();

    for my $other ($dmi->get_handles(group => "slot")) {
        my $desig = $other->keyword("slot-designation");

        if ( ! ( $desig =~ /^PCIe Slot / ) ) {
            next;
        }

        $desig =~ s/PCIe Slot //;
        if ( ! looks_like_number($desig) ) {
            next;
        }

        my $busaddr = $other->keyword("slot-bus-address");
        $busaddr =~ s/\.[0-9]+$//; # remove the function number
        $hash{$busaddr} = $desig; # map bus address -> slot number
    }
    return \%hash;
}

# Dig around in the /sys/class/net for network interfaces and build a hash
# table, indexed by PCI bus address, that contains hash references as
# returned by device_info().  Then get vendor-supplied slot descriptions
# from dmidecode via find_pci_slotnums() and add a slot number, if available,
# to each device info hash.
sub find_pci_ethdevs {
    my ($systypename) = @_;
    my %pcidevs = ();

    for my $path (glob q{/sys/class/net/*}) {
        my $devname;

        ($devname = $path) =~ s/^.*\///;
        my $dinfo = device_info( $devname );

        if ( !defined $dinfo ) {
            next;
        }

        if ( exists $dinfo->{'acpi_index'} ) {
            $dinfo->{'port'} = $dinfo->{'acpi_index'};
        } else {
            my $function = $dinfo->{'busaddr'};
            $function =~ s/^.*\.//;
            $dinfo->{'port'} = $function; # use function number for "port" number
        }
        $pcidevs{ $dinfo->{'busaddr'} } = $dinfo;
    }

    my $slotnums = find_pci_slotnums();
    if ( !defined $slotnums ) {
        goto OUT;
    }

    # find_pci_slotnums indexes the hash by bus address, excluding the zero
    # function number.  device_info() includes a function number for
    # the ethernet device.  Knock the function numbers off of the device info and
    # compare.  If the rest of the bus address matches, add the slot number
    # to the hash created by device_info.
    for my $busaddr (keys %$slotnums) {
        for my $ethdev_busaddr (keys %pcidevs) {
            my $ethdev_nofunc = $ethdev_busaddr;

            $ethdev_nofunc =~ s/\.[0-9]+$//;
            if ( $busaddr eq $ethdev_nofunc ) {
                $pcidevs{$ethdev_busaddr}->{'slot'} = $slotnums->{$busaddr};
            }
        }
    }

    # One more pass: look for entries that do not have a slot number defined
    # and add one claiming to be in slot zero.
    for my $ethdev_busaddr (keys %pcidevs) {
        if ( !exists $pcidevs{$ethdev_busaddr}->{'slot'} ) {
            $pcidevs{$ethdev_busaddr}->{'slot'} = '0';
        }
    }

    OUT: return \%pcidevs;
}

# Starting with the hash table, indexed by pci bus address, generated
# by pci_find_ethdevs(), build a nested hash tables of pci ethernet
# devices indexed by slot (outer hash table) and then indexed by port
# (inner hash table).
sub index_by_slotport {
    my ($href) = @_;
    my %slothash = ();

    for my $busaddr (keys %$href) {
       my $slot = $href->{$busaddr}->{'slot'};
       my $port = $href->{$busaddr}->{'port'};

       if ( !exists $slothash{$slot} ) {
           my %porthash = ();

           $slothash{$slot} = \%porthash;
       }
       $slothash{$slot}->{$port} = $href->{$busaddr};
    }
    return \%slothash;
}

# need a third interface type?  collection?
sub is_collector_monitor_device {
    my ($dinfo) = @_;

    # For a collector, any PCI expansion card that is an intel x710 or
    # i350 is used to collect flow records from a sensor.

    if ( ! $dinfo->{'vendor'} eq $PCI_VENDOR_INTEL ) {
        # all monitor devices are either intel or napatech
        return;
    }

    if ( defined $dinfo->{'acpi_index'} ) {
        if ( $dinfo->{'device'} eq $PCI_DEVICE_INTEL_I350 ) {
            return;
        }
    }

    if ( ! ( $dinfo->{'device'} eq ${PCI_DEVICE_INTEL_I350} ||
             $dinfo->{'device'} eq ${PCI_DEVICE_INTEL_X710} ) ) {
        return;
    }

    return 1;
}

sub is_sensor_monitor_device {
    my ($dinfo) = @_;

    # All on-board devices are used for management by sensor.
    # Check for acpi index.
    if ( defined $dinfo->{'acpi_index'} ) {
        return;
    }

    if ( ! $dinfo->{'vendor'} eq $PCI_VENDOR_INTEL ) {
        # all monitor devices are either intel or napatech
        return;
    }

    if ( $dinfo->{'device'} eq $PCI_DEVICE_INTEL_X710 ) {
        # This device is used for direct connection to collector
        return;
    }

    return 1;
}

# find_monitor_ethdevs:
# returns an array of array references.  Each reference points to a
# result from device_info().
sub find_monitor_ethdevs {
    my ($pcidevs, $systypename) = @_;
    my @meds = [];
    my $is_sensor_appliance = 0;

    if ( $systypename eq 'sensor' ) {
        $is_sensor_appliance = 1;
    }

    for my $busaddr (keys %$pcidevs) {
        my $dinfo = $pcidevs->{$busaddr};

        if ( $is_sensor_appliance ) {
            if (is_sensor_monitor_ethdev($dinfo)) {
                push @meds, $dinfo;
            }
        } else {
            if (is_collector_monitor_ethdev($dinfo)) {
                push @meds, $dinfo;
            }
        }
    }

    return @meds;
}

# Example:
# my $href = index_by_slotport(find_pci_ethdevs());
# print Dumper($href);

1;
