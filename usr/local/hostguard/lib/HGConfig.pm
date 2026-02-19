package HGConfig;
###############################################################################
# HostGuard Pro - Configuration Parser Module
# /usr/local/hostguard/lib/HGConfig.pm
###############################################################################
use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock);

our $CONFIG_DIR = "/etc/hostguard";
our $DATA_DIR   = "/var/lib/hostguard";
our $LOG_DIR    = "/var/log/hostguard";
our $LIB_DIR    = "/usr/local/hostguard/lib";
our $BIN_DIR    = "/usr/local/hostguard/bin";
our $VERSION    = "1.0.0";

# Load main configuration file
sub loadconfig {
    my ($class, $file) = @_;
    $file //= "$CONFIG_DIR/hostguard.conf";

    my %config;
    open(my $fh, '<', $file) or die "Cannot open config $file: $!\n";
    flock($fh, LOCK_SH);
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/\s*#.*$// unless $line =~ /^#/;
        next if $line =~ /^\s*#/ || $line =~ /^\s*$/;
        if ($line =~ /^\s*(\w+)\s*=\s*"([^"]*)"\s*$/) {
            $config{$1} = $2;
        } elsif ($line =~ /^\s*(\w+)\s*=\s*'([^']*)'\s*$/) {
            $config{$1} = $2;
        } elsif ($line =~ /^\s*(\w+)\s*=\s*(\S+)\s*$/) {
            $config{$1} = $2;
        }
    }
    close($fh);

    return bless { config => \%config, file => $file }, $class;
}

# Get a config value
sub get {
    my ($self, $key) = @_;
    return $self->{config}{$key};
}

# Get entire config hash
sub config {
    my ($self) = @_;
    return %{$self->{config}};
}

# Save a config value back to file
sub set {
    my ($self, $key, $value) = @_;
    $self->{config}{$key} = $value;

    my $file = $self->{file};
    open(my $fh, '<', $file) or die "Cannot read config: $!\n";
    flock($fh, LOCK_SH);
    my @lines = <$fh>;
    close($fh);

    my $found = 0;
    for my $line (@lines) {
        if ($line =~ /^\s*\Q$key\E\s*=/) {
            $line = "$key = \"$value\"\n";
            $found = 1;
            last;
        }
    }
    push @lines, "$key = \"$value\"\n" unless $found;

    open(my $wfh, '>', $file) or die "Cannot write config: $!\n";
    flock($wfh, LOCK_EX);
    print $wfh @lines;
    close($wfh);
}

# Load an IP list file (allow, deny, ignore) with Include support
sub load_iplist {
    my ($class, $file, $seen) = @_;
    $seen //= {};

    # Prevent include loops
    return () if $seen->{$file};
    $seen->{$file} = 1;

    my @entries;
    return @entries unless -f $file;

    open(my $fh, '<', $file) or do {
        warn "Cannot open $file: $!\n";
        return @entries;
    };
    flock($fh, LOCK_SH);
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;

        # Skip blanks and pure comments
        next if $line =~ /^\s*$/ || $line =~ /^\s*#/;

        # Handle Include directives
        if ($line =~ /^Include\s+(.+)$/i) {
            my $inc_file = $1;
            $inc_file =~ s/\s+$//;
            push @entries, $class->load_iplist($inc_file, $seen);
            next;
        }

        # Extract IP/CIDR (strip inline comment)
        my ($entry, $comment) = split(/\s*#\s*/, $line, 2);
        $entry =~ s/\s+$//;
        $comment //= "";

        next unless $entry;
        push @entries, { ip => $entry, comment => $comment, raw => $line };
    }
    close($fh);

    return @entries;
}

# Write an IP list file
sub save_iplist {
    my ($class, $file, $header, @entries) = @_;

    open(my $fh, '>', $file) or die "Cannot write $file: $!\n";
    flock($fh, LOCK_EX);
    print $fh $header if $header;
    for my $entry (@entries) {
        if (ref $entry eq 'HASH') {
            if ($entry->{comment}) {
                print $fh "$entry->{ip} # $entry->{comment}\n";
            } else {
                print $fh "$entry->{ip}\n";
            }
        } else {
            print $fh "$entry\n";
        }
    }
    close($fh);
}

# Validate an IPv4 address
sub valid_ipv4 {
    my ($class, $ip) = @_;
    return 0 unless defined $ip;
    # Strip CIDR
    my ($addr, $cidr) = split(/\//, $ip, 2);
    return 0 unless $addr =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    return 0 if $1 > 255 || $2 > 255 || $3 > 255 || $4 > 255;
    if (defined $cidr) {
        return 0 unless $cidr =~ /^\d{1,2}$/;
        return 0 if $cidr > 32;
    }
    return 1;
}

# Validate an IPv6 address (simplified check)
sub valid_ipv6 {
    my ($class, $ip) = @_;
    return 0 unless defined $ip;
    my ($addr, $cidr) = split(/\//, $ip, 2);
    return 0 unless $addr =~ /^[0-9a-fA-F:]+$/;
    return 0 unless $addr =~ /:/;
    if (defined $cidr) {
        return 0 unless $cidr =~ /^\d{1,3}$/;
        return 0 if $cidr > 128;
    }
    return 1;
}

# Validate an IP (v4 or v6)
sub valid_ip {
    my ($class, $ip) = @_;
    return $class->valid_ipv4($ip) || $class->valid_ipv6($ip);
}

# Validate port list string
sub valid_ports {
    my ($class, $ports) = @_;
    return 1 if !defined $ports || $ports eq '';
    for my $p (split(/,/, $ports)) {
        $p =~ s/\s//g;
        if ($p =~ /^(\d+):(\d+)$/) {
            return 0 if $1 > 65535 || $2 > 65535 || $1 > $2;
        } elsif ($p =~ /^\d+$/) {
            return 0 if $p > 65535;
        } else {
            return 0;
        }
    }
    return 1;
}

# Check if an IP is in a list (supports CIDR matching)
sub ip_in_list {
    my ($class, $ip, @list) = @_;
    for my $entry (@list) {
        my $check = ref $entry eq 'HASH' ? $entry->{ip} : $entry;
        # Handle advanced filter format
        next if $check =~ /\|/;
        if ($check =~ /\//) {
            return 1 if $class->ip_in_cidr($ip, $check);
        } else {
            return 1 if $ip eq $check;
        }
    }
    return 0;
}

# Check if IP is within a CIDR range (IPv4 only for now)
sub ip_in_cidr {
    my ($class, $ip, $cidr) = @_;
    return 0 unless $class->valid_ipv4($ip);

    my ($net, $bits) = split(/\//, $cidr, 2);
    $bits //= 32;

    my $ip_n   = _ip4_to_int($ip);
    my $net_n  = _ip4_to_int($net);
    my $mask_n = $bits == 0 ? 0 : (~0 << (32 - $bits)) & 0xFFFFFFFF;

    return ($ip_n & $mask_n) == ($net_n & $mask_n) ? 1 : 0;
}

sub _ip4_to_int {
    my ($ip) = @_;
    my @octets = split(/\./, $ip);
    return ($octets[0] << 24) + ($octets[1] << 16) + ($octets[2] << 8) + $octets[3];
}

# Get lock for exclusive operations
sub get_lock {
    my ($class, $name) = @_;
    my $lockfile = "$DATA_DIR/$name.lock";
    open(my $fh, '>', $lockfile) or die "Cannot create lock $lockfile: $!\n";
    flock($fh, LOCK_EX | LOCK_NB) or die "Cannot acquire lock $lockfile (another instance running?)\n";
    return $fh;
}

1;
