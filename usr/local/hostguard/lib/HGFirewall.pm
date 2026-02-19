package HGFirewall;
###############################################################################
# HostGuard Pro - Firewall Engine Module
# /usr/local/hostguard/lib/HGFirewall.pm
#
# Manages iptables/ip6tables rules with ipset for performance.
# Supports stateful rules, allowlist/denylist, port filtering, and
# connection limits. Auto-detects nftables and falls back if needed.
###############################################################################
use strict;
use warnings;
use HGConfig;
use HGLogger;

my $IPTABLES;
my $IP6TABLES;
my $IPSET;
my $USE_IPSET;
my $IPV6;

# Chain names
my $CHAIN_IN       = "HOSTGUARD_IN";
my $CHAIN_OUT      = "HOSTGUARD_OUT";
my $CHAIN_DENY     = "HOSTGUARD_DENY";
my $CHAIN_ALLOW    = "HOSTGUARD_ALLOW";
my $CHAIN_LOGDROP  = "HOSTGUARD_LOGDROP";
my $CHAIN6_IN      = "HOSTGUARD6_IN";
my $CHAIN6_OUT     = "HOSTGUARD6_OUT";
my $CHAIN6_DENY    = "HOSTGUARD6_DENY";
my $CHAIN6_ALLOW   = "HOSTGUARD6_ALLOW";

# ipset set names
my $SET_ALLOW4  = "hg_allow4";
my $SET_DENY4   = "hg_deny4";
my $SET_TEMP4   = "hg_tempblock4";
my $SET_ALLOW6  = "hg_allow6";
my $SET_DENY6   = "hg_deny6";
my $SET_TEMP6   = "hg_tempblock6";

###############################################################################
# Initialization
###############################################################################

sub init {
    my ($class, $config) = @_;

    $IPTABLES  = $config->get('IPTABLES')  || _find_bin('iptables');
    $IP6TABLES = $config->get('IP6TABLES') || _find_bin('ip6tables');
    $IPSET     = $config->get('IPSET')     || _find_bin('ipset');
    $USE_IPSET = ($config->get('LF_IPSET') // 1) && $IPSET;
    $IPV6      = $config->get('IPV6') // 0;

    unless ($IPTABLES && -x $IPTABLES) {
        die "FATAL: iptables not found. Cannot start firewall.\n";
    }

    HGLogger->info("Firewall engine initialized: iptables=$IPTABLES ipset=" .
                    ($USE_IPSET ? $IPSET : "disabled") .
                    " ipv6=" . ($IPV6 ? "yes" : "no"));
    return 1;
}

sub _find_bin {
    my ($name) = @_;
    for my $dir ('/usr/sbin', '/sbin', '/usr/bin', '/bin', '/usr/local/sbin') {
        return "$dir/$name" if -x "$dir/$name";
    }
    return "";
}

###############################################################################
# High-level operations
###############################################################################

sub start {
    my ($class, $config) = @_;

    $class->init($config);

    my $lock = HGConfig->get_lock('firewall');

    HGLogger->info("Starting HostGuard Pro firewall...");

    # Run pre-script if configured
    my $pre = $config->get('PRE_SCRIPT');
    if ($pre && -x $pre) {
        HGLogger->info("Running pre-script: $pre");
        system($pre);
    }

    # Flush existing rules
    $class->_flush_chains();

    # Create ipsets
    $class->_setup_ipsets() if $USE_IPSET;

    # Build rules
    $class->_build_rules($config);

    # Build IPv6 rules if enabled
    $class->_build_rules6($config) if $IPV6;

    # Load allowlist/denylist into ipsets or chains
    $class->_load_allowlist($config);
    $class->_load_denylist($config);
    $class->_load_tempblocks();

    # Connection limits
    $class->_apply_connlimits($config);
    $class->_apply_portflood($config);
    $class->_apply_synflood($config);

    # Run post-script if configured
    my $post = $config->get('POST_SCRIPT');
    if ($post && -x $post) {
        HGLogger->info("Running post-script: $post");
        system($post);
    }

    # Record start time
    _write_file("$HGConfig::DATA_DIR/firewall.started", time());

    HGLogger->info("HostGuard Pro firewall started successfully.");
    close($lock);
    return 1;
}

sub stop {
    my ($class) = @_;
    HGLogger->info("Stopping HostGuard Pro firewall...");

    my $lock = HGConfig->get_lock('firewall');

    # Flush all our chains
    $class->_flush_chains();

    # Destroy ipsets
    $class->_destroy_ipsets() if $USE_IPSET;

    # Reset default policies to ACCEPT
    _run("$IPTABLES -P INPUT ACCEPT");
    _run("$IPTABLES -P OUTPUT ACCEPT");
    _run("$IPTABLES -P FORWARD ACCEPT");

    if ($IPV6 && $IP6TABLES) {
        _run("$IP6TABLES -P INPUT ACCEPT");
        _run("$IP6TABLES -P OUTPUT ACCEPT");
        _run("$IP6TABLES -P FORWARD ACCEPT");
    }

    unlink("$HGConfig::DATA_DIR/firewall.started");
    HGLogger->info("HostGuard Pro firewall stopped.");
    close($lock);
    return 1;
}

sub reload {
    my ($class, $config) = @_;
    HGLogger->info("Reloading HostGuard Pro firewall rules...");
    $class->stop();
    $class->start($config);
    return 1;
}

sub status {
    my ($class) = @_;
    my $started_file = "$HGConfig::DATA_DIR/firewall.started";
    if (-f $started_file) {
        open(my $fh, '<', $started_file);
        my $ts = <$fh>;
        close($fh);
        chomp $ts if $ts;
        return { running => 1, since => $ts };
    }
    return { running => 0 };
}

###############################################################################
# ipset management
###############################################################################

sub _setup_ipsets {
    # Destroy existing sets first (ignore errors)
    for my $set ($SET_ALLOW4, $SET_DENY4, $SET_TEMP4) {
        _run("$IPSET destroy $set 2>/dev/null", 1);
        _run("$IPSET create $set hash:net family inet hashsize 4096 maxelem 1000000");
    }
    if ($IPV6) {
        for my $set ($SET_ALLOW6, $SET_DENY6, $SET_TEMP6) {
            _run("$IPSET destroy $set 2>/dev/null", 1);
            _run("$IPSET create $set hash:net family inet6 hashsize 4096 maxelem 1000000");
        }
    }
}

sub _destroy_ipsets {
    for my $set ($SET_ALLOW4, $SET_DENY4, $SET_TEMP4, $SET_ALLOW6, $SET_DENY6, $SET_TEMP6) {
        _run("$IPSET destroy $set 2>/dev/null", 1);
    }
}

###############################################################################
# Chain creation and flushing
###############################################################################

sub _flush_chains {
    # Remove jumps from built-in chains
    for my $chain ($CHAIN_IN, $CHAIN_OUT, $CHAIN_DENY, $CHAIN_ALLOW, $CHAIN_LOGDROP) {
        _run("$IPTABLES -D INPUT -j $chain 2>/dev/null", 1);
        _run("$IPTABLES -D OUTPUT -j $chain 2>/dev/null", 1);
        _run("$IPTABLES -F $chain 2>/dev/null", 1);
        _run("$IPTABLES -X $chain 2>/dev/null", 1);
    }

    if ($IPV6 && $IP6TABLES) {
        for my $chain ($CHAIN6_IN, $CHAIN6_OUT, $CHAIN6_DENY, $CHAIN6_ALLOW) {
            _run("$IP6TABLES -D INPUT -j $chain 2>/dev/null", 1);
            _run("$IP6TABLES -D OUTPUT -j $chain 2>/dev/null", 1);
            _run("$IP6TABLES -F $chain 2>/dev/null", 1);
            _run("$IP6TABLES -X $chain 2>/dev/null", 1);
        }
    }

    # Reset default policies to ACCEPT before rebuilding
    _run("$IPTABLES -P INPUT ACCEPT");
    _run("$IPTABLES -P OUTPUT ACCEPT");
    _run("$IPTABLES -P FORWARD DROP");
}

###############################################################################
# Rule building - IPv4
###############################################################################

sub _build_rules {
    my ($class, $config) = @_;
    my $spi        = $config->get('LF_SPI') // 1;
    my $drop       = $config->get('DROP_ACTION') // 'DROP';
    my $drop_log   = $config->get('DROP_LOGGING') // 1;
    my $conntrack  = $config->get('USE_CONNTRACK') // 1;
    my $state_mod  = $conntrack ? "conntrack --ctstate" : "state --state";
    my $icmp_in    = $config->get('ICMP_IN') // 1;
    my $icmp_out   = $config->get('ICMP_OUT') // 1;
    my $icmp_rate  = $config->get('ICMP_IN_RATE') // '1/s';
    my $eth        = $config->get('ETH_DEVICE') // '';
    my $eth_skip   = $config->get('ETH_DEVICE_SKIP') // '';
    my $iface      = $eth ? "-i $eth" : "";
    my $oface      = $eth ? "-o $eth" : "";

    # Create chains
    _run("$IPTABLES -N $CHAIN_IN");
    _run("$IPTABLES -N $CHAIN_OUT");
    _run("$IPTABLES -N $CHAIN_ALLOW");
    _run("$IPTABLES -N $CHAIN_DENY");
    _run("$IPTABLES -N $CHAIN_LOGDROP");

    # Log+drop chain
    if ($drop_log) {
        _run("$IPTABLES -A $CHAIN_LOGDROP -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix 'HG_DROP: ' --log-level 4");
    }
    _run("$IPTABLES -A $CHAIN_LOGDROP -j $drop");

    # Loopback - always allow
    _run("$IPTABLES -A $CHAIN_IN -i lo -j ACCEPT");
    _run("$IPTABLES -A $CHAIN_OUT -o lo -j ACCEPT");

    # Skip interfaces
    if ($eth_skip) {
        for my $dev (split(/,/, $eth_skip)) {
            $dev =~ s/\s//g;
            next unless $dev;
            _run("$IPTABLES -A $CHAIN_IN -i $dev -j ACCEPT");
            _run("$IPTABLES -A $CHAIN_OUT -o $dev -j ACCEPT");
        }
    }

    # Stateful rules
    if ($spi) {
        _run("$IPTABLES -A $CHAIN_IN $iface -m $state_mod ESTABLISHED,RELATED -j ACCEPT");
        _run("$IPTABLES -A $CHAIN_OUT $oface -m $state_mod ESTABLISHED,RELATED -j ACCEPT");
        # Drop invalid
        _run("$IPTABLES -A $CHAIN_IN $iface -m $state_mod INVALID -j $drop");
    }

    # Allowlist (checked before deny)
    if ($USE_IPSET) {
        _run("$IPTABLES -A $CHAIN_IN $iface -m set --match-set $SET_ALLOW4 src -j ACCEPT");
    }
    _run("$IPTABLES -A $CHAIN_IN -j $CHAIN_ALLOW");

    # Denylist
    if ($USE_IPSET) {
        _run("$IPTABLES -A $CHAIN_IN $iface -m set --match-set $SET_DENY4 src -j $CHAIN_LOGDROP");
        _run("$IPTABLES -A $CHAIN_IN $iface -m set --match-set $SET_TEMP4 src -j $CHAIN_LOGDROP");
    }
    _run("$IPTABLES -A $CHAIN_IN -j $CHAIN_DENY");

    # ICMP
    if ($icmp_in) {
        if ($icmp_rate && $icmp_rate ne '0') {
            _run("$IPTABLES -A $CHAIN_IN $iface -p icmp --icmp-type echo-request -m limit --limit $icmp_rate -j ACCEPT");
            _run("$IPTABLES -A $CHAIN_IN $iface -p icmp --icmp-type echo-request -j $drop");
        } else {
            _run("$IPTABLES -A $CHAIN_IN $iface -p icmp --icmp-type echo-request -j ACCEPT");
        }
    }

    # Open TCP incoming ports
    my $tcp_in = $config->get('TCP_IN') // '';
    for my $port (_parse_ports($tcp_in)) {
        _run("$IPTABLES -A $CHAIN_IN $iface -p tcp -m $state_mod NEW --dport $port -j ACCEPT");
    }

    # Open UDP incoming ports
    my $udp_in = $config->get('UDP_IN') // '';
    for my $port (_parse_ports($udp_in)) {
        _run("$IPTABLES -A $CHAIN_IN $iface -p udp --dport $port -j ACCEPT");
    }

    # Default drop inbound
    _run("$IPTABLES -A $CHAIN_IN -j $CHAIN_LOGDROP");

    # Outbound rules
    if ($spi) {
        # Open TCP outgoing ports
        my $tcp_out = $config->get('TCP_OUT') // '';
        for my $port (_parse_ports($tcp_out)) {
            _run("$IPTABLES -A $CHAIN_OUT $oface -p tcp -m $state_mod NEW --dport $port -j ACCEPT");
        }

        # Open UDP outgoing ports
        my $udp_out = $config->get('UDP_OUT') // '';
        for my $port (_parse_ports($udp_out)) {
            _run("$IPTABLES -A $CHAIN_OUT $oface -p udp --dport $port -j ACCEPT");
        }

        # ICMP outbound
        if ($icmp_out) {
            _run("$IPTABLES -A $CHAIN_OUT $oface -p icmp -j ACCEPT");
        }

        # Default drop outbound
        _run("$IPTABLES -A $CHAIN_OUT -j $CHAIN_LOGDROP");
    } else {
        # Non-SPI: allow all outbound
        _run("$IPTABLES -A $CHAIN_OUT -j ACCEPT");
    }

    # Insert our chains into INPUT/OUTPUT
    _run("$IPTABLES -I INPUT -j $CHAIN_IN");
    _run("$IPTABLES -I OUTPUT -j $CHAIN_OUT");

    HGLogger->info("IPv4 firewall rules applied.");
}

###############################################################################
# Rule building - IPv6
###############################################################################

sub _build_rules6 {
    my ($class, $config) = @_;

    return unless $IPV6 && $IP6TABLES;

    my $spi       = $config->get('IPV6_SPI') // 1;
    my $drop      = $config->get('DROP_ACTION') // 'DROP';
    my $conntrack = $config->get('USE_CONNTRACK') // 1;
    my $state_mod = $conntrack ? "conntrack --ctstate" : "state --state";

    # Create chains
    _run("$IP6TABLES -N $CHAIN6_IN");
    _run("$IP6TABLES -N $CHAIN6_OUT");
    _run("$IP6TABLES -N $CHAIN6_ALLOW");
    _run("$IP6TABLES -N $CHAIN6_DENY");

    # Loopback
    _run("$IP6TABLES -A $CHAIN6_IN -i lo -j ACCEPT");
    _run("$IP6TABLES -A $CHAIN6_OUT -o lo -j ACCEPT");

    # ICMPv6 - essential for IPv6
    _run("$IP6TABLES -A $CHAIN6_IN -p icmpv6 -j ACCEPT");
    _run("$IP6TABLES -A $CHAIN6_OUT -p icmpv6 -j ACCEPT");

    # Stateful
    if ($spi) {
        _run("$IP6TABLES -A $CHAIN6_IN -m $state_mod ESTABLISHED,RELATED -j ACCEPT");
        _run("$IP6TABLES -A $CHAIN6_OUT -m $state_mod ESTABLISHED,RELATED -j ACCEPT");
        _run("$IP6TABLES -A $CHAIN6_IN -m $state_mod INVALID -j $drop");
    }

    # Allowlist
    if ($USE_IPSET) {
        _run("$IP6TABLES -A $CHAIN6_IN -m set --match-set $SET_ALLOW6 src -j ACCEPT");
    }
    _run("$IP6TABLES -A $CHAIN6_IN -j $CHAIN6_ALLOW");

    # Denylist
    if ($USE_IPSET) {
        _run("$IP6TABLES -A $CHAIN6_IN -m set --match-set $SET_DENY6 src -j $drop");
        _run("$IP6TABLES -A $CHAIN6_IN -m set --match-set $SET_TEMP6 src -j $drop");
    }
    _run("$IP6TABLES -A $CHAIN6_IN -j $CHAIN6_DENY");

    # TCP6 incoming
    my $tcp6_in = $config->get('TCP6_IN') // '';
    for my $port (_parse_ports($tcp6_in)) {
        _run("$IP6TABLES -A $CHAIN6_IN -p tcp -m $state_mod NEW --dport $port -j ACCEPT");
    }

    # UDP6 incoming
    my $udp6_in = $config->get('UDP6_IN') // '';
    for my $port (_parse_ports($udp6_in)) {
        _run("$IP6TABLES -A $CHAIN6_IN -p udp --dport $port -j ACCEPT");
    }

    # Default drop inbound
    _run("$IP6TABLES -A $CHAIN6_IN -j $drop");

    # Outbound
    if ($spi) {
        my $tcp6_out = $config->get('TCP6_OUT') // '';
        for my $port (_parse_ports($tcp6_out)) {
            _run("$IP6TABLES -A $CHAIN6_OUT -p tcp -m $state_mod NEW --dport $port -j ACCEPT");
        }
        my $udp6_out = $config->get('UDP6_OUT') // '';
        for my $port (_parse_ports($udp6_out)) {
            _run("$IP6TABLES -A $CHAIN6_OUT -p udp --dport $port -j ACCEPT");
        }
        _run("$IP6TABLES -A $CHAIN6_OUT -j $drop");
    } else {
        _run("$IP6TABLES -A $CHAIN6_OUT -j ACCEPT");
    }

    # Insert into INPUT/OUTPUT
    _run("$IP6TABLES -I INPUT -j $CHAIN6_IN");
    _run("$IP6TABLES -I OUTPUT -j $CHAIN6_OUT");

    HGLogger->info("IPv6 firewall rules applied.");
}

###############################################################################
# Allowlist / Denylist loading
###############################################################################

sub _load_allowlist {
    my ($class, $config) = @_;
    my @entries = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/allow.conf");

    for my $entry (@entries) {
        my $ip = $entry->{ip};
        next if $ip =~ /\|/;    # skip advanced filters for ipset (handled by chain rules)

        if (HGConfig->valid_ipv4($ip)) {
            if ($USE_IPSET) {
                _run("$IPSET add $SET_ALLOW4 $ip 2>/dev/null", 1);
            } else {
                _run("$IPTABLES -A $CHAIN_ALLOW -s $ip -j ACCEPT");
            }
        } elsif ($IPV6 && HGConfig->valid_ipv6($ip)) {
            if ($USE_IPSET) {
                _run("$IPSET add $SET_ALLOW6 $ip 2>/dev/null", 1);
            } else {
                _run("$IP6TABLES -A $CHAIN6_ALLOW -s $ip -j ACCEPT") if $IP6TABLES;
            }
        }

        # Handle advanced filter lines (tcp|in|d=port|s=ip)
        if ($ip =~ /\|/) {
            $class->_apply_advanced_filter($ip, 'ACCEPT');
        }
    }

    HGLogger->info("Allowlist loaded: " . scalar(@entries) . " entries.");
}

sub _load_denylist {
    my ($class, $config) = @_;
    my @entries = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/deny.conf");
    my $drop    = $config->get('DROP_ACTION') // 'DROP';
    my $limit   = $config->get('DENY_IP_LIMIT') // 0;

    my $count = 0;
    for my $entry (@entries) {
        if ($limit > 0 && $count >= $limit) {
            # Check for "do not delete" entries
            next unless ($entry->{comment} // '') =~ /do not delete/i;
        }

        my $ip = $entry->{ip};
        next if $ip =~ /\|/;

        if (HGConfig->valid_ipv4($ip)) {
            if ($USE_IPSET) {
                _run("$IPSET add $SET_DENY4 $ip 2>/dev/null", 1);
            } else {
                _run("$IPTABLES -A $CHAIN_DENY -s $ip -j $CHAIN_LOGDROP");
            }
        } elsif ($IPV6 && HGConfig->valid_ipv6($ip)) {
            if ($USE_IPSET) {
                _run("$IPSET add $SET_DENY6 $ip 2>/dev/null", 1);
            } else {
                _run("$IP6TABLES -A $CHAIN6_DENY -s $ip -j $drop") if $IP6TABLES;
            }
        }

        if ($ip =~ /\|/) {
            $class->_apply_advanced_filter($ip, $CHAIN_LOGDROP);
        }

        $count++;
    }

    HGLogger->info("Denylist loaded: $count entries.");
}

sub _load_tempblocks {
    my ($class) = @_;
    my $tempfile = "$HGConfig::DATA_DIR/tempblock.dat";
    return unless -f $tempfile;

    open(my $fh, '<', $tempfile) or return;
    flock($fh, LOCK_SH);
    my $now = time();
    while (my $line = <$fh>) {
        chomp $line;
        my ($ip, $expires, $reason) = split(/\|/, $line, 3);
        next unless $ip && $expires;
        next if $expires <= $now;  # expired

        if (HGConfig->valid_ipv4($ip)) {
            if ($USE_IPSET) {
                my $ttl = $expires - $now;
                _run("$IPSET add $SET_TEMP4 $ip timeout $ttl 2>/dev/null", 1);
            } else {
                _run("$IPTABLES -A $CHAIN_DENY -s $ip -j $CHAIN_LOGDROP");
            }
        } elsif ($IPV6 && HGConfig->valid_ipv6($ip)) {
            if ($USE_IPSET) {
                my $ttl = $expires - $now;
                _run("$IPSET add $SET_TEMP6 $ip timeout $ttl 2>/dev/null", 1);
            }
        }
    }
    close($fh);
    HGLogger->info("Temporary blocks loaded.");
}

###############################################################################
# Advanced filter support (tcp|in|d=port|s=ip)
###############################################################################

sub _apply_advanced_filter {
    my ($class, $filter, $target) = @_;
    my @parts = split(/\|/, $filter);
    return unless scalar(@parts) >= 3;

    my $proto     = lc($parts[0]); # tcp or udp
    my $direction = lc($parts[1]); # in or out

    return unless $proto =~ /^(tcp|udp)$/;
    return unless $direction =~ /^(in|out)$/;

    my ($dport, $sport, $sip, $dip);
    for my $i (2 .. $#parts) {
        if ($parts[$i] =~ /^d=(\S+)/) { $dport = $1; }
        if ($parts[$i] =~ /^s=(\S+)/) {
            # Could be port or IP
            my $val = $1;
            if ($val =~ /^[\d,:]+$/) { $sport = $val; }
            else { $sip = $val; }
        }
    }
    # Re-parse for explicit ip/port designators
    for my $i (2 .. $#parts) {
        if ($parts[$i] =~ /^s=(.+)/ && ($1 =~ /\./ || $1 =~ /:/)) { $sip = $1; }
        if ($parts[$i] =~ /^d=(.+)/ && $1 =~ /^\d[\d,:]*$/) { $dport = $1; }
    }

    my $chain = $direction eq 'in' ? $CHAIN_IN : $CHAIN_OUT;
    my $cmd   = "$IPTABLES -I $chain -p $proto";
    $cmd .= " -s $sip" if $sip;
    $cmd .= " --dport $dport" if $dport;
    $cmd .= " -j $target";

    _run($cmd);
}

###############################################################################
# Connection limits and flood protection
###############################################################################

sub _apply_connlimits {
    my ($class, $config) = @_;
    my $connlimit = $config->get('CONNLIMIT') // '';
    return unless $connlimit;

    for my $rule (split(/,/, $connlimit)) {
        my ($port, $limit) = split(/;/, $rule, 2);
        next unless $port && $limit;
        $port =~ s/\s//g;
        $limit =~ s/\s//g;
        next unless $port =~ /^\d+$/ && $limit =~ /^\d+$/;

        _run("$IPTABLES -I $CHAIN_IN -p tcp --syn --dport $port -m connlimit --connlimit-above $limit -j DROP");
        HGLogger->info("Connection limit: port $port max $limit connections/IP");
    }
}

sub _apply_portflood {
    my ($class, $config) = @_;
    my $portflood = $config->get('PORTFLOOD') // '';
    return unless $portflood;

    for my $rule (split(/,/, $portflood)) {
        my ($port, $hits, $interval, $proto) = split(/;/, $rule, 4);
        next unless $port && $hits && $interval;
        $proto //= 'tcp';
        $port =~ s/\s//g;
        $hits =~ s/\s//g;
        $interval =~ s/\s//g;
        $proto =~ s/\s//g;

        _run("$IPTABLES -I $CHAIN_IN -p $proto --dport $port -m $proto -m hashlimit --hashlimit-above $hits/$interval" . "s --hashlimit-mode srcip --hashlimit-name hg_flood_$port -j DROP");
        HGLogger->info("Port flood protection: $proto/$port max $hits per ${interval}s");
    }
}

sub _apply_synflood {
    my ($class, $config) = @_;
    my $synflood = $config->get('SYNFLOOD') // 0;
    return unless $synflood;

    my $rate  = $config->get('SYNFLOOD_RATE')  // '100/s';
    my $burst = $config->get('SYNFLOOD_BURST') // '150';

    _run("$IPTABLES -I $CHAIN_IN -p tcp --syn -m limit --limit $rate --limit-burst $burst -j ACCEPT");
    _run("$IPTABLES -I $CHAIN_IN -p tcp --syn -j DROP");
    HGLogger->info("SYN flood protection enabled: rate=$rate burst=$burst");
}

###############################################################################
# Runtime block/unblock operations
###############################################################################

# Temporarily block an IP with a TTL
sub tempblock {
    my ($class, $ip, $duration, $reason) = @_;

    # Validate
    unless (HGConfig->valid_ip($ip)) {
        HGLogger->error("tempblock: Invalid IP: $ip");
        return 0;
    }

    # Check allowlist first
    my @allow = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/allow.conf");
    if (HGConfig->ip_in_list($ip, @allow)) {
        HGLogger->info("tempblock: Skipping allowed IP $ip");
        return 0;
    }

    # Check ignore list
    my @ignore = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/ignore.conf");
    if (HGConfig->ip_in_list($ip, @ignore)) {
        HGLogger->info("tempblock: Skipping ignored IP $ip");
        return 0;
    }

    $duration //= 3600;
    $reason   //= "Manual block";
    my $expires = time() + $duration;

    # Add to ipset with timeout
    if ($USE_IPSET) {
        if (HGConfig->valid_ipv4($ip)) {
            _run("$IPSET add $SET_TEMP4 $ip timeout $duration -exist");
        } elsif (HGConfig->valid_ipv6($ip)) {
            _run("$IPSET add $SET_TEMP6 $ip timeout $duration -exist");
        }
    } else {
        if (HGConfig->valid_ipv4($ip)) {
            _run("$IPTABLES -I $CHAIN_DENY -s $ip -j $CHAIN_LOGDROP");
        }
    }

    # Record in tempblock file
    _append_tempblock($ip, $expires, $reason);

    HGLogger->info("Temporary block: $ip for ${duration}s - $reason");

    # Call block report hook if configured
    my $config = HGConfig->loadconfig();
    my $hook = $config->get('BLOCK_REPORT');
    if ($hook && -x $hook) {
        # Sanitize arguments - only pass validated IP
        system($hook, $ip, $reason, $duration);
    }

    return 1;
}

# Permanently block an IP (add to deny list)
sub permblock {
    my ($class, $ip, $reason) = @_;

    unless (HGConfig->valid_ip($ip)) {
        HGLogger->error("permblock: Invalid IP: $ip");
        return 0;
    }

    my @allow = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/allow.conf");
    if (HGConfig->ip_in_list($ip, @allow)) {
        HGLogger->info("permblock: Skipping allowed IP $ip");
        return 0;
    }

    $reason //= "Permanent block";

    # Add to deny.conf
    open(my $fh, '>>', "$HGConfig::CONFIG_DIR/deny.conf")
        or die "Cannot append to deny.conf: $!\n";
    flock($fh, LOCK_EX);
    print $fh "$ip # $reason - " . localtime() . "\n";
    close($fh);

    # Add to ipset/iptables immediately
    if ($USE_IPSET && HGConfig->valid_ipv4($ip)) {
        _run("$IPSET add $SET_DENY4 $ip -exist");
    } elsif ($USE_IPSET && HGConfig->valid_ipv6($ip)) {
        _run("$IPSET add $SET_DENY6 $ip -exist");
    } else {
        _run("$IPTABLES -I $CHAIN_DENY -s $ip -j $CHAIN_LOGDROP") if HGConfig->valid_ipv4($ip);
    }

    HGLogger->info("Permanent block: $ip - $reason");
    return 1;
}

# Allow an IP (add to allow list)
sub allow {
    my ($class, $ip, $comment) = @_;

    unless (HGConfig->valid_ip($ip)) {
        HGLogger->error("allow: Invalid IP: $ip");
        return 0;
    }

    $comment //= "Manual allow";

    # Add to allow.conf
    open(my $fh, '>>', "$HGConfig::CONFIG_DIR/allow.conf")
        or die "Cannot append to allow.conf: $!\n";
    flock($fh, LOCK_EX);
    print $fh "$ip # $comment - " . localtime() . "\n";
    close($fh);

    # Add to ipset/iptables immediately
    if ($USE_IPSET && HGConfig->valid_ipv4($ip)) {
        _run("$IPSET add $SET_ALLOW4 $ip -exist");
    } elsif ($USE_IPSET && HGConfig->valid_ipv6($ip)) {
        _run("$IPSET add $SET_ALLOW6 $ip -exist");
    } else {
        _run("$IPTABLES -I $CHAIN_ALLOW -s $ip -j ACCEPT") if HGConfig->valid_ipv4($ip);
    }

    # Also remove from temp blocks if present
    $class->tempunblock($ip);

    HGLogger->info("Allowed IP: $ip - $comment");
    return 1;
}

# Remove a temporary block
sub tempunblock {
    my ($class, $ip) = @_;

    unless (HGConfig->valid_ip($ip)) {
        HGLogger->error("tempunblock: Invalid IP: $ip");
        return 0;
    }

    # Remove from ipset
    if ($USE_IPSET) {
        if (HGConfig->valid_ipv4($ip)) {
            _run("$IPSET del $SET_TEMP4 $ip 2>/dev/null", 1);
        } elsif (HGConfig->valid_ipv6($ip)) {
            _run("$IPSET del $SET_TEMP6 $ip 2>/dev/null", 1);
        }
    } else {
        _run("$IPTABLES -D $CHAIN_DENY -s $ip -j $CHAIN_LOGDROP 2>/dev/null", 1) if HGConfig->valid_ipv4($ip);
    }

    # Remove from tempblock file
    _remove_tempblock($ip);

    HGLogger->info("Temporary unblock: $ip");
    return 1;
}

# Search for an IP in all rules and lists
sub grep_ip {
    my ($class, $ip) = @_;
    my @results;

    # Check allow.conf
    my @allow = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/allow.conf");
    for my $e (@allow) {
        if ($e->{ip} eq $ip || HGConfig->ip_in_cidr($ip, $e->{ip})) {
            push @results, "ALLOW: $e->{ip}" . ($e->{comment} ? " # $e->{comment}" : "");
        }
    }

    # Check deny.conf
    my @deny = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/deny.conf");
    for my $e (@deny) {
        if ($e->{ip} eq $ip || HGConfig->ip_in_cidr($ip, $e->{ip})) {
            push @results, "DENY: $e->{ip}" . ($e->{comment} ? " # $e->{comment}" : "");
        }
    }

    # Check ignore.conf
    my @ignore = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/ignore.conf");
    for my $e (@ignore) {
        if ($e->{ip} eq $ip || HGConfig->ip_in_cidr($ip, $e->{ip})) {
            push @results, "IGNORE: $e->{ip}" . ($e->{comment} ? " # $e->{comment}" : "");
        }
    }

    # Check temp blocks
    my @temp = $class->list_tempblocks();
    for my $t (@temp) {
        if ($t->{ip} eq $ip) {
            push @results, "TEMPBLOCK: $t->{ip} expires=$t->{expires} reason=$t->{reason}";
        }
    }

    # Check iptables
    my $ipt_out = `$IPTABLES -L -n 2>/dev/null | grep -w '$ip'`;
    if ($ipt_out) {
        for my $line (split(/\n/, $ipt_out)) {
            push @results, "IPTABLES: $line";
        }
    }

    return @results;
}

# List all temporary blocks
sub list_tempblocks {
    my ($class) = @_;
    my @blocks;
    my $tempfile = "$HGConfig::DATA_DIR/tempblock.dat";
    return @blocks unless -f $tempfile;

    open(my $fh, '<', $tempfile) or return @blocks;
    flock($fh, LOCK_SH);
    my $now = time();
    while (my $line = <$fh>) {
        chomp $line;
        my ($ip, $expires, $reason) = split(/\|/, $line, 3);
        next unless $ip && $expires;
        push @blocks, {
            ip      => $ip,
            expires => $expires,
            reason  => $reason // "",
            active  => ($expires > $now ? 1 : 0),
            ttl     => ($expires > $now ? $expires - $now : 0),
        };
    }
    close($fh);
    return @blocks;
}

###############################################################################
# Temp block file management
###############################################################################

sub _append_tempblock {
    my ($ip, $expires, $reason) = @_;
    my $tempfile = "$HGConfig::DATA_DIR/tempblock.dat";

    # Remove existing entry for this IP first
    _remove_tempblock($ip);

    open(my $fh, '>>', $tempfile) or die "Cannot append to tempblock.dat: $!\n";
    flock($fh, LOCK_EX);
    print $fh "$ip|$expires|$reason\n";
    close($fh);
}

sub _remove_tempblock {
    my ($ip) = @_;
    my $tempfile = "$HGConfig::DATA_DIR/tempblock.dat";
    return unless -f $tempfile;

    open(my $fh, '<', $tempfile) or return;
    flock($fh, LOCK_SH);
    my @lines = <$fh>;
    close($fh);

    open(my $wfh, '>', $tempfile) or return;
    flock($wfh, LOCK_EX);
    for my $line (@lines) {
        my ($lip) = split(/\|/, $line, 2);
        next if $lip eq $ip;
        print $wfh $line;
    }
    close($wfh);
}

# Clean up expired temp blocks from the data file
sub cleanup_expired {
    my ($class) = @_;
    my $tempfile = "$HGConfig::DATA_DIR/tempblock.dat";
    return unless -f $tempfile;

    open(my $fh, '<', $tempfile) or return;
    flock($fh, LOCK_SH);
    my @lines = <$fh>;
    close($fh);

    my $now = time();
    my @kept;
    for my $line (@lines) {
        chomp $line;
        my ($ip, $expires) = split(/\|/, $line, 3);
        if ($expires > $now) {
            push @kept, "$line\n";
        } else {
            HGLogger->info("Expired temp block removed: $ip");
        }
    }

    open(my $wfh, '>', $tempfile) or return;
    flock($wfh, LOCK_EX);
    print $wfh @kept;
    close($wfh);
}

###############################################################################
# Helpers
###############################################################################

sub _parse_ports {
    my ($portstr) = @_;
    return () unless $portstr;
    my @ports;
    for my $p (split(/,/, $portstr)) {
        $p =~ s/\s//g;
        next unless $p;
        # Convert colon ranges to iptables format
        $p =~ s/:/-/ if $p =~ /^\d+:\d+$/;
        # Revert - we keep colon for iptables multiport but individual rules use --dport
        # Actually iptables uses : for ranges in --dport
        $p =~ s/-/:/;
        push @ports, $p;
    }
    return @ports;
}

sub _run {
    my ($cmd, $ignore_error) = @_;
    HGLogger->debug("RUN: $cmd");
    my $out = `$cmd 2>&1`;
    my $rc  = $? >> 8;
    if ($rc && !$ignore_error) {
        HGLogger->error("Command failed (rc=$rc): $cmd\n  Output: $out");
    }
    return ($rc, $out);
}

sub _write_file {
    my ($file, $content) = @_;
    open(my $fh, '>', $file) or die "Cannot write $file: $!\n";
    print $fh $content;
    close($fh);
}

use Fcntl qw(:flock);

1;
