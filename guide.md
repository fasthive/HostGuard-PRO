# HostGuard Pro - Administrator Guide

## Installation

### Prerequisites
- AlmaLinux 8/9, Rocky Linux 8/9, or CentOS 7/8 with cPanel/WHM
- Root SSH access
- iptables installed (standard on all supported OS)
- Perl 5.16+ (included with cPanel)

### Install Steps
```bash
cd /usr/src
git clone https://github.com/fasthive/HostGuard-PRO.git hostguard-pro
cd hostguard-pro
bash install.sh
```

The installer will:
1. Run compatibility checks (iptables, ipset, Perl)
2. Create all directories and install files
3. Install systemd services
4. Auto-detect server IPs and add them to the allowlist/ignorelist
5. Auto-detect the admin's SSH IP and add it to the allowlist
6. Register the WHM plugin (if cPanel is present)
7. Install with TESTING=1 (safe mode) by default

### First Start
```bash
# Start the firewall (TESTING mode auto-clears rules every 5 min)
systemctl start hostguard

# Verify you can still SSH in, then disable testing mode:
vi /etc/hostguard/hostguard.conf
# Change: TESTING = "0"

# Reload and start daemon
hostguard -r
systemctl start hostguardd
```

## Configuring Ports

Edit `/etc/hostguard/hostguard.conf`:

```
# Allow incoming TCP ports (comma-separated, ranges with colon)
TCP_IN = "20,21,22,25,53,80,110,143,443,465,587,993,995,2082,2083,2086,2087,2095,2096,8443"

# Allow outgoing TCP ports
TCP_OUT = "20,21,22,25,37,43,53,80,110,113,443,587,873,993,995,2086,2087,2089"

# Allow incoming UDP ports
UDP_IN = "20,21,53,80,443"

# Allow outgoing UDP ports
UDP_OUT = "20,21,53,113,123,873,6277"
```

After changing ports, reload the firewall:
```bash
hostguard -r
```

### Common Port Additions
- **Custom SSH port**: Change `SSH_PORT` and add to `TCP_IN`
- **Mail**: Ports 25, 465, 587, 993, 995 (included by default)
- **DNS**: Port 53 TCP/UDP (included by default)
- **Game servers**: Add custom ports to `TCP_IN`/`UDP_IN`

## How Blocking Works

### Login Failure Detection
The daemon (`hostguardd`) continuously monitors log files for authentication failures:

| Service | Log File | Config Key |
|---------|----------|------------|
| SSH | /var/log/secure | LF_SSHD |
| FTP | /var/log/messages | LF_FTPD |
| POP3 | /var/log/maillog | LF_POP3D |
| IMAP | /var/log/maillog | LF_IMAPD |
| SMTP AUTH | /var/log/maillog | LF_SMTPAUTH |
| cPanel/WHM | /usr/local/cpanel/logs/login_log | LF_CPANEL |

### Blocking Flow
1. Daemon detects failed login attempt and records the source IP
2. If failures from one IP exceed the threshold within `LF_INTERVAL` seconds:
   - IP is temporarily blocked for `LF_TEMP_BLOCK_DURATION` seconds
   - Block is added to ipset (instant, kernel-level blocking)
3. If the same IP gets temp-blocked `LF_PERM_BLOCK_AFTER` times:
   - IP is promoted to permanent block (added to deny.conf)
4. Allowlisted IPs are never blocked
5. Ignored IPs are never auto-blocked by the daemon

### Cross-Protocol Aggregation
When `LF_GLOBAL_THRESHOLD = "1"`, failures across all services count toward a single limit (`LF_GLOBAL_LIMIT`). An attacker trying SSH, then FTP, then SMTP AUTH will hit the combined limit faster.

## Lockout Recovery

### If you get locked out

**Method 1: TESTING mode (preventive)**
TESTING=1 is on by default. The firewall auto-clears every `TESTING_INTERVAL` minutes. Wait for the cron to fire, then SSH back in.

**Method 2: Console/IPMI/KVM access**
```bash
# Disable firewall immediately
hostguard -x

# Or flush iptables directly
iptables -F
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
```

**Method 3: From WHM (if web access works)**
Navigate to WHM > HostGuard Pro > Services > Stop Firewall

**Method 4: Via cPanel's Terminal**
If you can access WHM's built-in terminal, run:
```bash
hostguard -x
```

**Method 5: Reboot with init override**
If nothing else works, reboot and in the GRUB menu add `init=/bin/bash`, then:
```bash
mount -o remount,rw /
iptables -F
systemctl disable hostguard hostguardd
```

### Prevention Tips
- Always keep your own IP in the allowlist
- Use TESTING mode when making changes
- Test SSH access from a second terminal before closing your current session

## Managing Allow/Deny/Ignore Lists

### Via CLI
```bash
# Allow an IP
hostguard -a 203.0.113.10 "Office IP"

# Deny an IP
hostguard -d 198.51.100.50 "Known attacker"

# Remove a temporary block
hostguard -tr 192.0.2.100

# Search for an IP
hostguard -g 10.0.0.1

# List all temporary blocks
hostguard -l
```

### Via WHM
Navigate to WHM > HostGuard Pro > Allowlist/Denylist/Ignore List

### File Format
Edit files directly: `/etc/hostguard/allow.conf`, `deny.conf`, `ignore.conf`
```
# One IP/CIDR per line, optional comment after #
192.168.1.100        # Office network
10.0.0.0/8           # Internal
203.0.113.0/24       # Partner network - do not delete

# Include external files
Include /etc/hostguard/custom_allow.conf

# Advanced filter (allow SSH only from specific IP)
tcp|in|d=22|s=10.0.0.5
```

After editing files manually, reload the firewall:
```bash
hostguard -r
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `hostguard -e` | Enable/start firewall |
| `hostguard -x` | Disable/stop firewall |
| `hostguard -r` | Reload firewall rules |
| `hostguard -s` | Show status |
| `hostguard -a <ip> [note]` | Allow IP |
| `hostguard -d <ip> [note]` | Deny IP permanently |
| `hostguard -tr <ip>` | Remove temporary block |
| `hostguard -g <ip>` | Search for IP in all lists |
| `hostguard -l` | List active temp blocks |
| `hostguard --start-daemon` | Start the daemon |
| `hostguard --stop-daemon` | Stop the daemon |
| `hostguard --restart-daemon` | Restart the daemon |
| `hostguard -v` | Show version |

The `myfw` command is an alias that works identically.

## Systemd Services

```bash
# Firewall
systemctl start hostguard
systemctl stop hostguard
systemctl restart hostguard
systemctl status hostguard

# Daemon
systemctl start hostguardd
systemctl stop hostguardd
systemctl restart hostguardd
systemctl status hostguardd
```

## Uninstallation

```bash
cd /usr/src/hostguard-pro
bash uninstall.sh
```

The uninstaller will:
1. Stop all services and flush firewall rules
2. Remove systemd services
3. Remove the WHM plugin
4. Back up configuration to `/root/hostguard_backup/`
5. Remove all installed files

## File Reference

| Path | Purpose |
|------|---------|
| `/etc/hostguard/hostguard.conf` | Main configuration |
| `/etc/hostguard/allow.conf` | Allowlisted IPs |
| `/etc/hostguard/deny.conf` | Permanently denied IPs |
| `/etc/hostguard/ignore.conf` | Daemon-ignored IPs |
| `/etc/hostguard/blocklists.conf` | External block list URLs |
| `/usr/local/hostguard/bin/hostguard` | CLI tool |
| `/usr/local/hostguard/bin/hostguardd` | Login failure daemon |
| `/usr/local/hostguard/lib/` | Perl modules |
| `/var/lib/hostguard/` | Runtime data (temp blocks, counters) |
| `/var/log/hostguard/daemon.log` | Daemon log |
