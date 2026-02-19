# 🛡️ HostGuard Pro

> Advanced Firewall & Real-Time Intrusion Protection for cPanel / WHM Servers

HostGuard Pro is a high-performance firewall and brute-force protection suite built specifically for modern cPanel/WHM environments.
It delivers real-time attack mitigation, intelligent login monitoring, and a fully integrated WHM interface, all with secure defaults and enterprise-grade stability.

Designed for AlmaLinux, Rocky Linux, and CentOS-based cPanel servers.

------------------------------------------------------------------------

## 🚀 Why HostGuard Pro?

Public-facing servers are constantly targeted by:

-   Brute-force login attempts
-   SSH abuse
-   SMTP authentication attacks
-   FTP scanning
-   Web login probing
-   Port scanning
-   Distributed credential attacks

HostGuard Pro continuously monitors your system and reacts within seconds blocking threats before they escalate.

------------------------------------------------------------------------

## 🔥 Core Features

### 🧱 Stateful Firewall Engine

-   Default deny inbound policy
-   Allow established & related connections
-   Configurable `TCP_IN`, `TCP_OUT`, `UDP_IN`, `UDP_OUT`
-   IPv4 + IPv6 support
-   iptables + ipset optimized rule sets
-   Optional nftables detection
-   Secure auto-allow protection during installation
-   Built-in TEST mode to prevent accidental lockouts

------------------------------------------------------------------------

### 🧠 Real-Time Login Protection

HostGuard Pro includes a persistent background daemon (`hostguardd`) that:

-   Monitors authentication logs continuously
-   Detects brute-force behavior instantly
-   Aggregates login attempts across multiple services
-   Blocks attackers automatically
-   Supports temporary blocks with automatic expiry
-   Optionally promotes repeat offenders to permanent block
-   Handles log rotation gracefully

Supported detection targets include:

-   SSH
-   WHM / cPanel logins
-   Exim (SMTP AUTH)
-   Dovecot (IMAP / POP3)
-   FTP services
-   Web authentication logs

------------------------------------------------------------------------

## 🖥️ Native WHM Integration

Access HostGuard Pro directly inside WHM:

**WHM → HostGuard Pro**

Features:

-   📊 Live Dashboard (status, recent blocks, system overview)
-   ⚙️ Firewall Configuration Editor
-   🧾 Allowlist / Denylist / Ignore Manager
-   ⏳ Temporary Blocks Viewer with One-Click Unblock
-   🔄 Service Controls (Start / Stop / Restart / Reload)
-   📜 Integrated Log Viewer

------------------------------------------------------------------------

## 💻 Command Line Interface

HostGuard Pro provides a powerful CLI for system administrators:

``` bash
hostguard -e                # Enable firewall
hostguard -x                # Disable firewall
hostguard -r                # Reload firewall rules
hostguard -a <ip> [note]    # Allow IP
hostguard -d <ip> [note]    # Deny IP
hostguard -tr <ip>          # Remove temporary block
hostguard -g <ip>           # Search IP in configuration
hostguard -l                # List temporary blocks
```

------------------------------------------------------------------------

## 📂 Directory Structure

    /etc/hostguard/               # Configuration files
    /usr/local/hostguard/bin/     # CLI & core scripts
    /usr/local/hostguard/lib/     # Internal modules
    /usr/local/hostguard/tpl/     # Alert templates
    /var/lib/hostguard/           # Runtime data & counters
    /var/log/hostguard/           # Daemon logs

------------------------------------------------------------------------

## ⚙️ Installation

``` bash
git clone https://github.com/fasthive/hostguard-pro.git
cd hostguard-pro
bash install.sh
```

------------------------------------------------------------------------

## 🔄 Uninstallation

``` bash
bash uninstall.sh
```

------------------------------------------------------------------------

## 🔐 Security Architecture

-   Strong validation for IP/CIDR/port inputs
-   No unsafe shell execution
-   Secure configuration file permissions
-   Allowlist priority override
-   Safe recovery mechanisms

------------------------------------------------------------------------

# HostGuard Pro

Secure your infrastructure.
React instantly.
Control everything from WHM.
