#!/bin/bash
###############################################################################
# HostGuard Pro - Installation Script
# Run as root on a cPanel/WHM server (AlmaLinux/Rocky/CentOS)
###############################################################################
set -e
ss
VERSION="1.0.0"
INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC} $1"; }

###############################################################################
# Pre-flight checks
###############################################################################

echo ""
echo "=============================================="
echo "  HostGuard Pro v${VERSION} - Installer"
echo "=============================================="
echo ""

# Must be root
if [ "$(id -u)" -ne 0 ]; then
    log_error "This installer must be run as root."
    exit 1
fi

# Check for cPanel
if [ ! -e "/usr/local/cpanel/version" ]; then
    log_warn "cPanel not detected. WHM plugin integration will be skipped."
    log_warn "Firewall and daemon will still be installed."
    HAS_CPANEL=0
else
    CPANEL_VER=$(cat /usr/local/cpanel/version)
    log_info "cPanel detected: v${CPANEL_VER}"
    HAS_CPANEL=1
fi

# Check OS
if [ -f /etc/redhat-release ]; then
    OS_NAME=$(cat /etc/redhat-release)
    log_info "OS: ${OS_NAME}"
elif [ -f /etc/os-release ]; then
    OS_NAME=$(. /etc/os-release && echo "$PRETTY_NAME")
    log_info "OS: ${OS_NAME}"
fi

###############################################################################
# Compatibility test
###############################################################################

log_step "Running compatibility checks..."

COMPAT_ERRORS=0

# iptables
if command -v iptables &>/dev/null; then
    IPT_VER=$(iptables --version 2>/dev/null | head -1)
    log_info "iptables found: ${IPT_VER}"
else
    log_error "iptables not found. Install iptables first."
    COMPAT_ERRORS=$((COMPAT_ERRORS + 1))
fi

# ip6tables
if command -v ip6tables &>/dev/null; then
    log_info "ip6tables found."
else
    log_warn "ip6tables not found. IPv6 support will be unavailable."
fi

# ipset
if command -v ipset &>/dev/null; then
    IPSET_VER=$(ipset --version 2>/dev/null | head -1)
    log_info "ipset found: ${IPSET_VER}"
else
    log_warn "ipset not found. Installing..."
    yum install -y ipset &>/dev/null || dnf install -y ipset &>/dev/null || apt-get install -y ipset &>/dev/null || true
    if command -v ipset &>/dev/null; then
        log_info "ipset installed successfully."
    else
        log_warn "ipset installation failed. Large blocklists will use individual iptables rules (slower)."
    fi
fi

# Required kernel modules
for mod in ip_tables iptable_filter ip_conntrack nf_conntrack xt_set ip_set; do
    modprobe "$mod" 2>/dev/null || true
done

# Check iptables modules
for target in REJECT LOG ACCEPT DROP; do
    if ! iptables -N _hg_test_$$ 2>/dev/null; then
        continue
    fi
    if iptables -A _hg_test_$$ -j "$target" 2>/dev/null; then
        iptables -D _hg_test_$$ -j "$target" 2>/dev/null
    fi
    iptables -X _hg_test_$$ 2>/dev/null
done

# Perl check
if command -v perl &>/dev/null; then
    PERL_VER=$(perl -v 2>/dev/null | grep version | head -1)
    log_info "Perl found."
else
    log_error "Perl not found. Required for HostGuard Pro."
    COMPAT_ERRORS=$((COMPAT_ERRORS + 1))
fi

# sendmail for alerts
if [ -x /usr/sbin/sendmail ]; then
    log_info "sendmail found."
else
    log_warn "sendmail not found. Email alerts will be unavailable."
fi

if [ "$COMPAT_ERRORS" -gt 0 ]; then
    log_error "Compatibility checks failed with $COMPAT_ERRORS error(s). Cannot continue."
    exit 1
fi

log_info "All compatibility checks passed."
echo ""

###############################################################################
# Create directories
###############################################################################

log_step "Creating directories..."

mkdir -p /etc/hostguard
mkdir -p /usr/local/hostguard/bin
mkdir -p /usr/local/hostguard/lib
mkdir -p /usr/local/hostguard/tpl
mkdir -p /var/lib/hostguard
mkdir -p /var/log/hostguard

###############################################################################
# Install config files (preserve existing)
###############################################################################

log_step "Installing configuration files..."

install_config() {
    local src="$1"
    local dst="$2"
    if [ -f "$dst" ]; then
        log_warn "Config exists, preserving: $dst"
        cp "$src" "${dst}.dist"
    else
        cp "$src" "$dst"
        log_info "Installed: $dst"
    fi
}

install_config "${INSTALL_DIR}/etc/hostguard/hostguard.conf" "/etc/hostguard/hostguard.conf"
install_config "${INSTALL_DIR}/etc/hostguard/allow.conf"     "/etc/hostguard/allow.conf"
install_config "${INSTALL_DIR}/etc/hostguard/deny.conf"      "/etc/hostguard/deny.conf"
install_config "${INSTALL_DIR}/etc/hostguard/ignore.conf"    "/etc/hostguard/ignore.conf"
install_config "${INSTALL_DIR}/etc/hostguard/blocklists.conf" "/etc/hostguard/blocklists.conf"

# Set strict permissions on config files
chmod 600 /etc/hostguard/*.conf
chown root:root /etc/hostguard/*.conf

###############################################################################
# Install binaries and libraries
###############################################################################

log_step "Installing binaries and libraries..."

# Perl modules
cp "${INSTALL_DIR}/usr/local/hostguard/lib/HGConfig.pm"   /usr/local/hostguard/lib/
cp "${INSTALL_DIR}/usr/local/hostguard/lib/HGFirewall.pm"  /usr/local/hostguard/lib/
cp "${INSTALL_DIR}/usr/local/hostguard/lib/HGLogger.pm"    /usr/local/hostguard/lib/
chmod 644 /usr/local/hostguard/lib/*.pm

# CLI tool
cp "${INSTALL_DIR}/usr/local/hostguard/bin/hostguard" /usr/local/hostguard/bin/hostguard
chmod 755 /usr/local/hostguard/bin/hostguard

# Daemon
cp "${INSTALL_DIR}/usr/local/hostguard/bin/hostguardd" /usr/local/hostguard/bin/hostguardd
chmod 755 /usr/local/hostguard/bin/hostguardd

# Templates
cp "${INSTALL_DIR}/usr/local/hostguard/tpl/block_alert.txt" /usr/local/hostguard/tpl/
chmod 644 /usr/local/hostguard/tpl/*.txt

# Create symlinks for convenience
ln -sf /usr/local/hostguard/bin/hostguard /usr/sbin/hostguard
ln -sf /usr/local/hostguard/bin/hostguardd /usr/sbin/hostguardd

# Also create 'myfw' alias as per spec
ln -sf /usr/local/hostguard/bin/hostguard /usr/sbin/myfw

log_info "Binaries installed."

###############################################################################
# Initialize runtime data
###############################################################################

log_step "Initializing runtime data..."

touch /var/lib/hostguard/tempblock.dat
touch /var/lib/hostguard/block_history.dat
chmod 600 /var/lib/hostguard/*.dat
chown root:root /var/lib/hostguard/*.dat

touch /var/log/hostguard/daemon.log
chmod 640 /var/log/hostguard/daemon.log
chown root:root /var/log/hostguard/daemon.log

###############################################################################
# Install systemd services
###############################################################################

log_step "Installing systemd services..."

cp "${INSTALL_DIR}/systemd/hostguard.service"  /etc/systemd/system/hostguard.service
cp "${INSTALL_DIR}/systemd/hostguardd.service" /etc/systemd/system/hostguardd.service
chmod 644 /etc/systemd/system/hostguard.service
chmod 644 /etc/systemd/system/hostguardd.service

# Install logrotate
cp "${INSTALL_DIR}/systemd/hostguard.logrotate" /etc/logrotate.d/hostguard
chmod 644 /etc/logrotate.d/hostguard

systemctl daemon-reload

# Enable services
systemctl enable hostguard.service
systemctl enable hostguardd.service

log_info "Systemd services installed and enabled."

###############################################################################
# Auto-detect server IPs and add to ignore list
###############################################################################

log_step "Detecting server IP addresses..."

SERVER_IPS=$(ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[\d.]+' | sort -u)
for sip in $SERVER_IPS; do
    if ! grep -q "^${sip}$" /etc/hostguard/ignore.conf 2>/dev/null; then
        echo "$sip # Server IP (auto-detected)" >> /etc/hostguard/ignore.conf
        log_info "Added server IP to ignore list: $sip"
    fi
    if ! grep -q "^${sip}$" /etc/hostguard/allow.conf 2>/dev/null; then
        echo "$sip # Server IP (auto-detected)" >> /etc/hostguard/allow.conf
        log_info "Added server IP to allowlist: $sip"
    fi
done

# Detect current admin IP (who is SSHed in)
ADMIN_IP=$(who am i 2>/dev/null | grep -oP '\([\d.]+\)' | tr -d '()' | head -1)
if [ -n "$ADMIN_IP" ] && [ "$ADMIN_IP" != "" ]; then
    if ! grep -q "^${ADMIN_IP}$" /etc/hostguard/allow.conf 2>/dev/null; then
        echo "$ADMIN_IP # Admin IP (auto-detected at install)" >> /etc/hostguard/allow.conf
        log_info "Added admin SSH IP to allowlist: $ADMIN_IP"
    fi
    if ! grep -q "^${ADMIN_IP}$" /etc/hostguard/ignore.conf 2>/dev/null; then
        echo "$ADMIN_IP # Admin IP (auto-detected at install)" >> /etc/hostguard/ignore.conf
    fi
fi

###############################################################################
# Install WHM plugin
###############################################################################

if [ "$HAS_CPANEL" -eq 1 ]; then
    log_step "Installing WHM plugin..."

    WHM_CGI="/usr/local/cpanel/whostmgr/docroot/cgi"
    WHM_PLUGINS="/usr/local/cpanel/whostmgr/docroot/addon_plugins"

    # Create CGI directory
    mkdir -p "${WHM_CGI}/hostguard"

    # Install CGI file
    cp "${INSTALL_DIR}/whm/cgi/hostguard/hostguard.cgi" "${WHM_CGI}/hostguard/hostguard.cgi"
    chmod 755 "${WHM_CGI}/hostguard/hostguard.cgi"
    chown root:root "${WHM_CGI}/hostguard/hostguard.cgi"

    # Install plugin icon (create a simple SVG icon)
    cat > "${WHM_CGI}/hostguard/hostguard_icon.png" << 'ICON_PLACEHOLDER'
ICON_PLACEHOLDER
    # We'll create a proper SVG icon instead
    cat > "${WHM_CGI}/hostguard/hostguard_icon.svg" << 'SVGEOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs><linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%">
    <stop offset="0%" style="stop-color:#3498db"/>
    <stop offset="100%" style="stop-color:#1a5276"/>
  </linearGradient></defs>
  <path d="M32 4 L56 16 V34 C56 48 44 58 32 62 C20 58 8 48 8 34 V16 Z" fill="url(#g)" stroke="#1a2332" stroke-width="2"/>
  <text x="32" y="38" text-anchor="middle" fill="white" font-size="18" font-weight="bold" font-family="sans-serif">HG</text>
</svg>
SVGEOF
    chmod 644 "${WHM_CGI}/hostguard/hostguard_icon.svg"

    # Register the WHM plugin using appconfig
    if [ -x /usr/local/cpanel/bin/register_appconfig ]; then
        # Use appconfig registration (modern cPanel)
        cp "${INSTALL_DIR}/whm/addon_plugins/hostguard.conf" /tmp/hostguard_appconfig.conf
        # Update icon path
        sed -i 's|icon=hostguard_icon.png|icon=hostguard/hostguard_icon.svg|' /tmp/hostguard_appconfig.conf
        /usr/local/cpanel/bin/register_appconfig /tmp/hostguard_appconfig.conf
        rm -f /tmp/hostguard_appconfig.conf
        log_info "WHM plugin registered via appconfig."
    else
        # Fallback: copy to addon_plugins directory
        mkdir -p "$WHM_PLUGINS"
        cp "${INSTALL_DIR}/whm/addon_plugins/hostguard.conf" "${WHM_PLUGINS}/hostguard.conf"
        # Create the legacy addon CGI symlink
        ln -sf "${WHM_CGI}/hostguard/hostguard.cgi" "${WHM_CGI}/addon_hostguard.cgi"
        log_info "WHM plugin registered via addon_plugins."
    fi

    # Register ACL
    if [ -d /usr/local/cpanel/whostmgr/addonfeatures ]; then
        echo "hostguard:HostGuard Pro" > /usr/local/cpanel/whostmgr/addonfeatures/hostguard
    fi

    log_info "WHM plugin installed."
else
    log_warn "cPanel not found. WHM plugin not installed."
    log_info "You can manage HostGuard Pro via CLI: hostguard --help"
fi

###############################################################################
# Version file
###############################################################################

echo "$VERSION" > /etc/hostguard/version.txt
chmod 644 /etc/hostguard/version.txt

###############################################################################
# Summary
###############################################################################

echo ""
echo "=============================================="
echo "  HostGuard Pro v${VERSION} - Installed!"
echo "=============================================="
echo ""
log_info "Configuration:  /etc/hostguard/"
log_info "Binaries:       /usr/local/hostguard/bin/"
log_info "Libraries:      /usr/local/hostguard/lib/"
log_info "Runtime data:   /var/lib/hostguard/"
log_info "Logs:           /var/log/hostguard/"
echo ""
log_info "CLI commands:"
echo "  hostguard -e          # Enable firewall"
echo "  hostguard -x          # Disable firewall"
echo "  hostguard -r          # Reload rules"
echo "  hostguard -s          # Show status"
echo "  hostguard -a <ip>     # Allow IP"
echo "  hostguard -d <ip>     # Deny IP"
echo "  hostguard -l          # List temp blocks"
echo "  hostguard --help      # Full help"
echo ""
log_info "Also available as: myfw (alias)"
echo ""

if [ "$HAS_CPANEL" -eq 1 ]; then
    log_info "WHM: Log into WHM and look for 'HostGuard Pro' in the left menu."
    echo ""
fi

log_warn "IMPORTANT: TESTING mode is ON by default."
log_warn "The firewall will auto-disable every 5 minutes until you set TESTING=0"
log_warn "in /etc/hostguard/hostguard.conf and reload."
echo ""
log_info "To start the firewall now:"
echo "  systemctl start hostguard"
echo "  systemctl start hostguardd   (after setting TESTING=0)"
echo ""
log_info "Installation complete."
