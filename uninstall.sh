#!/bin/bash
###############################################################################
# HostGuard Pro - Uninstallation Script
# Run as root to completely remove HostGuard Pro
###############################################################################
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }

echo ""
echo "=============================================="
echo "  HostGuard Pro - Uninstaller"
echo "=============================================="
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Must be run as root."
    exit 1
fi

# Confirm
echo "This will completely remove HostGuard Pro from this server."
echo "Configuration files will be backed up to /root/hostguard_backup/"
echo ""
read -p "Continue? (y/N): " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "Aborted."
    exit 0
fi

###############################################################################
# Stop services
###############################################################################

log_info "Stopping services..."

# Stop daemon first
if systemctl is-active hostguardd &>/dev/null; then
    systemctl stop hostguardd
fi

# Stop and flush firewall
if systemctl is-active hostguard &>/dev/null; then
    systemctl stop hostguard
fi

# Extra safety: flush our rules directly
if command -v iptables &>/dev/null; then
    for chain in HOSTGUARD_IN HOSTGUARD_OUT HOSTGUARD_DENY HOSTGUARD_ALLOW HOSTGUARD_LOGDROP; do
        iptables -D INPUT -j "$chain" 2>/dev/null || true
        iptables -D OUTPUT -j "$chain" 2>/dev/null || true
        iptables -F "$chain" 2>/dev/null || true
        iptables -X "$chain" 2>/dev/null || true
    done
    for chain in HOSTGUARD6_IN HOSTGUARD6_OUT HOSTGUARD6_DENY HOSTGUARD6_ALLOW; do
        ip6tables -D INPUT -j "$chain" 2>/dev/null || true
        ip6tables -D OUTPUT -j "$chain" 2>/dev/null || true
        ip6tables -F "$chain" 2>/dev/null || true
        ip6tables -X "$chain" 2>/dev/null || true
    done
    # Reset policies
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
fi

# Destroy ipsets
if command -v ipset &>/dev/null; then
    for set in hg_allow4 hg_deny4 hg_tempblock4 hg_allow6 hg_deny6 hg_tempblock6; do
        ipset destroy "$set" 2>/dev/null || true
    done
fi

log_info "Services stopped and firewall rules flushed."

###############################################################################
# Disable and remove systemd services
###############################################################################

log_info "Removing systemd services..."

systemctl disable hostguard.service 2>/dev/null || true
systemctl disable hostguardd.service 2>/dev/null || true
rm -f /etc/systemd/system/hostguard.service
rm -f /etc/systemd/system/hostguardd.service
systemctl daemon-reload

# Remove cron
rm -f /etc/cron.d/hostguard_testing

# Remove logrotate
rm -f /etc/logrotate.d/hostguard

###############################################################################
# Remove WHM plugin
###############################################################################

log_info "Removing WHM plugin..."

# Unregister appconfig
if [ -x /usr/local/cpanel/bin/unregister_appconfig ]; then
    /usr/local/cpanel/bin/unregister_appconfig hostguard 2>/dev/null || true
fi

# Remove CGI files
rm -rf /usr/local/cpanel/whostmgr/docroot/cgi/hostguard
rm -f /usr/local/cpanel/whostmgr/docroot/cgi/addon_hostguard.cgi

# Remove plugin config
rm -f /usr/local/cpanel/whostmgr/docroot/addon_plugins/hostguard.conf

# Remove ACL
rm -f /usr/local/cpanel/whostmgr/addonfeatures/hostguard

###############################################################################
# Backup config files
###############################################################################

log_info "Backing up configuration..."

BACKUP_DIR="/root/hostguard_backup/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -a /etc/hostguard/* "$BACKUP_DIR/" 2>/dev/null || true
log_info "Config backed up to: $BACKUP_DIR"

###############################################################################
# Remove files
###############################################################################

log_info "Removing installed files..."

rm -rf /etc/hostguard
rm -rf /usr/local/hostguard
rm -rf /var/lib/hostguard
rm -rf /var/log/hostguard
rm -f /usr/sbin/hostguard
rm -f /usr/sbin/hostguardd
rm -f /usr/sbin/myfw
rm -f /run/hostguardd.pid

###############################################################################
# Done
###############################################################################

echo ""
echo "=============================================="
echo "  HostGuard Pro - Uninstalled"
echo "=============================================="
echo ""
log_info "All HostGuard Pro files have been removed."
log_info "Firewall rules have been flushed (all traffic allowed)."
log_info "Configuration backup: $BACKUP_DIR"
echo ""
log_warn "If you had other firewall software, you may need to restart it."
echo ""
