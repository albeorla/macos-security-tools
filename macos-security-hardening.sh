#!/bin/bash

# ==============================================================================
# macOS Security Hardening Script
# ==============================================================================
# Based on:
# - NIST macOS Security Guidelines
# - CIS Benchmarks for macOS
# - dotkaio/security-mac recommendations
# - Apple Security Best Practices
#
# This script implements comprehensive security hardening for macOS including:
# - System configuration hardening
# - Network security
# - Privacy enhancements
# - Malware protection
# - Access controls
# - Audit logging
# ==============================================================================

set -euo pipefail

# --- Color Codes ---
Color_Off='\033[0m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
BYellow='\033[1;33m'
BBlue='\033[1;34m'
BCyan='\033[1;36m'

# --- Logging ---
LOG_DIR="/var/log/macos-security"
LOG_FILE="$LOG_DIR/hardening-$(date +%Y%m%d-%H%M%S).log"
CHANGES_FILE="$LOG_DIR/changes.log"

# Create log directory
sudo mkdir -p "$LOG_DIR"
sudo chmod 700 "$LOG_DIR"

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | sudo tee -a "$LOG_FILE"
    
    case "$level" in
        "INFO") echo -e "${BBlue}[INFO]${Color_Off} $message" ;;
        "SUCCESS") echo -e "${BGreen}[SUCCESS]${Color_Off} $message" ;;
        "WARNING") echo -e "${BYellow}[WARNING]${Color_Off} $message" ;;
        "ERROR") echo -e "${BRed}[ERROR]${Color_Off} $message" ;;
    esac
}

record_change() {
    local change="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $change" | sudo tee -a "$CHANGES_FILE" >/dev/null
}

# --- Pre-flight Checks ---
preflight_checks() {
    log "INFO" "Starting pre-flight checks..."
    
    # Check if running on macOS
    if [[ "$(uname)" != "Darwin" ]]; then
        log "ERROR" "This script is designed for macOS only"
        exit 1
    fi
    
    # Check for admin privileges
    if ! sudo -n true 2>/dev/null; then
        log "INFO" "This script requires administrator privileges"
        sudo -v
    fi
    
    # Check macOS version
    OS_VERSION=$(sw_vers -productVersion)
    log "INFO" "macOS version: $OS_VERSION"
    
    # Check if running on Apple Silicon
    if [[ "$(uname -m)" == "arm64" ]]; then
        log "INFO" "Running on Apple Silicon"
        ARCH="arm64"
    else
        log "WARNING" "Running on Intel - some hardware security features unavailable"
        ARCH="x86_64"
    fi
}

# --- 1. Enable FileVault ---
enable_filevault() {
    log "INFO" "Checking FileVault status..."
    
    if fdesetup status | grep -q "FileVault is On"; then
        log "SUCCESS" "FileVault is already enabled"
    else
        log "WARNING" "FileVault is not enabled"
        read -p "Enable FileVault now? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo fdesetup enable
            record_change "FileVault enabled"
            log "SUCCESS" "FileVault enablement initiated"
        fi
    fi
}

# --- 2. Enable Firewall ---
enable_firewall() {
    log "INFO" "Configuring firewall..."
    
    # Enable firewall
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
    record_change "Firewall enabled"
    
    # Enable stealth mode
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
    record_change "Firewall stealth mode enabled"
    
    # Enable logging
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on
    record_change "Firewall logging enabled"
    
    # Block all incoming connections except essential services
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on
    record_change "Firewall set to block all incoming connections"
    
    log "SUCCESS" "Firewall configured with strict settings"
}

# --- 3. System Integrity Protection ---
check_sip() {
    log "INFO" "Checking System Integrity Protection..."
    
    if csrutil status | grep -q "enabled"; then
        log "SUCCESS" "System Integrity Protection is enabled"
    else
        log "WARNING" "System Integrity Protection is DISABLED - this is a security risk!"
        log "WARNING" "To enable SIP, restart in Recovery Mode and run 'csrutil enable'"
    fi
}

# --- 4. Gatekeeper and XProtect ---
configure_gatekeeper() {
    log "INFO" "Configuring Gatekeeper..."
    
    # Enable Gatekeeper
    sudo spctl --master-enable
    record_change "Gatekeeper enabled"
    
    # Set to App Store and identified developers
    sudo spctl --enable --label "Developer ID"
    record_change "Gatekeeper set to App Store and identified developers"
    
    # Update XProtect and MRT
    log "INFO" "Updating XProtect and Malware Removal Tool..."
    softwareupdate --background-critical
    
    log "SUCCESS" "Gatekeeper and XProtect configured"
}

# --- 5. Privacy Settings ---
configure_privacy() {
    log "INFO" "Configuring privacy settings..."
    
    # Disable Siri
    defaults write com.apple.assistant.support "Assistant Enabled" -bool false
    defaults write com.apple.Siri StatusMenuVisible -bool false
    defaults write com.apple.Siri UserHasDeclinedEnable -bool true
    record_change "Siri disabled"
    
    # Disable location services for system services
    sudo defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool false
    record_change "Location services disabled for system"
    
    # Disable diagnostics and usage data
    defaults write com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true
    defaults write com.apple.CrashReporter DialogType -string "none"
    defaults write com.apple.assistant.support "Siri Data Sharing Opt-In Status" -int 2
    record_change "Diagnostics and usage data disabled"
    
    # Disable Handoff
    defaults -currentHost write com.apple.coreservices.useractivityd ActivityAdvertisingAllowed -bool false
    defaults -currentHost write com.apple.coreservices.useractivityd ActivityReceivingAllowed -bool false
    record_change "Handoff disabled"
    
    log "SUCCESS" "Privacy settings configured"
}

# --- 6. Network Security ---
configure_network_security() {
    log "INFO" "Configuring network security..."
    
    # Disable Bonjour multicast
    sudo defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true
    record_change "Bonjour multicast advertisements disabled"
    
    # Disable captive portal
    sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.captive.control Active -bool false
    record_change "Captive portal disabled"
    
    # Configure DNS to use secure servers
    log "INFO" "Configuring secure DNS..."
    # Using Quad9 (9.9.9.9) and Cloudflare (1.1.1.1) as secure DNS servers
    networksetup -listallnetworkservices | grep -v "*" | while read service; do
        networksetup -setdnsservers "$service" 9.9.9.9 1.1.1.1 2>/dev/null || true
    done
    record_change "Secure DNS servers configured"
    
    log "SUCCESS" "Network security configured"
}

# --- 7. Login and Access Controls ---
configure_access_controls() {
    log "INFO" "Configuring access controls..."
    
    # Require password immediately after sleep or screen saver
    defaults write com.apple.screensaver askForPassword -int 1
    defaults write com.apple.screensaver askForPasswordDelay -int 0
    record_change "Immediate password requirement after sleep enabled"
    
    # Disable automatic login
    sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || true
    record_change "Automatic login disabled"
    
    # Display login window as name and password
    sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true
    record_change "Login window set to name and password"
    
    # Disable guest account
    sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false
    sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess -bool false
    record_change "Guest account disabled"
    
    # Set screen lock timeout (5 minutes)
    defaults -currentHost write com.apple.screensaver idleTime -int 300
    record_change "Screen lock timeout set to 5 minutes"
    
    log "SUCCESS" "Access controls configured"
}

# --- 8. Audit and Logging ---
configure_audit_logging() {
    log "INFO" "Configuring audit and logging..."
    
    # Enable security auditing
    sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null || true
    record_change "Security auditing enabled"
    
    # Configure audit control
    if [ -f /etc/security/audit_control ]; then
        sudo cp /etc/security/audit_control /etc/security/audit_control.backup
        # Add file attribute modification, failed file access
        echo "# Security hardening additions" | sudo tee -a /etc/security/audit_control
        echo "flags:lo,aa,ad,fd,fm,-all" | sudo tee -a /etc/security/audit_control
        record_change "Audit control configured for security events"
    fi
    
    # Enable additional logging
    sudo log config --mode "level:debug" --subsystem com.apple.securityd 2>/dev/null || true
    
    log "SUCCESS" "Audit and logging configured"
}

# --- 9. Application Security ---
configure_app_security() {
    log "INFO" "Configuring application security..."
    
    # Safari security settings
    defaults write com.apple.Safari AutoOpenSafeDownloads -bool false
    defaults write com.apple.Safari com.apple.Safari.ContentPageGroupIdentifier.WebKit2JavaEnabled -bool false
    defaults write com.apple.Safari com.apple.Safari.ContentPageGroupIdentifier.WebKit2JavaEnabledForLocalFiles -bool false
    defaults write com.apple.Safari SendDoNotTrackHTTPHeader -bool true
    record_change "Safari security settings configured"
    
    # Disable opening "safe" files after downloading
    defaults write com.apple.Safari AutoOpenSafeDownloads -bool false
    
    # Show full URLs in Safari
    defaults write com.apple.Safari ShowFullURLInSmartSearchField -bool true
    
    log "SUCCESS" "Application security configured"
}

# --- 10. File System Security ---
configure_filesystem_security() {
    log "INFO" "Configuring file system security..."
    
    # Set restrictive umask
    sudo launchctl config user umask 077
    record_change "Restrictive umask (077) set"
    
    # Show hidden files and extensions
    defaults write com.apple.finder AppleShowAllFiles -bool true
    defaults write NSGlobalDomain AppleShowAllExtensions -bool true
    record_change "Hidden files and extensions shown"
    
    # Disable .DS_Store on network volumes
    defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true
    record_change ".DS_Store creation on network volumes disabled"
    
    log "SUCCESS" "File system security configured"
}

# --- 11. Create Security Tools ---
create_security_tools() {
    log "INFO" "Creating security monitoring tools..."
    
    # Create security check script
    cat << 'EOF' | sudo tee /usr/local/bin/macos-security-check > /dev/null
#!/bin/bash
# macOS Security Status Check

echo "=== macOS Security Status Check ==="
echo "Date: $(date)"
echo

# FileVault
echo "FileVault Status:"
fdesetup status

# Firewall
echo -e "\nFirewall Status:"
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode

# SIP
echo -e "\nSystem Integrity Protection:"
csrutil status

# Gatekeeper
echo -e "\nGatekeeper Status:"
spctl --status

# Check for software updates
echo -e "\nSoftware Updates:"
softwareupdate -l 2>&1 | grep -E "Software Update found|No new software" || echo "Check failed"

# Recent auth failures
echo -e "\nRecent Authentication Failures (last 10):"
log show --style syslog --predicate 'process == "loginwindow"' --debug --last 1h 2>/dev/null | grep "Authentication failed" | tail -10

echo -e "\nSecurity check complete."
EOF
    
    sudo chmod 755 /usr/local/bin/macos-security-check
    record_change "Security check tool created"
    
    log "SUCCESS" "Security tools created"
}

# --- 12. Lockdown Mode (macOS 13+) ---
enable_lockdown_mode() {
    log "INFO" "Checking Lockdown Mode availability..."
    
    # Check if macOS version supports Lockdown Mode (13.0+)
    if [[ $(sw_vers -productVersion | cut -d. -f1) -ge 13 ]]; then
        log "INFO" "Lockdown Mode is available on this system"
        log "WARNING" "Lockdown Mode significantly restricts functionality for maximum security"
        log "WARNING" "Enable manually in System Settings > Privacy & Security > Lockdown Mode"
    else
        log "INFO" "Lockdown Mode not available (requires macOS 13+)"
    fi
}

# --- Main Execution ---
main() {
    echo -e "${BBlue}====================================${Color_Off}"
    echo -e "${BBlue}   macOS Security Hardening Script${Color_Off}"
    echo -e "${BBlue}====================================${Color_Off}"
    echo
    
    preflight_checks
    
    # Create backup of current settings
    log "INFO" "Creating settings backup..."
    sudo defaults read > "$LOG_DIR/defaults-backup-$(date +%Y%m%d-%H%M%S).plist"
    
    # Execute hardening steps
    enable_filevault
    enable_firewall
    check_sip
    configure_gatekeeper
    configure_privacy
    configure_network_security
    configure_access_controls
    configure_audit_logging
    configure_app_security
    configure_filesystem_security
    create_security_tools
    enable_lockdown_mode
    
    # Summary
    echo
    echo -e "${BGreen}====================================${Color_Off}"
    echo -e "${BGreen}   Security Hardening Complete!${Color_Off}"
    echo -e "${BGreen}====================================${Color_Off}"
    echo
    echo -e "${BYellow}Important Notes:${Color_Off}"
    echo "• Some settings require a restart to take effect"
    echo "• Review changes in: $CHANGES_FILE"
    echo "• Run security check: macos-security-check"
    echo "• Full log available: $LOG_FILE"
    echo
    echo -e "${BYellow}Additional Recommendations:${Color_Off}"
    echo "• Use a password manager for strong, unique passwords"
    echo "• Enable two-factor authentication on all accounts"
    echo "• Regularly update macOS and all applications"
    echo "• Consider using a VPN for untrusted networks"
    echo "• Review and limit application permissions regularly"
    echo
    
    log "SUCCESS" "Security hardening completed"
}

# Run main function
main "$@" 