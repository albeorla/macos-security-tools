#!/bin/bash

# ==============================================================================
# macOS Compromise Detection Script
# ==============================================================================
# Advanced forensic analysis to detect if a macOS system has been compromised
# Checks for:
# - Known malware indicators
# - Persistence mechanisms
# - Suspicious system modifications
# - Data exfiltration evidence
# - Rootkits and hidden processes
# - Credential theft indicators
# - Historical compromise evidence
# ==============================================================================

set -euo pipefail

# --- Color Codes ---
Color_Off='\033[0m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
BYellow='\033[1;33m'
BBlue='\033[1;34m'
BCyan='\033[1;36m'
BPurple='\033[1;35m'
BWhite='\033[1;37m'

# --- Configuration ---
DETECTION_DIR="/var/log/macos-compromise-detection"
REPORT_FILE="$DETECTION_DIR/compromise-report-$(date +%Y%m%d-%H%M%S).txt"
EVIDENCE_DIR="$DETECTION_DIR/evidence"
INDICATORS_FILE="$DETECTION_DIR/indicators.txt"

# Create directories
sudo mkdir -p "$DETECTION_DIR" "$EVIDENCE_DIR"
sudo chmod 700 "$DETECTION_DIR"

# --- Score Tracking ---
COMPROMISE_SCORE=0
INDICATORS_FOUND=()

# --- Logging Functions ---
log() {
    echo "$1" | sudo tee -a "$REPORT_FILE"
}

log_indicator() {
    local severity="$1"
    local indicator="$2"
    local details="$3"
    
    INDICATORS_FOUND+=("[$severity] $indicator: $details")
    
    case "$severity" in
        "CRITICAL")
            COMPROMISE_SCORE=$((COMPROMISE_SCORE + 10))
            echo -e "${BRed}[CRITICAL]${Color_Off} $indicator: $details"
            ;;
        "HIGH")
            COMPROMISE_SCORE=$((COMPROMISE_SCORE + 7))
            echo -e "${BRed}[HIGH]${Color_Off} $indicator: $details"
            ;;
        "MEDIUM")
            COMPROMISE_SCORE=$((COMPROMISE_SCORE + 4))
            echo -e "${BYellow}[MEDIUM]${Color_Off} $indicator: $details"
            ;;
        "LOW")
            COMPROMISE_SCORE=$((COMPROMISE_SCORE + 2))
            echo -e "${BBlue}[LOW]${Color_Off} $indicator: $details"
            ;;
    esac
    
    log "[$severity] $indicator: $details"
}

# --- 1. Check for Known Malware Signatures ---
check_known_malware() {
    echo -e "\n${BCyan}Checking for known malware signatures...${Color_Off}"
    
    # Common malware process names
    local malware_processes=(
        "MacKeeper"
        "MacDefender"
        "MacSecurity"
        "MacProtector"
        "OSX/Shlayer"
        "OSX/CrescentCore"
        "OSX/Bundlore"
        "OSX/Pirrit"
        "OSX/Dok"
        "OSX/MaMi"
        "OSX/FruitFly"
        "OSX/X-Agent"
        "OSX/Komplex"
        "OSX/Eleanor"
        "OSX/Keydnap"
        "OSX/KeRanger"
        "com.apple.updates"  # Fake system process
        "kernel_service"     # Fake kernel process
    )
    
    for malware in "${malware_processes[@]}"; do
        if pgrep -fi "$malware" > /dev/null 2>&1; then
            log_indicator "CRITICAL" "Known Malware Process" "Found process matching: $malware"
        fi
    done
    
    # Check for suspicious files in common malware locations
    local malware_paths=(
        "/tmp/.hidden"
        "/var/tmp/.system"
        "/usr/local/bin/com.apple.*"
        "/Library/LaunchDaemons/com.apple.*.plist"
        "$HOME/Library/LaunchAgents/com.apple.*.plist"
        "/Users/Shared/.hidden"
    )
    
    for path in "${malware_paths[@]}"; do
        if find $(dirname "$path") -name "$(basename "$path")" 2>/dev/null | grep -q .; then
            log_indicator "HIGH" "Suspicious File Location" "Found suspicious file matching: $path"
        fi
    done
}

# --- 2. Check Persistence Mechanisms ---
check_persistence() {
    echo -e "\n${BCyan}Checking persistence mechanisms...${Color_Off}"
    
    # Check LaunchDaemons and LaunchAgents
    local persistence_dirs=(
        "/System/Library/LaunchDaemons"
        "/Library/LaunchDaemons"
        "/Library/LaunchAgents"
        "$HOME/Library/LaunchAgents"
    )
    
    for dir in "${persistence_dirs[@]}"; do
        if [ -d "$dir" ]; then
            # Look for recently added items
            find "$dir" -name "*.plist" -mtime -30 2>/dev/null | while read -r plist; do
                # Skip Apple-signed items
                if ! codesign -dv "$plist" 2>&1 | grep -q "Authority=Apple"; then
                    # Check for suspicious content
                    if grep -E "(RunAtLoad.*true|KeepAlive.*true)" "$plist" > /dev/null 2>&1; then
                        log_indicator "HIGH" "Suspicious Persistence" "Non-Apple plist with RunAtLoad/KeepAlive: $plist"
                    fi
                    
                    # Check for hidden executables
                    if grep -E "\.hidden|/tmp/|/var/tmp/" "$plist" > /dev/null 2>&1; then
                        log_indicator "CRITICAL" "Hidden Persistence" "Plist references hidden path: $plist"
                    fi
                fi
            done
        fi
    done
    
    # Check login items
    osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null | while read -r item; do
        if [[ "$item" =~ \.(hidden|tmp)$ ]]; then
            log_indicator "HIGH" "Suspicious Login Item" "Hidden login item: $item"
        fi
    done
    
    # Check cron jobs
    if crontab -l 2>/dev/null | grep -E "(curl|wget|nc|/tmp/|/var/tmp/)" > /dev/null; then
        log_indicator "HIGH" "Suspicious Cron Job" "Cron job with network or temp directory access"
    fi
}

# --- 3. Check for Rootkits ---
check_rootkits() {
    echo -e "\n${BCyan}Checking for rootkit indicators...${Color_Off}"
    
    # Check for process hiding
    local ps_count=$(ps aux | wc -l)
    local proc_count=$(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | wc -l)
    
    if [ "$proc_count" -gt 0 ] && [ $((proc_count - ps_count)) -gt 5 ]; then
        log_indicator "CRITICAL" "Hidden Processes" "Discrepancy between /proc and ps output"
    fi
    
    # Check for kernel module tampering
    if kextstat | grep -v "com.apple" | grep -vE "(signed|certificate)" > /dev/null 2>&1; then
        log_indicator "HIGH" "Unsigned Kernel Extension" "Non-Apple unsigned kernel extension detected"
    fi
    
    # Check for library injection
    if [ -n "${DYLD_INSERT_LIBRARIES:-}" ]; then
        log_indicator "CRITICAL" "Library Injection" "DYLD_INSERT_LIBRARIES is set: $DYLD_INSERT_LIBRARIES"
    fi
    
    # Check for suspicious dtrace scripts
    if dtrace -l 2>/dev/null | grep -E "(hide|stealth|rootkit)" > /dev/null; then
        log_indicator "HIGH" "Suspicious DTrace" "DTrace script with suspicious keywords"
    fi
}

# --- 4. Check Network Indicators ---
check_network_indicators() {
    echo -e "\n${BCyan}Checking network indicators of compromise...${Color_Off}"
    
    # Check for reverse shells
    if netstat -an | grep -E "ESTABLISHED.*:(4444|5555|6666|31337|1337)" > /dev/null; then
        log_indicator "CRITICAL" "Reverse Shell Port" "Connection on known backdoor port"
    fi
    
    # Check for suspicious DNS settings
    local dns_servers=$(networksetup -getdnsservers Wi-Fi 2>/dev/null | grep -v "There aren't any")
    if [ ! -z "$dns_servers" ]; then
        # Check against known malicious DNS servers
        if echo "$dns_servers" | grep -E "(186\.2\.|93\.184\.|213\.109\.)" > /dev/null; then
            log_indicator "HIGH" "Suspicious DNS" "DNS server matches known malicious IP pattern"
        fi
    fi
    
    # Check hosts file modifications
    if [ -f /etc/hosts ]; then
        local hosts_lines=$(grep -v -E "^#|^$|localhost|broadcasthost" /etc/hosts | wc -l)
        if [ "$hosts_lines" -gt 10 ]; then
            log_indicator "MEDIUM" "Modified Hosts File" "Hosts file has $hosts_lines custom entries"
        fi
        
        # Check for security vendor blocking
        if grep -E "(virustotal|malwarebytes|avast|kaspersky|sophos)" /etc/hosts > /dev/null 2>&1; then
            log_indicator "HIGH" "Security Vendor Blocking" "Hosts file blocks security vendors"
        fi
    fi
    
    # Check for proxy settings
    if networksetup -getwebproxy Wi-Fi | grep "Enabled: Yes" > /dev/null 2>&1; then
        local proxy_server=$(networksetup -getwebproxy Wi-Fi | grep "Server:" | awk '{print $2}')
        log_indicator "MEDIUM" "Proxy Configuration" "HTTP proxy enabled: $proxy_server"
    fi
}

# --- 5. Check Browser Compromise ---
check_browser_compromise() {
    echo -e "\n${BCyan}Checking for browser compromise...${Color_Off}"
    
    # Check Safari extensions
    local safari_extensions="$HOME/Library/Safari/Extensions"
    if [ -d "$safari_extensions" ]; then
        find "$safari_extensions" -name "*.safariextz" -o -name "*.safariextension" 2>/dev/null | while read -r ext; do
            if ! codesign -dv "$ext" 2>&1 | grep -q "Authority=Apple"; then
                log_indicator "MEDIUM" "Unsigned Safari Extension" "$(basename "$ext")"
            fi
        done
    fi
    
    # Check Chrome extensions
    local chrome_profile="$HOME/Library/Application Support/Google/Chrome/Default"
    if [ -d "$chrome_profile/Extensions" ]; then
        # Check for suspicious extension IDs
        find "$chrome_profile/Extensions" -mindepth 1 -maxdepth 1 -type d | while read -r ext_dir; do
            local ext_id=$(basename "$ext_dir")
            # Check if extension has suspicious permissions
            if find "$ext_dir" -name "manifest.json" -exec grep -l "all_urls\|<all_urls>\|http://*/*\|https://*/*" {} \; 2>/dev/null | grep -q .; then
                log_indicator "MEDIUM" "Chrome Extension with Broad Permissions" "Extension ID: $ext_id"
            fi
        done
    fi
    
    # Check for suspicious certificates
    if security find-certificate -a -p /Library/Keychains/System.keychain 2>/dev/null | openssl x509 -text 2>/dev/null | grep -E "Subject:.*CN=.*\.(tk|ml|ga|cf)" > /dev/null 2>&1; then
        log_indicator "HIGH" "Suspicious Certificate" "Certificate with suspicious TLD in System keychain"
    fi
}

# --- 6. Check for Data Exfiltration ---
check_data_exfiltration() {
    echo -e "\n${BCyan}Checking for data exfiltration indicators...${Color_Off}"
    
    # Check for large outbound data transfers in logs
    log show --predicate 'process == "nettop" OR process == "netstat"' --style syslog --last 7d 2>/dev/null | \
        grep -E "sent.*[0-9]{9,}" > /dev/null && \
        log_indicator "MEDIUM" "Large Data Transfer" "Large outbound data transfer detected in logs"
    
    # Check for archive creation in suspicious locations
    find /tmp /var/tmp -name "*.zip" -o -name "*.tar" -o -name "*.gz" -mtime -7 2>/dev/null | while read -r archive; do
        log_indicator "MEDIUM" "Suspicious Archive" "Archive in temp directory: $archive"
    done
    
    # Check for screenshots in temp directories
    find /tmp /var/tmp -name "*.png" -o -name "*.jpg" -o -name "*.jpeg" -mtime -7 2>/dev/null | while read -r image; do
        log_indicator "HIGH" "Suspicious Screenshot" "Image file in temp directory: $image"
    done
}

# --- 7. Check System Integrity ---
check_system_integrity() {
    echo -e "\n${BCyan}Checking system integrity...${Color_Off}"
    
    # Check if SIP is disabled
    if ! csrutil status | grep -q "enabled"; then
        log_indicator "HIGH" "System Integrity Protection" "SIP is disabled - system is vulnerable"
    fi
    
    # Check for modified system binaries
    local system_binaries=(
        "/usr/bin/sudo"
        "/usr/bin/ssh"
        "/usr/bin/curl"
        "/usr/bin/wget"
        "/bin/bash"
        "/bin/sh"
    )
    
    for binary in "${system_binaries[@]}"; do
        if [ -f "$binary" ]; then
            if ! codesign -v "$binary" 2>/dev/null; then
                log_indicator "CRITICAL" "Modified System Binary" "Failed code signature: $binary"
            fi
        fi
    done
    
    # Check for suspicious kernel extensions
    kextstat | grep -v "com.apple" | while read -r line; do
        local kext=$(echo "$line" | awk '{print $6}')
        if [ ! -z "$kext" ]; then
            log_indicator "MEDIUM" "Third-party Kernel Extension" "$kext"
        fi
    done
}

# --- 8. Check User Account Compromise ---
check_user_accounts() {
    echo -e "\n${BCyan}Checking for user account compromise...${Color_Off}"
    
    # Check for new admin users
    dscl . -read /Groups/admin GroupMembership 2>/dev/null | tr ' ' '\n' | grep -v GroupMembership | while read -r user; do
        # Check if user was created recently
        if [ ! -z "$user" ]; then
            local user_created=$(dscl . -read /Users/"$user" accountCreated 2>/dev/null)
            if [ ! -z "$user_created" ]; then
                # If created in last 30 days, flag it
                log_indicator "HIGH" "Recent Admin User" "Admin user '$user' was created recently"
            fi
        fi
    done
    
    # Check for hidden users
    dscl . -list /Users | while read -r user; do
        if [[ "$user" =~ ^\. ]] && [[ "$user" != ".localized" ]]; then
            log_indicator "CRITICAL" "Hidden User Account" "Hidden user found: $user"
        fi
    done
    
    # Check SSH authorized keys
    find /Users -name "authorized_keys" 2>/dev/null | while read -r authkeys; do
        if [ -f "$authkeys" ]; then
            local key_count=$(wc -l < "$authkeys")
            if [ "$key_count" -gt 0 ]; then
                log_indicator "MEDIUM" "SSH Authorized Keys" "Found $key_count keys in $authkeys"
            fi
        fi
    done
}

# --- 9. Check Historical Logs ---
check_historical_logs() {
    echo -e "\n${BCyan}Checking historical logs for compromise indicators...${Color_Off}"
    
    # Check for sudo usage from unusual locations
    log show --predicate 'process == "sudo"' --style syslog --last 30d 2>/dev/null | \
        grep -E "(/tmp/|/var/tmp/|Downloads)" > /dev/null && \
        log_indicator "HIGH" "Suspicious Sudo Usage" "Sudo executed from temporary directory"
    
    # Check for authentication failures followed by success (brute force)
    local auth_failures=$(log show --predicate 'process == "loginwindow"' --style syslog --last 7d 2>/dev/null | \
        grep -c "authentication failed" || echo 0)
    
    if [ "$auth_failures" -gt 50 ]; then
        log_indicator "HIGH" "Brute Force Attempts" "$auth_failures authentication failures in past week"
    fi
    
    # Check for security tool tampering
    log show --predicate 'process == "spctl" OR process == "XProtect" OR process == "MRT"' --style syslog --last 30d 2>/dev/null | \
        grep -E "(disabled|failed|error)" > /dev/null && \
        log_indicator "HIGH" "Security Tool Tampering" "Security tools show errors or disabled state"
}

# --- 10. Memory Analysis ---
check_memory_indicators() {
    echo -e "\n${BCyan}Checking memory for compromise indicators...${Color_Off}"
    
    # Check for process injection indicators
    ps aux | while read -r line; do
        local pid=$(echo "$line" | awk '{print $2}')
        [[ "$pid" == "PID" ]] && continue
        
        # Check for suspicious memory patterns
        if vmmap "$pid" 2>/dev/null | grep -E "(MALLOC_TINY.*rwx|__TEXT.*rw-)" > /dev/null; then
            local proc_name=$(ps -p "$pid" -o comm= 2>/dev/null)
            log_indicator "HIGH" "Process Injection Indicator" "PID $pid ($proc_name) has suspicious memory permissions"
        fi
    done 2>/dev/null
    
    # Check for suspicious shared memory segments
    if ipcs -m 2>/dev/null | grep -E "666|777" > /dev/null; then
        log_indicator "MEDIUM" "Insecure Shared Memory" "World-writable shared memory segments found"
    fi
}

# --- Generate Compromise Assessment ---
generate_assessment() {
    echo -e "\n${BWhite}========== COMPROMISE DETECTION REPORT ==========${Color_Off}"
    
    {
        echo "===== macOS COMPROMISE DETECTION REPORT ====="
        echo "Generated: $(date)"
        echo "Hostname: $(hostname)"
        echo "macOS Version: $(sw_vers -productVersion)"
        echo
        echo "===== EXECUTIVE SUMMARY ====="
        echo "Compromise Score: $COMPROMISE_SCORE"
        echo "Indicators Found: ${#INDICATORS_FOUND[@]}"
        echo
        
        if [ "$COMPROMISE_SCORE" -eq 0 ]; then
            echo "Assessment: NO COMPROMISE DETECTED"
            echo "Status: System appears clean"
        elif [ "$COMPROMISE_SCORE" -lt 10 ]; then
            echo "Assessment: LOW RISK"
            echo "Status: Minor security concerns detected"
        elif [ "$COMPROMISE_SCORE" -lt 30 ]; then
            echo "Assessment: MEDIUM RISK"
            echo "Status: Suspicious activity detected - investigation recommended"
        elif [ "$COMPROMISE_SCORE" -lt 50 ]; then
            echo "Assessment: HIGH RISK"
            echo "Status: Strong indicators of compromise - immediate action required"
        else
            echo "Assessment: CRITICAL - SYSTEM COMPROMISED"
            echo "Status: Multiple compromise indicators - isolate system immediately"
        fi
        
        echo
        echo "===== INDICATORS FOUND ====="
        if [ ${#INDICATORS_FOUND[@]} -eq 0 ]; then
            echo "No compromise indicators detected."
        else
            printf '%s\n' "${INDICATORS_FOUND[@]}"
        fi
        
        echo
        echo "===== RECOMMENDATIONS ====="
        if [ "$COMPROMISE_SCORE" -gt 30 ]; then
            echo "1. IMMEDIATELY isolate this system from the network"
            echo "2. Preserve system state for forensic analysis"
            echo "3. Do not login to sensitive accounts from this system"
            echo "4. Contact security team or consider professional incident response"
            echo "5. Begin containment and eradication procedures"
        elif [ "$COMPROMISE_SCORE" -gt 10 ]; then
            echo "1. Run a full antivirus scan with updated definitions"
            echo "2. Review and remove suspicious applications"
            echo "3. Change all passwords from a clean system"
            echo "4. Enable additional logging and monitoring"
            echo "5. Consider reimaging if suspicious activity continues"
        else
            echo "1. Keep security software updated"
            echo "2. Monitor system for unusual activity"
            echo "3. Review security settings regularly"
            echo "4. Maintain good security hygiene"
        fi
    } | tee "$REPORT_FILE"
    
    # Visual indicator
    echo
    if [ "$COMPROMISE_SCORE" -eq 0 ]; then
        echo -e "${BGreen}✓ SYSTEM CLEAN${Color_Off}"
    elif [ "$COMPROMISE_SCORE" -lt 30 ]; then
        echo -e "${BYellow}⚠ SUSPICIOUS ACTIVITY DETECTED${Color_Off}"
    else
        echo -e "${BRed}✗ SYSTEM LIKELY COMPROMISED${Color_Off}"
    fi
    
    echo
    echo -e "${BCyan}Full report saved to: $REPORT_FILE${Color_Off}"
}

# --- Main Execution ---
main() {
    echo -e "${BBlue}======================================${Color_Off}"
    echo -e "${BBlue}   macOS Compromise Detection Tool${Color_Off}"
    echo -e "${BBlue}======================================${Color_Off}"
    echo
    
    # Check for root privileges
    if [ "$EUID" -ne 0 ]; then
        echo -e "${BRed}Error: This script requires sudo privileges${Color_Off}"
        echo "Please run: sudo $0"
        exit 1
    fi
    
    echo -e "${BYellow}Starting comprehensive compromise detection...${Color_Off}"
    echo "This may take several minutes to complete."
    echo
    
    # Run all checks
    check_known_malware
    check_persistence
    check_rootkits
    check_network_indicators
    check_browser_compromise
    check_data_exfiltration
    check_system_integrity
    check_user_accounts
    check_historical_logs
    check_memory_indicators
    
    # Generate final assessment
    generate_assessment
    
    # Save indicators for future reference
    printf '%s\n' "${INDICATORS_FOUND[@]}" > "$INDICATORS_FILE" 2>/dev/null
}

# Run main function
main "$@" 