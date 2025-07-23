#!/bin/bash

# ==============================================================================
# macOS Advanced Threat Monitoring System
# ==============================================================================
# Real-time threat detection and monitoring for macOS
# Monitors for:
# - Suspicious processes and network connections
# - Unauthorized system modifications
# - Malware indicators
# - Persistence mechanisms
# - Data exfiltration attempts
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

# --- Configuration ---
MONITOR_DIR="/var/log/macos-threat-monitor"
ALERT_LOG="$MONITOR_DIR/alerts.log"
BASELINE_DIR="$MONITOR_DIR/baselines"
TEMP_DIR="$MONITOR_DIR/temp"

# Create directories
sudo mkdir -p "$MONITOR_DIR" "$BASELINE_DIR" "$TEMP_DIR"
sudo chmod 700 "$MONITOR_DIR"

# --- Logging Functions ---
log_alert() {
    local severity="$1"
    local category="$2"
    local message="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$severity] [$category] $message" | sudo tee -a "$ALERT_LOG"
    
    case "$severity" in
        "CRITICAL") echo -e "${BRed}[CRITICAL]${Color_Off} ${BPurple}[$category]${Color_Off} $message" ;;
        "HIGH") echo -e "${BRed}[HIGH]${Color_Off} ${BPurple}[$category]${Color_Off} $message" ;;
        "MEDIUM") echo -e "${BYellow}[MEDIUM]${Color_Off} ${BPurple}[$category]${Color_Off} $message" ;;
        "LOW") echo -e "${BBlue}[LOW]${Color_Off} ${BPurple}[$category]${Color_Off} $message" ;;
        "INFO") echo -e "${BGreen}[INFO]${Color_Off} ${BPurple}[$category]${Color_Off} $message" ;;
    esac
}

# --- 1. Process Monitoring ---
monitor_processes() {
    log_alert "INFO" "PROCESS" "Starting process monitoring..."
    
    # Check for suspicious process names
    local suspicious_names=(
        "com.apple.updates"  # Fake system process
        "kernel_task_helper" # Fake kernel process
        "syslogd_helper"     # Fake logging process
        "mdworker_shared"    # Fake Spotlight process
    )
    
    for name in "${suspicious_names[@]}"; do
        if pgrep -f "$name" > /dev/null; then
            log_alert "HIGH" "PROCESS" "Suspicious process detected: $name"
        fi
    done
    
    # Check for unsigned processes accessing sensitive areas
    ps aux | while read -r line; do
        local pid=$(echo "$line" | awk '{print $2}')
        local cmd=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i}')
        
        # Skip header and kernel processes
        [[ "$pid" == "PID" ]] && continue
        [[ "$pid" -lt 100 ]] && continue
        
        # Check if process is accessing sensitive directories
        if lsof -p "$pid" 2>/dev/null | grep -E "/System/Library/LaunchDaemons|/Library/LaunchAgents|/private/var/db" > /dev/null; then
            # Check if process is signed
            if ! codesign -v -R="anchor apple" "/proc/$pid/exe" 2>/dev/null; then
                log_alert "MEDIUM" "PROCESS" "Unsigned process accessing sensitive areas: PID $pid - $cmd"
            fi
        fi
    done
    
    # Monitor for process injection
    local injection_indicators=(
        "DYLD_INSERT_LIBRARIES"
        "DYLD_FORCE_FLAT_NAMESPACE"
    )
    
    for var in "${injection_indicators[@]}"; do
        if ps aux | grep -v grep | grep "$var" > /dev/null; then
            log_alert "HIGH" "PROCESS" "Possible process injection detected using $var"
        fi
    done
}

# --- 2. Network Monitoring ---
monitor_network() {
    log_alert "INFO" "NETWORK" "Starting network monitoring..."
    
    # Check for suspicious network connections
    netstat -an | grep ESTABLISHED | while read -r line; do
        local foreign_addr=$(echo "$line" | awk '{print $5}')
        local local_addr=$(echo "$line" | awk '{print $4}')
        
        # Skip local connections
        [[ "$foreign_addr" =~ ^127\. ]] && continue
        [[ "$foreign_addr" =~ ^::1 ]] && continue
        
        # Check for connections to known bad ports
        local bad_ports=(1337 31337 4444 5555 6666 6667 12345)
        for port in "${bad_ports[@]}"; do
            if [[ "$foreign_addr" =~ :$port$ ]]; then
                log_alert "HIGH" "NETWORK" "Connection to suspicious port detected: $foreign_addr"
            fi
        done
        
        # Check for unusual outbound connections
        if [[ "$local_addr" =~ :(22|23|3389|5900)$ ]]; then
            log_alert "MEDIUM" "NETWORK" "Unusual outbound connection from service port: $local_addr -> $foreign_addr"
        fi
    done
    
    # Monitor DNS queries for suspicious domains
    log show --predicate 'process == "mDNSResponder"' --style syslog --last 5m 2>/dev/null | while read -r line; do
        # Check for DGA-like domains (high entropy)
        if echo "$line" | grep -E '[a-z0-9]{20,}\.(com|net|org|info)' > /dev/null; then
            log_alert "MEDIUM" "NETWORK" "Possible DGA domain detected in DNS query"
        fi
        
        # Check for known malicious TLDs
        if echo "$line" | grep -E '\.(tk|ml|ga|cf)' > /dev/null; then
            log_alert "MEDIUM" "NETWORK" "DNS query to suspicious TLD detected"
        fi
    done
}

# --- 3. File System Monitoring ---
monitor_filesystem() {
    log_alert "INFO" "FILESYSTEM" "Starting file system monitoring..."
    
    # Monitor LaunchDaemons and LaunchAgents
    local persistence_dirs=(
        "/System/Library/LaunchDaemons"
        "/Library/LaunchDaemons"
        "/Library/LaunchAgents"
        "$HOME/Library/LaunchAgents"
    )
    
    for dir in "${persistence_dirs[@]}"; do
        if [ -d "$dir" ]; then
            # Create baseline if doesn't exist
            local baseline_file="$BASELINE_DIR/$(echo $dir | tr '/' '_').baseline"
            
            if [ ! -f "$baseline_file" ]; then
                sudo find "$dir" -name "*.plist" -type f | sort > "$baseline_file"
                log_alert "INFO" "FILESYSTEM" "Created baseline for $dir"
            else
                # Compare with baseline
                local current_list="$TEMP_DIR/current_$(echo $dir | tr '/' '_').list"
                sudo find "$dir" -name "*.plist" -type f | sort > "$current_list"
                
                if ! diff "$baseline_file" "$current_list" > /dev/null; then
                    log_alert "HIGH" "FILESYSTEM" "Changes detected in persistence location: $dir"
                    diff "$baseline_file" "$current_list" | grep "^>" | while read -r new_file; do
                        new_file=${new_file#> }
                        log_alert "HIGH" "FILESYSTEM" "New persistence file: $new_file"
                        
                        # Check if it's signed
                        if ! codesign -v "$new_file" 2>/dev/null; then
                            log_alert "CRITICAL" "FILESYSTEM" "Unsigned persistence file detected: $new_file"
                        fi
                    done
                fi
            fi
        fi
    done
    
    # Monitor for hidden files in user directories
    find "$HOME" -name ".*" -type f -mtime -1 2>/dev/null | grep -v -E '\.DS_Store|\.localized|\.bash_|\.zsh_' | while read -r hidden_file; do
        # Check if it's executable
        if [ -x "$hidden_file" ]; then
            log_alert "HIGH" "FILESYSTEM" "New hidden executable file: $hidden_file"
        fi
    done
    
    # Check for world-writable files in system directories
    sudo find /usr/local /opt -perm -002 -type f 2>/dev/null | while read -r writable_file; do
        log_alert "MEDIUM" "FILESYSTEM" "World-writable file in system directory: $writable_file"
    done
}

# --- 4. System Configuration Monitoring ---
monitor_system_config() {
    log_alert "INFO" "SYSTEM" "Starting system configuration monitoring..."
    
    # Check for disabled security features
    if ! csrutil status | grep -q "enabled"; then
        log_alert "CRITICAL" "SYSTEM" "System Integrity Protection is DISABLED!"
    fi
    
    if ! fdesetup status | grep -q "FileVault is On"; then
        log_alert "HIGH" "SYSTEM" "FileVault encryption is DISABLED!"
    fi
    
    if ! /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep -q "enabled"; then
        log_alert "HIGH" "SYSTEM" "Firewall is DISABLED!"
    fi
    
    # Check for suspicious kernel extensions
    kextstat | grep -v com.apple | while read -r line; do
        local kext_name=$(echo "$line" | awk '{print $6}')
        if [ ! -z "$kext_name" ]; then
            log_alert "MEDIUM" "SYSTEM" "Non-Apple kernel extension loaded: $kext_name"
        fi
    done
    
    # Check for modified system files
    local critical_files=(
        "/etc/hosts"
        "/etc/sudoers"
        "/etc/ssh/sshd_config"
    )
    
    for file in "${critical_files[@]}"; do
        if [ -f "$file" ]; then
            # Check modification time
            if find "$file" -mtime -7 2>/dev/null | grep -q "$file"; then
                log_alert "MEDIUM" "SYSTEM" "Critical system file recently modified: $file"
            fi
        fi
    done
}

# --- 5. User Activity Monitoring ---
monitor_user_activity() {
    log_alert "INFO" "USER" "Starting user activity monitoring..."
    
    # Check for failed authentication attempts
    log show --predicate 'process == "loginwindow" OR process == "SecurityAgent"' --style syslog --last 10m 2>/dev/null | grep -i "failed" | while read -r line; do
        log_alert "MEDIUM" "USER" "Failed authentication attempt detected"
    done
    
    # Monitor sudo usage
    log show --predicate 'process == "sudo"' --style syslog --last 10m 2>/dev/null | while read -r line; do
        if echo "$line" | grep -i "incorrect password attempts" > /dev/null; then
            log_alert "HIGH" "USER" "Multiple failed sudo attempts detected"
        fi
    done
    
    # Check for unusual user account changes
    dscl . -list /Users | while read -r user; do
        # Skip system users
        [[ "$user" =~ ^_ ]] && continue
        
        # Check if user has unusual privileges
        if dsmemberutil checkmembership -u "$user" -g admin 2>/dev/null | grep -q "is a member"; then
            # Check if this is a new admin
            if ! grep -q "$user:admin" "$BASELINE_DIR/admin_users.baseline" 2>/dev/null; then
                log_alert "HIGH" "USER" "New admin user detected: $user"
                echo "$user:admin" >> "$BASELINE_DIR/admin_users.baseline"
            fi
        fi
    done
}

# --- 6. Memory Analysis ---
monitor_memory() {
    log_alert "INFO" "MEMORY" "Starting memory monitoring..."
    
    # Look for suspicious memory patterns
    sudo vm_stat | while read -r line; do
        if echo "$line" | grep -q "Pages wired down"; then
            local wired_pages=$(echo "$line" | awk '{print $NF}' | tr -d '.')
            # Alert if wired memory is unusually high (potential rootkit)
            if [ "$wired_pages" -gt 1000000 ]; then
                log_alert "MEDIUM" "MEMORY" "Unusually high wired memory detected"
            fi
        fi
    done
    
    # Check for process memory anomalies
    ps aux | awk '$6 > 500000' | while read -r line; do
        local pid=$(echo "$line" | awk '{print $2}')
        local rss=$(echo "$line" | awk '{print $6}')
        local cmd=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i}')
        
        # Skip known memory-intensive processes
        [[ "$cmd" =~ (Chrome|Safari|Firefox|Xcode) ]] && continue
        
        log_alert "LOW" "MEMORY" "High memory usage: PID $pid ($rss KB) - $cmd"
    done
}

# --- 7. Generate Summary Report ---
generate_report() {
    local report_file="$MONITOR_DIR/threat-report-$(date +%Y%m%d-%H%M%S).txt"
    
    {
        echo "=== macOS Threat Monitoring Report ==="
        echo "Generated: $(date)"
        echo
        echo "=== Alert Summary ==="
        echo "Critical: $(grep -c CRITICAL "$ALERT_LOG" 2>/dev/null || echo 0)"
        echo "High: $(grep -c HIGH "$ALERT_LOG" 2>/dev/null || echo 0)"
        echo "Medium: $(grep -c MEDIUM "$ALERT_LOG" 2>/dev/null || echo 0)"
        echo "Low: $(grep -c LOW "$ALERT_LOG" 2>/dev/null || echo 0)"
        echo
        echo "=== Recent Critical Alerts ==="
        grep CRITICAL "$ALERT_LOG" 2>/dev/null | tail -10 || echo "No critical alerts"
        echo
        echo "=== Recent High Priority Alerts ==="
        grep HIGH "$ALERT_LOG" 2>/dev/null | tail -10 || echo "No high priority alerts"
    } > "$report_file"
    
    echo -e "\n${BGreen}Report saved to: $report_file${Color_Off}"
}

# --- Main Monitoring Loop ---
main() {
    echo -e "${BBlue}======================================${Color_Off}"
    echo -e "${BBlue}   macOS Threat Monitoring System${Color_Off}"
    echo -e "${BBlue}======================================${Color_Off}"
    echo
    
    # Check for root privileges
    if [ "$EUID" -ne 0 ]; then
        echo -e "${BRed}Error: This script must be run with sudo privileges${Color_Off}"
        exit 1
    fi
    
    log_alert "INFO" "SYSTEM" "Threat monitoring system started"
    
    # Continuous monitoring mode
    if [ "${1:-}" == "--continuous" ]; then
        echo -e "${BYellow}Running in continuous monitoring mode. Press Ctrl+C to stop.${Color_Off}"
        while true; do
            monitor_processes
            monitor_network
            monitor_filesystem
            monitor_system_config
            monitor_user_activity
            monitor_memory
            
            echo -e "\n${BCyan}Scan completed. Next scan in 60 seconds...${Color_Off}"
            sleep 60
        done
    else
        # Single scan mode
        monitor_processes
        monitor_network
        monitor_filesystem
        monitor_system_config
        monitor_user_activity
        monitor_memory
        
        generate_report
        
        echo -e "\n${BGreen}Monitoring complete!${Color_Off}"
        echo -e "${BYellow}Run with --continuous for real-time monitoring${Color_Off}"
    fi
}

# Handle interrupts gracefully
trap 'echo -e "\n${BYellow}Monitoring stopped by user${Color_Off}"; exit 0' INT TERM

# Run main function
main "$@" 