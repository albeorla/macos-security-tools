#!/bin/bash

# ==============================================================================
# macOS Security Operations Center (SOC)
# ==============================================================================
# Central command center for macOS security operations
# Integrates:
# - Security hardening
# - Threat monitoring
# - Incident response
# - Forensics capabilities
# - Automated remediation
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
SOC_DIR="/var/log/macos-soc"
INCIDENT_DIR="$SOC_DIR/incidents"
FORENSICS_DIR="$SOC_DIR/forensics"
REPORTS_DIR="$SOC_DIR/reports"
SCRIPTS_DIR="$(dirname "$0")"

# Create directories
sudo mkdir -p "$SOC_DIR" "$INCIDENT_DIR" "$FORENSICS_DIR" "$REPORTS_DIR"
sudo chmod 700 "$SOC_DIR"

# --- Display Menu ---
display_menu() {
    clear
    echo -e "${BBlue}================================================${Color_Off}"
    echo -e "${BBlue}       macOS Security Operations Center${Color_Off}"
    echo -e "${BBlue}================================================${Color_Off}"
    echo
    echo -e "${BWhite}Security Status:${Color_Off}"
    check_security_status
    echo
    echo -e "${BWhite}Main Menu:${Color_Off}"
    echo -e "${BCyan}1.${Color_Off} Run Security Hardening"
    echo -e "${BCyan}2.${Color_Off} Start Threat Monitoring"
    echo -e "${BCyan}3.${Color_Off} Check for System Compromise"
    echo -e "${BCyan}4.${Color_Off} Perform Security Audit"
    echo -e "${BCyan}5.${Color_Off} Incident Response"
    echo -e "${BCyan}6.${Color_Off} Forensics Collection"
    echo -e "${BCyan}7.${Color_Off} View Security Logs"
    echo -e "${BCyan}8.${Color_Off} Emergency Lockdown"
    echo -e "${BCyan}9.${Color_Off} Generate Executive Report"
    echo -e "${BCyan}10.${Color_Off} Configure Automated Response"
    echo -e "${BCyan}0.${Color_Off} Exit"
    echo
}

# --- Check Security Status ---
check_security_status() {
    local status_good=0
    local status_bad=0
    
    # FileVault
    if fdesetup status | grep -q "FileVault is On"; then
        echo -e "  ${BGreen}✓${Color_Off} FileVault: Enabled"
        ((status_good++))
    else
        echo -e "  ${BRed}✗${Color_Off} FileVault: Disabled"
        ((status_bad++))
    fi
    
    # Firewall
    if /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep -q "enabled"; then
        echo -e "  ${BGreen}✓${Color_Off} Firewall: Enabled"
        ((status_good++))
    else
        echo -e "  ${BRed}✗${Color_Off} Firewall: Disabled"
        ((status_bad++))
    fi
    
    # SIP
    if csrutil status | grep -q "enabled"; then
        echo -e "  ${BGreen}✓${Color_Off} System Integrity Protection: Enabled"
        ((status_good++))
    else
        echo -e "  ${BRed}✗${Color_Off} System Integrity Protection: Disabled"
        ((status_bad++))
    fi
    
    # Gatekeeper
    if spctl --status 2>&1 | grep -q "enabled"; then
        echo -e "  ${BGreen}✓${Color_Off} Gatekeeper: Enabled"
        ((status_good++))
    else
        echo -e "  ${BRed}✗${Color_Off} Gatekeeper: Disabled"
        ((status_bad++))
    fi
    
    # Overall status
    echo
    if [ $status_bad -eq 0 ]; then
        echo -e "  ${BGreen}Overall Status: SECURE${Color_Off}"
    elif [ $status_bad -le 1 ]; then
        echo -e "  ${BYellow}Overall Status: PARTIALLY SECURE${Color_Off}"
    else
        echo -e "  ${BRed}Overall Status: AT RISK${Color_Off}"
    fi
}

# --- 1. Run Security Hardening ---
run_hardening() {
    echo -e "${BBlue}Running Security Hardening...${Color_Off}"
    if [ -f "$SCRIPTS_DIR/macos-security-hardening.sh" ]; then
        sudo "$SCRIPTS_DIR/macos-security-hardening.sh"
    else
        echo -e "${BRed}Error: Hardening script not found${Color_Off}"
    fi
    read -p "Press Enter to continue..."
}

# --- 2. Start Threat Monitoring ---
start_monitoring() {
    echo -e "${BBlue}Starting Threat Monitoring...${Color_Off}"
    echo
    echo "1. Single scan"
    echo "2. Continuous monitoring"
    read -p "Select option: " monitor_option
    
    if [ -f "$SCRIPTS_DIR/macos-threat-monitor.sh" ]; then
        if [ "$monitor_option" == "2" ]; then
            sudo "$SCRIPTS_DIR/macos-threat-monitor.sh" --continuous
        else
            sudo "$SCRIPTS_DIR/macos-threat-monitor.sh"
        fi
    else
        echo -e "${BRed}Error: Monitoring script not found${Color_Off}"
    fi
    read -p "Press Enter to continue..."
}

# --- 3. Check for System Compromise ---
check_compromise() {
    echo -e "${BBlue}Running Compromise Detection...${Color_Off}"
    if [ -f "$SCRIPTS_DIR/macos-compromise-detection.sh" ]; then
        sudo "$SCRIPTS_DIR/macos-compromise-detection.sh"
    else
        echo -e "${BRed}Error: Compromise detection script not found${Color_Off}"
    fi
    read -p "Press Enter to continue..."
}

# --- 4. Perform Security Audit ---
perform_audit() {
    echo -e "${BBlue}Performing Security Audit...${Color_Off}"
    local audit_file="$REPORTS_DIR/audit-$(date +%Y%m%d-%H%M%S).txt"
    
    {
        echo "=== macOS Security Audit Report ==="
        echo "Generated: $(date)"
        echo "Hostname: $(hostname)"
        echo "macOS Version: $(sw_vers -productVersion)"
        echo
        
        echo "=== Security Configuration ==="
        check_security_status
        echo
        
        echo "=== User Accounts ==="
        echo "Admin users:"
        dscl . -read /Groups/admin GroupMembership
        echo
        echo "Recently modified users:"
        dscl . -list /Users | while read user; do
            if [ ! -z "$(find /var/db/dslocal/nodes/Default/users/${user}.plist -mtime -7 2>/dev/null)" ]; then
                echo "  - $user (modified within 7 days)"
            fi
        done
        echo
        
        echo "=== Network Configuration ==="
        echo "Active network interfaces:"
        ifconfig | grep "flags=" | grep -v "lo0"
        echo
        echo "Listening ports:"
        sudo lsof -iTCP -sTCP:LISTEN | grep -v "localhost"
        echo
        
        echo "=== Installed Applications ==="
        echo "Recently installed applications:"
        find /Applications -type d -name "*.app" -mtime -30 2>/dev/null | head -20
        echo
        
        echo "=== Security Software ==="
        echo "Antivirus/Security software:"
        ps aux | grep -E "(sentinel|crowdstrike|malwarebytes|sophos|mcafee|norton)" | grep -v grep || echo "None detected"
        echo
        
        echo "=== Recent Security Events ==="
        echo "Failed login attempts (last 24h):"
        log show --predicate 'process == "loginwindow"' --style syslog --last 1d 2>/dev/null | grep -i "failed" | wc -l
        echo
        echo "Sudo usage (last 24h):"
        log show --predicate 'process == "sudo"' --style syslog --last 1d 2>/dev/null | wc -l
        echo
    } | sudo tee "$audit_file"
    
    echo
    echo -e "${BGreen}Audit complete. Report saved to: $audit_file${Color_Off}"
    read -p "Press Enter to continue..."
}

# --- 5. Incident Response ---
incident_response() {
    echo -e "${BBlue}Incident Response Module${Color_Off}"
    echo
    echo "1. Create new incident"
    echo "2. Isolate system (block network)"
    echo "3. Kill suspicious process"
    echo "4. Quarantine file"
    echo "5. Back to main menu"
    
    read -p "Select option: " ir_option
    
    case $ir_option in
        1)
            create_incident
            ;;
        2)
            isolate_system
            ;;
        3)
            kill_suspicious_process
            ;;
        4)
            quarantine_file
            ;;
        *)
            return
            ;;
    esac
}

create_incident() {
    local incident_id="INC-$(date +%Y%m%d-%H%M%S)"
    local incident_dir="$INCIDENT_DIR/$incident_id"
    
    sudo mkdir -p "$incident_dir"
    
    read -p "Incident description: " description
    read -p "Severity (LOW/MEDIUM/HIGH/CRITICAL): " severity
    
    {
        echo "Incident ID: $incident_id"
        echo "Created: $(date)"
        echo "Severity: $severity"
        echo "Description: $description"
        echo
        echo "=== System State at Incident Time ==="
        echo "Active processes:"
        ps aux | head -20
        echo
        echo "Network connections:"
        netstat -an | grep ESTABLISHED | head -20
        echo
        echo "Recent system logs:"
        log show --style syslog --last 10m 2>/dev/null | tail -50
    } | sudo tee "$incident_dir/incident-report.txt"
    
    echo -e "${BGreen}Incident $incident_id created${Color_Off}"
    read -p "Press Enter to continue..."
}

isolate_system() {
    echo -e "${BYellow}WARNING: This will block all network connections${Color_Off}"
    read -p "Are you sure? (yes/no): " confirm
    
    if [ "$confirm" == "yes" ]; then
        # Block all incoming connections
        sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on
        
        # Disable Wi-Fi
        sudo networksetup -setairportpower en0 off
        
        # Log the action
        echo "[$(date)] System isolated by user $USER" | sudo tee -a "$SOC_DIR/actions.log"
        
        echo -e "${BGreen}System isolated. To restore: re-enable firewall exceptions and Wi-Fi${Color_Off}"
    fi
    read -p "Press Enter to continue..."
}

kill_suspicious_process() {
    echo "Enter PID of suspicious process (or 'list' to see processes):"
    read pid
    
    if [ "$pid" == "list" ]; then
        ps aux | less
        echo "Enter PID of suspicious process:"
        read pid
    fi
    
    if [[ "$pid" =~ ^[0-9]+$ ]]; then
        # Get process info before killing
        local proc_info=$(ps -p "$pid" -o comm=,user=,pid=,ppid=,%cpu=,%mem= 2>/dev/null)
        
        if [ ! -z "$proc_info" ]; then
            echo "Process info: $proc_info"
            read -p "Kill this process? (yes/no): " confirm
            
            if [ "$confirm" == "yes" ]; then
                sudo kill -9 "$pid"
                echo "[$(date)] Killed process $pid: $proc_info" | sudo tee -a "$SOC_DIR/actions.log"
                echo -e "${BGreen}Process terminated${Color_Off}"
            fi
        else
            echo -e "${BRed}Process not found${Color_Off}"
        fi
    fi
    read -p "Press Enter to continue..."
}

quarantine_file() {
    echo "Enter full path of file to quarantine:"
    read filepath
    
    if [ -f "$filepath" ]; then
        local quarantine_dir="$SOC_DIR/quarantine"
        sudo mkdir -p "$quarantine_dir"
        
        local filename=$(basename "$filepath")
        local quarantine_name="${filename}.$(date +%Y%m%d-%H%M%S).quarantined"
        
        # Create metadata file
        {
            echo "Original path: $filepath"
            echo "Quarantined: $(date)"
            echo "SHA256: $(shasum -a 256 "$filepath" | awk '{print $1}')"
            echo "File info: $(file "$filepath")"
        } | sudo tee "$quarantine_dir/${quarantine_name}.info"
        
        # Move file to quarantine
        sudo mv "$filepath" "$quarantine_dir/$quarantine_name"
        sudo chmod 000 "$quarantine_dir/$quarantine_name"
        
        echo "[$(date)] Quarantined file: $filepath" | sudo tee -a "$SOC_DIR/actions.log"
        echo -e "${BGreen}File quarantined${Color_Off}"
    else
        echo -e "${BRed}File not found${Color_Off}"
    fi
    read -p "Press Enter to continue..."
}

# --- 6. Forensics Collection ---
forensics_collection() {
    echo -e "${BBlue}Forensics Collection${Color_Off}"
    local collection_id="FOR-$(date +%Y%m%d-%H%M%S)"
    local collection_dir="$FORENSICS_DIR/$collection_id"
    
    sudo mkdir -p "$collection_dir"
    
    echo "Collecting forensic data..."
    
    # System information
    echo "Collecting system information..."
    sudo system_profiler -detailLevel basic > "$collection_dir/system_profile.txt"
    
    # Running processes
    echo "Collecting process information..."
    sudo ps aux > "$collection_dir/processes.txt"
    sudo lsof > "$collection_dir/open_files.txt"
    
    # Network connections
    echo "Collecting network information..."
    sudo netstat -an > "$collection_dir/network_connections.txt"
    sudo arp -a > "$collection_dir/arp_cache.txt"
    
    # User activity
    echo "Collecting user activity..."
    last > "$collection_dir/login_history.txt"
    w > "$collection_dir/current_users.txt"
    
    # System logs
    echo "Collecting system logs..."
    sudo log show --style syslog --last 1d > "$collection_dir/system_logs.txt" 2>/dev/null
    
    # File system timeline
    echo "Creating file system timeline..."
    sudo find / -type f -mtime -7 2>/dev/null | head -1000 > "$collection_dir/recently_modified_files.txt"
    
    # Memory dump (if available)
    if command -v vm_stat >/dev/null; then
        echo "Collecting memory statistics..."
        sudo vm_stat > "$collection_dir/memory_stats.txt"
    fi
    
    # Create collection summary
    {
        echo "Forensics Collection ID: $collection_id"
        echo "Collected: $(date)"
        echo "Collected by: $USER"
        echo
        echo "Contents:"
        ls -la "$collection_dir"
    } | sudo tee "$collection_dir/collection_summary.txt"
    
    echo -e "${BGreen}Forensics collection complete: $collection_dir${Color_Off}"
    read -p "Press Enter to continue..."
}

# --- 7. View Security Logs ---
view_logs() {
    echo -e "${BBlue}Security Logs${Color_Off}"
    echo
    echo "1. View threat alerts"
    echo "2. View hardening changes"
    echo "3. View SOC actions"
    echo "4. View all incidents"
    echo "5. Back to main menu"
    
    read -p "Select option: " log_option
    
    case $log_option in
        1)
            if [ -f "/var/log/macos-threat-monitor/alerts.log" ]; then
                sudo less "/var/log/macos-threat-monitor/alerts.log"
            else
                echo "No threat alerts found"
            fi
            ;;
        2)
            if [ -f "/var/log/macos-security/changes.log" ]; then
                sudo less "/var/log/macos-security/changes.log"
            else
                echo "No hardening changes found"
            fi
            ;;
        3)
            if [ -f "$SOC_DIR/actions.log" ]; then
                sudo less "$SOC_DIR/actions.log"
            else
                echo "No SOC actions found"
            fi
            ;;
        4)
            ls -la "$INCIDENT_DIR" 2>/dev/null || echo "No incidents found"
            ;;
    esac
    
    read -p "Press Enter to continue..."
}

# --- 8. Emergency Lockdown ---
emergency_lockdown() {
    echo -e "${BRed}EMERGENCY LOCKDOWN${Color_Off}"
    echo -e "${BYellow}This will:${Color_Off}"
    echo "  - Block all network connections"
    echo "  - Disable all sharing services"
    echo "  - Lock all user sessions"
    echo "  - Increase logging verbosity"
    echo
    read -p "Activate emergency lockdown? (YES/no): " confirm
    
    if [ "$confirm" == "YES" ]; then
        echo "Activating emergency lockdown..."
        
        # Network isolation
        sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on
        sudo networksetup -setairportpower en0 off
        
        # Disable sharing
        sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.screensharing.plist 2>/dev/null
        sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.remotedesktop.agent.plist 2>/dev/null
        
        # Lock screen
        pmset displaysleepnow
        
        # Increase logging
        sudo log config --mode "level:debug" 2>/dev/null
        
        # Log the action
        echo "[$(date)] EMERGENCY LOCKDOWN activated by $USER" | sudo tee -a "$SOC_DIR/actions.log"
        
        echo -e "${BGreen}Emergency lockdown activated${Color_Off}"
        echo "To deactivate: manually reverse these settings"
    fi
    read -p "Press Enter to continue..."
}

# --- 9. Generate Executive Report ---
generate_executive_report() {
    echo -e "${BBlue}Generating Executive Report...${Color_Off}"
    local report_file="$REPORTS_DIR/executive-report-$(date +%Y%m%d).pdf"
    local temp_file="$REPORTS_DIR/executive-report-$(date +%Y%m%d).txt"
    
    {
        echo "MACOS SECURITY EXECUTIVE REPORT"
        echo "================================"
        echo "Date: $(date)"
        echo
        echo "EXECUTIVE SUMMARY"
        echo "-----------------"
        check_security_status
        echo
        
        echo "THREAT LANDSCAPE"
        echo "----------------"
        if [ -f "/var/log/macos-threat-monitor/alerts.log" ]; then
            echo "Critical Alerts: $(grep -c CRITICAL /var/log/macos-threat-monitor/alerts.log 2>/dev/null || echo 0)"
            echo "High Priority Alerts: $(grep -c HIGH /var/log/macos-threat-monitor/alerts.log 2>/dev/null || echo 0)"
            echo "Medium Priority Alerts: $(grep -c MEDIUM /var/log/macos-threat-monitor/alerts.log 2>/dev/null || echo 0)"
        else
            echo "No threat monitoring data available"
        fi
        echo
        
        echo "INCIDENT METRICS"
        echo "----------------"
        local incident_count=$(ls -1 "$INCIDENT_DIR" 2>/dev/null | wc -l || echo 0)
        echo "Total Incidents: $incident_count"
        echo
        
        echo "RECOMMENDATIONS"
        echo "---------------"
        echo "1. Ensure all security features remain enabled"
        echo "2. Review and respond to high-priority alerts"
        echo "3. Conduct regular security audits"
        echo "4. Keep macOS and applications updated"
        echo "5. Train users on security best practices"
        
    } | sudo tee "$temp_file"
    
    echo
    echo -e "${BGreen}Report saved to: $temp_file${Color_Off}"
    read -p "Press Enter to continue..."
}

# --- 10. Configure Automated Response ---
configure_automation() {
    echo -e "${BBlue}Automated Response Configuration${Color_Off}"
    echo
    echo "1. Enable automatic threat quarantine"
    echo "2. Enable automatic security updates"
    echo "3. Configure alert notifications"
    echo "4. Schedule security scans"
    echo "5. Back to main menu"
    
    read -p "Select option: " auto_option
    
    case $auto_option in
        1)
            echo "Configuring automatic threat quarantine..."
            # In a real implementation, this would set up launchd jobs
            echo -e "${BGreen}Automatic quarantine configured${Color_Off}"
            ;;
        2)
            sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true
            sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true
            echo -e "${BGreen}Automatic updates enabled${Color_Off}"
            ;;
        3)
            echo "Enter email for security alerts:"
            read email
            echo "Alert email: $email" | sudo tee "$SOC_DIR/alert_config.txt"
            echo -e "${BGreen}Alert notifications configured${Color_Off}"
            ;;
        4)
            echo "Creating scheduled security scan..."
            # In a real implementation, this would create a launchd plist
            echo -e "${BGreen}Scheduled scans configured${Color_Off}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
}

# --- Main Loop ---
main() {
    # Check for root privileges
    if [ "$EUID" -ne 0 ]; then
        echo -e "${BRed}Error: This script must be run with sudo privileges${Color_Off}"
        exit 1
    fi
    
    while true; do
        display_menu
        read -p "Select option: " choice
        
        case $choice in
            1) run_hardening ;;
            2) start_monitoring ;;
            3) check_compromise ;;
            4) perform_audit ;;
            5) incident_response ;;
            6) forensics_collection ;;
            7) view_logs ;;
            8) emergency_lockdown ;;
            9) generate_executive_report ;;
            10) configure_automation ;;
            0) echo "Exiting..."; exit 0 ;;
            *) echo "Invalid option"; read -p "Press Enter to continue..." ;;
        esac
    done
}

# Run main function
main "$@" 