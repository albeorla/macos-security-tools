# Quick Reference

## 🚨 Emergency Commands

```bash
# Check if system is compromised
sudo ./macos-compromise-detection.sh

# Emergency lockdown (from Security Center)
sudo ./macos-security-center.sh
# Select option 8

# Collect forensic data
sudo ./macos-security-center.sh
# Select option 6
```

## 🛡️ Common Operations

### First Time Setup
```bash
# 1. Check system status
sudo ./macos-compromise-detection.sh

# 2. Apply security hardening
sudo ./macos-security-hardening.sh

# 3. Start monitoring
sudo ./macos-threat-monitor.sh --continuous
```

### Daily Security Tasks
```bash
# Quick compromise check (Rust - fast)
sudo ./target/release/macos-security detect

# Review threat alerts
sudo tail -f /var/log/macos-threat-monitor/*.log

# Check security status
sudo ./macos-security-center.sh
# Select option 2
```

### Weekly Security Review
```bash
# Full compromise scan
sudo ./macos-compromise-detection.sh

# Review and update hardening
sudo ./macos-security-hardening.sh --check

# Generate executive report
sudo ./macos-security-center.sh
# Select option 7
```

## 🔧 Useful Flags

### Compromise Detection
```bash
# Verbose output
sudo ./macos-compromise-detection.sh -v

# Quick scan (skip deep checks)
sudo ./macos-compromise-detection.sh --quick

# Save report to specific location
sudo ./macos-compromise-detection.sh --output ~/Desktop/report.txt
```

### Threat Monitor
```bash
# Single scan
sudo ./macos-threat-monitor.sh

# Continuous monitoring
sudo ./macos-threat-monitor.sh --continuous

# Monitor specific process
sudo ./macos-threat-monitor.sh --pid 12345
```

### Security Hardening
```bash
# Dry run (show what would change)
sudo ./macos-security-hardening.sh --dry-run

# Check current status
sudo ./macos-security-hardening.sh --check

# Undo specific hardening
sudo ./macos-security-hardening.sh --undo firewall
```

## 📊 Understanding Results

### Compromise Score Ranges
- **0**: Clean system ✅
- **1-10**: Low risk ⚠️
- **11-30**: Medium risk 🟠
- **31-50**: High risk 🔴
- **50+**: Compromised 🚨

### Common False Positives
- Legitimate browser extensions with broad permissions
- Developer tools (Xcode, Docker)
- Security software (antivirus, VPNs)
- Virtual machines

## 🔍 Log Locations

```bash
# View latest alerts
tail -n 50 /var/log/macos-threat-monitor/alerts.log

# Search for specific threat
grep -i "malware" /var/log/macos-compromise-detection/*.log

# Check hardening changes
cat /var/log/macos-security/hardening.log

# Review JSON reports
ls -la /tmp/compromise-report-*.json
```

## 💡 Pro Tips

1. **Run as sudo** - All security tools need admin rights
2. **Check logs regularly** - Set up log rotation
3. **Automate scans** - Use cron for scheduled checks
4. **Keep backups** - Before making security changes
5. **Test first** - Use VMs for testing hardening

## 🆘 Getting Help

```bash
# Built-in help
./macos-security-hardening.sh --help
./macos-threat-monitor.sh --help
./macos-compromise-detection.sh --help

# Check tool versions
./target/release/macos-security --version

# Debug mode
DEBUG=1 sudo ./macos-compromise-detection.sh
``` 