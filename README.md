# macOS Security Suite

A comprehensive collection of enterprise-grade security tools for macOS systems. This suite provides deep security hardening, threat monitoring, compromise detection, and incident response capabilities.

## 🚨 Important Notice

These scripts make significant security changes to your macOS system. Always:
- Create a full backup before running any security scripts
- Test in a non-production environment first
- Understand what each script does before execution
- Keep logs of all changes for potential rollback

## 📋 Tool Overview

### 1. **macOS Security Operations Center** (`macos-security-center.sh`)
Central command interface for all security operations.

```bash
sudo ./macos-security-center.sh
```

Features:
- Interactive menu system
- Security status dashboard
- Integrates all other tools
- Executive reporting
- Incident management

### 2. **Security Hardening** (`macos-security-hardening.sh`)
Implements NIST and CIS benchmark security controls.

```bash
sudo ./macos-security-hardening.sh
```

Hardens:
- FileVault encryption
- Firewall configuration
- Privacy settings
- Network security
- Access controls
- Application security

### 3. **Compromise Detection** (`macos-compromise-detection.sh`)
Deep forensic analysis to detect if your system has been compromised.

```bash
sudo ./macos-compromise-detection.sh
```

Checks for:
- Known malware signatures
- Persistence mechanisms
- Rootkit indicators
- Network backdoors
- Browser compromise
- Data exfiltration
- Hidden user accounts
- System integrity

**Compromise Scoring:**
- 0: System Clean
- 1-10: Low Risk
- 11-30: Medium Risk
- 31-50: High Risk
- 50+: Critical - System Compromised

### 4. **Threat Monitoring** (`macos-threat-monitor.sh`)
Real-time monitoring for active threats and suspicious activity.

```bash
# Single scan
sudo ./macos-threat-monitor.sh

# Continuous monitoring
sudo ./macos-threat-monitor.sh --continuous
```

Monitors:
- Process activity
- Network connections
- File system changes
- System configuration
- User activity
- Memory anomalies

### 5. **Legacy Tools**

#### Network Monitoring (`run`)
Configures and launches Suricata NIDS for network traffic monitoring.

```bash
sudo ./run
```

#### System Introspection (`main.py`)
Python-based security audit tool for system analysis.

```bash
sudo python3 main.py
```

## 🚀 Quick Start

1. **Initial Security Assessment:**
   ```bash
   sudo ./macos-compromise-detection.sh
   ```

2. **If System is Clean, Harden It:**
   ```bash
   sudo ./macos-security-hardening.sh
   ```

3. **Enable Ongoing Monitoring:**
   ```bash
   sudo ./macos-threat-monitor.sh --continuous
   ```

4. **For Complete Control:**
   ```bash
   sudo ./macos-security-center.sh
   ```

## 📊 Security Logs and Reports

All tools generate detailed logs in:
- `/var/log/macos-security/` - Hardening changes
- `/var/log/macos-threat-monitor/` - Threat alerts
- `/var/log/macos-compromise-detection/` - Compromise reports
- `/var/log/macos-soc/` - Security operations center logs

## 🔴 Emergency Response

If compromise is detected:

1. **Immediate Actions:**
   - Run Emergency Lockdown (Option 8 in Security Center)
   - Isolate system from network
   - Preserve evidence

2. **Investigation:**
   - Run Forensics Collection (Option 6)
   - Review all security logs
   - Document all findings

3. **Recovery:**
   - Change all passwords from a clean system
   - Review and revoke all access tokens
   - Consider full system reinstall

## ⚠️ Known Limitations

- Some checks require macOS 13+ (Ventura or newer)
- Apple Silicon Macs have better security features than Intel
- SIP must be enabled for maximum security
- Some features may impact system performance

## 🛡️ Security Best Practices

1. **Regular Scans:** Run compromise detection weekly
2. **Monitor Alerts:** Check threat monitoring logs daily
3. **Update Regularly:** Keep macOS and all apps updated
4. **Backup Often:** Maintain offline backups
5. **User Training:** Educate users on security threats

## 📝 Compliance

These tools help meet requirements for:
- NIST Cybersecurity Framework
- CIS macOS Benchmarks
- SOC 2 Type II
- HIPAA Security Rule
- PCI DSS

## 🤝 Contributing

To improve these tools:
1. Test thoroughly in isolated environments
2. Document all changes
3. Follow existing code style
4. Add appropriate error handling
5. Update this README

## ⚖️ License

These tools are provided as-is for security professionals. Use at your own risk. Not responsible for any system damage or data loss.

## 🆘 Support

For issues or questions:
1. Check existing logs for error details
2. Run with verbose/debug flags where available
3. Ensure you have admin privileges
4. Verify macOS compatibility

---

**Remember:** Security is a journey, not a destination. Stay vigilant! 🔒 