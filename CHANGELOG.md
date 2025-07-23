# Changelog

All notable changes to macOS Security Tools will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Rust implementation of compromise detection (16x performance improvement)
- Comprehensive documentation structure
- Quick reference guide for common operations
- Installation guide with troubleshooting
- JSON export for compromise detection reports

### Changed
- Reorganized documentation into `docs/` directory
- Updated README with clearer structure and links
- Improved .gitignore for Rust development

### Removed
- Legacy Python scripts (main.py)
- Duplicate README-SECURITY.md file
- Old installation scripts

## [1.0.0] - 2024-01-23

### Added
- Initial release with four core bash scripts:
  - `macos-security-hardening.sh` - System hardening based on NIST/CIS
  - `macos-threat-monitor.sh` - Real-time threat monitoring
  - `macos-compromise-detection.sh` - Deep forensic analysis
  - `macos-security-center.sh` - Unified security operations
- Comprehensive logging system
- Scoring system for compromise detection
- Emergency response capabilities
- Support for macOS 10.15+

### Security
- All scripts require sudo for system-level operations
- Logs contain sensitive information and are protected
- No data is sent externally

## [0.9.0] - 2024-01-20 (Pre-release)

### Added
- Beta versions of security scripts
- Basic threat detection capabilities
- Initial hardening recommendations

### Known Issues
- Some false positives in browser extension detection
- Performance optimization needed for large file scans

---

## Future Releases

### [1.1.0] - Planned
- Complete Rust migration for all tools
- Web UI for remote monitoring
- Enhanced malware signature database
- Automated response actions

### [2.0.0] - Planned
- Full security orchestration platform
- Integration with enterprise SIEM
- Machine learning for anomaly detection
- Cross-platform support (Linux) 