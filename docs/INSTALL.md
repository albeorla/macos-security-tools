# Installation Guide

## Prerequisites

### System Requirements
- macOS 10.15 (Catalina) or later
- Administrator (sudo) access
- At least 1GB free disk space
- Internet connection for dependency installation

### For Bash Scripts
- Homebrew package manager
- bash 4.0 or later (installed by default)

### For Rust Version
- Rust toolchain (rustc, cargo)
- Xcode Command Line Tools

## Installing Bash Scripts

### 1. Clone the Repository
```bash
git clone https://github.com/albeorla/macos-security-tools.git
cd macos-security-tools
```

### 2. Install Dependencies
```bash
# Make install script executable
chmod +x install-secure

# Run installation (requires sudo)
sudo ./install-secure
```

This installs:
- Suricata (Network IDS)
- ClamAV (Antivirus)
- osquery (System monitoring)
- yara (Malware detection)
- Python dependencies

### 3. Verify Installation
```bash
# Check if tools are installed
which suricata
which clamscan
which osqueryi
which yara
```

## Installing Rust Version

### 1. Install Rust (if not already installed)
```bash
# Install rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add to PATH
source $HOME/.cargo/env

# Verify installation
rustc --version
cargo --version
```

### 2. Build from Source
```bash
# In the project directory
cargo build --release

# The binary will be at:
# ./target/release/macos-security
```

### 3. Optional: Install System-wide
```bash
# Copy to system bin
sudo cp target/release/macos-security /usr/local/bin/

# Now you can run from anywhere:
macos-security --help
```

## Quick Verification

### Test Bash Scripts
```bash
# Test each component
sudo ./macos-security-hardening.sh --help
sudo ./macos-threat-monitor.sh --help
sudo ./macos-compromise-detection.sh --help
sudo ./macos-security-center.sh --help
```

### Test Rust Binary
```bash
# If installed locally
./target/release/macos-security --help

# If installed system-wide
macos-security --help
```

## Troubleshooting

### Homebrew Issues
```bash
# Update Homebrew
brew update
brew upgrade

# Fix permissions
sudo chown -R $(whoami) /usr/local/bin /usr/local/lib
```

### Rust Build Errors
```bash
# Clean build
cargo clean
cargo build --release

# Update dependencies
cargo update
```

### Permission Errors
- Most tools require sudo access
- For Full Disk Access, grant Terminal.app permissions in System Preferences > Security & Privacy

### macOS Compatibility
- Tested on macOS 11 (Big Sur) through macOS 14 (Sonoma)
- Apple Silicon (M1/M2) and Intel both supported
- Some features may require disabling SIP (not recommended)

## Next Steps

After installation:
1. Run a compromise detection scan: `sudo ./macos-compromise-detection.sh`
2. Review security hardening options: `sudo ./macos-security-hardening.sh --dry-run`
3. Set up monitoring: `sudo ./macos-threat-monitor.sh`
4. Explore the Security Center: `sudo ./macos-security-center.sh` 