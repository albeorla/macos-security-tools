use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::Path,
    process::Command,
    time::SystemTime,
};
use tracing::warn;

#[derive(Parser)]
#[command(name = "macos-security")]
#[command(about = "Enterprise-grade macOS security suite", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check if system is compromised
    Detect {
        /// Output format (json, text, report)
        #[arg(short, long, default_value = "text")]
        format: String,
    },
    /// Harden system security
    Harden {
        /// Dry run - show what would be changed
        #[arg(short, long)]
        dry_run: bool,
    },
    /// Monitor for threats in real-time
    Monitor {
        /// Run continuously
        #[arg(short, long)]
        continuous: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Serialize, Deserialize)]
struct SecurityAlert {
    severity: Severity,
    category: String,
    indicator: String,
    details: String,
    score: u32,
}

struct CompromiseDetector {
    alerts: Vec<SecurityAlert>,
    total_score: u32,
}

impl CompromiseDetector {
    fn new() -> Self {
        Self {
            alerts: Vec::new(),
            total_score: 0,
        }
    }

    fn add_alert(&mut self, alert: SecurityAlert) {
        self.total_score += alert.score;
        self.alerts.push(alert);
    }

    fn check_kernel_extensions(&mut self) -> Result<()> {
        let output = Command::new("kextstat")
            .output()
            .context("Failed to execute kextstat")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        
        for line in stdout.lines() {
            if !line.contains("com.apple") && line.len() > 10 {
                // Parse kext info
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 5 {
                    let kext_name = parts[5];
                    
                    self.add_alert(SecurityAlert {
                        severity: Severity::High,
                        category: "KERNEL".to_string(),
                        indicator: "Non-Apple Kernel Extension".to_string(),
                        details: format!("Found: {}", kext_name),
                        score: 7,
                    });
                }
            }
        }
        
        Ok(())
    }

    fn check_suspicious_processes(&mut self) -> Result<()> {
        let malware_patterns = vec![
            "MacKeeper", "MacDefender", "com.apple.updates",
            "kernel_service", "syslogd_helper"
        ];

        let output = Command::new("ps")
            .args(&["aux"])
            .output()
            .context("Failed to execute ps")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        
        for pattern in malware_patterns {
            if stdout.contains(pattern) {
                self.add_alert(SecurityAlert {
                    severity: Severity::Critical,
                    category: "MALWARE".to_string(),
                    indicator: "Known Malware Process".to_string(),
                    details: format!("Found process matching: {}", pattern),
                    score: 10,
                });
            }
        }
        
        Ok(())
    }

    fn check_network_backdoors(&mut self) -> Result<()> {
        let suspicious_ports = vec![1337, 31337, 4444, 5555, 6666];
        
        let output = Command::new("netstat")
            .args(&["-an"])
            .output()
            .context("Failed to execute netstat")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        
        for port in suspicious_ports {
            if stdout.contains(&format!(":{}", port)) {
                self.add_alert(SecurityAlert {
                    severity: Severity::Critical,
                    category: "NETWORK".to_string(),
                    indicator: "Backdoor Port".to_string(),
                    details: format!("Connection on known backdoor port: {}", port),
                    score: 10,
                });
            }
        }
        
        Ok(())
    }

    fn check_persistence_mechanisms(&mut self) -> Result<()> {
        let home_path = format!("{}/Library/LaunchAgents", std::env::var("HOME")?);
        let persistence_paths = vec![
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            home_path.as_str(),
        ];

        for path in persistence_paths {
            if Path::new(path).exists() {
                let entries = fs::read_dir(path)?;
                for entry in entries {
                    let entry = entry?;
                    let path = entry.path();
                    
                    if path.extension().and_then(|s| s.to_str()) == Some("plist") {
                        // Check if it's recently modified (within 30 days)
                        if let Ok(metadata) = entry.metadata() {
                            if let Ok(modified) = metadata.modified() {
                                let age = SystemTime::now().duration_since(modified)?;
                                if age.as_secs() < 30 * 24 * 60 * 60 {
                                    // Read the plist and check for suspicious content
                                    if let Ok(content) = fs::read_to_string(&path) {
                                        if content.contains("RunAtLoad") || content.contains("/tmp/") {
                                            self.add_alert(SecurityAlert {
                                                severity: Severity::High,
                                                category: "PERSISTENCE".to_string(),
                                                indicator: "Suspicious LaunchAgent".to_string(),
                                                details: format!("Recently added: {}", path.display()),
                                                score: 7,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Ok(())
    }

    fn check_system_integrity(&mut self) -> Result<()> {
        // Check SIP status
        let output = Command::new("csrutil")
            .arg("status")
            .output()
            .context("Failed to check SIP status")?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.contains("enabled") {
            self.add_alert(SecurityAlert {
                severity: Severity::High,
                category: "SYSTEM".to_string(),
                indicator: "SIP Disabled".to_string(),
                details: "System Integrity Protection is disabled".to_string(),
                score: 7,
            });
        }

        // Check Gatekeeper
        let output = Command::new("spctl")
            .arg("--status")
            .output()
            .context("Failed to check Gatekeeper")?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("disabled") {
            self.add_alert(SecurityAlert {
                severity: Severity::Medium,
                category: "SYSTEM".to_string(),
                indicator: "Gatekeeper Disabled".to_string(),
                details: "Gatekeeper protection is disabled".to_string(),
                score: 4,
            });
        }
        
        Ok(())
    }

    fn check_browser_extensions(&mut self) -> Result<()> {
        let home = std::env::var("HOME")?;
        let chrome_extensions = format!("{}/Library/Application Support/Google/Chrome/Default/Extensions", home);
        
        if Path::new(&chrome_extensions).exists() {
            let mut suspicious_count = 0;
            
            if let Ok(entries) = fs::read_dir(&chrome_extensions) {
                for entry in entries {
                    if let Ok(entry) = entry {
                        // Look for manifest.json files
                        let manifest_path = entry.path().join("*/manifest.json");
                        let pattern = manifest_path.to_string_lossy();
                        
                        // Use glob to find manifest files
                        if let Ok(paths) = glob::glob(&pattern) {
                            for path in paths.flatten() {
                                if let Ok(content) = fs::read_to_string(&path) {
                                    if content.contains("\"all_urls\"") || content.contains("http://*/*") {
                                        suspicious_count += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            if suspicious_count > 5 {
                self.add_alert(SecurityAlert {
                    severity: Severity::Medium,
                    category: "BROWSER".to_string(),
                    indicator: "Many Browser Extensions".to_string(),
                    details: format!("{} extensions with broad permissions", suspicious_count),
                    score: 4,
                });
            }
        }
        
        Ok(())
    }

    fn generate_report(&self) {
        println!("\n{}", "========== COMPROMISE DETECTION REPORT ==========".bold());
        println!("Hostname: {}", hostname::get().unwrap_or_default().to_string_lossy());
        println!("macOS Version: {}", get_macos_version());
        println!("Scan Date: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
        println!();
        println!("Total Score: {}", self.total_score.to_string().bold());
        println!("Alerts Found: {}\n", self.alerts.len());

        let assessment = match self.total_score {
            0 => "NO COMPROMISE DETECTED".green(),
            1..=10 => "LOW RISK".yellow(),
            11..=30 => "MEDIUM RISK".yellow().bold(),
            31..=50 => "HIGH RISK".red(),
            _ => "CRITICAL - SYSTEM COMPROMISED".red().bold(),
        };

        println!("Assessment: {}\n", assessment);

        // Group alerts by category
        let mut by_category: std::collections::HashMap<String, Vec<&SecurityAlert>> = std::collections::HashMap::new();
        for alert in &self.alerts {
            by_category.entry(alert.category.clone()).or_default().push(alert);
        }

        for (category, alerts) in by_category {
            println!("\n{}", format!("=== {} ===", category).cyan().bold());
            for alert in alerts {
                let severity_str = match alert.severity {
                    Severity::Critical => "CRITICAL".red().bold(),
                    Severity::High => "HIGH".red(),
                    Severity::Medium => "MEDIUM".yellow(),
                    Severity::Low => "LOW".blue(),
                    Severity::Info => "INFO".green(),
                };

                println!("[{}] {}: {}", severity_str, alert.indicator.bold(), alert.details);
            }
        }

        // Recommendations
        println!("\n{}", "=== RECOMMENDATIONS ===".blue().bold());
        match self.total_score {
            0 => println!("✓ Your system appears clean. Continue regular monitoring."),
            1..=10 => println!("• Review and investigate the findings\n• Update security software\n• Check for software updates"),
            11..=30 => println!("• Investigate all HIGH severity findings immediately\n• Run antivirus scan\n• Review installed applications\n• Change passwords from a clean system"),
            _ => println!("⚠️  IMMEDIATE ACTION REQUIRED:\n• Isolate system from network\n• Do not enter passwords\n• Contact security team\n• Consider full system reinstall"),
        }
    }
}

fn get_macos_version() -> String {
    if let Ok(output) = Command::new("sw_vers")
        .arg("-productVersion")
        .output()
    {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        "Unknown".to_string()
    }
}

fn detect_compromise() -> Result<()> {
    println!("{}", "macOS Compromise Detection Tool".blue().bold());
    println!("{}", "================================".blue());
    println!("Starting comprehensive security scan...\n");
    
    let mut detector = CompromiseDetector::new();
    
    // Run all checks
    let checks = vec![
        ("Checking kernel extensions", detector.check_kernel_extensions()),
        ("Checking for suspicious processes", detector.check_suspicious_processes()),
        ("Checking for network backdoors", detector.check_network_backdoors()),
        ("Checking persistence mechanisms", detector.check_persistence_mechanisms()),
        ("Checking system integrity", detector.check_system_integrity()),
        ("Checking browser extensions", detector.check_browser_extensions()),
    ];
    
    for (description, result) in checks {
        print!("{:<40}", format!("{}...", description));
        match result {
            Ok(_) => println!("{}", "✓".green()),
            Err(e) => {
                println!("{} ({})", "✗".red(), e);
                warn!("Check failed: {} - {}", description, e);
            }
        }
    }
    
    println!();
    
    // Generate report
    detector.generate_report();
    
    // Save report to file
    if let Ok(report_json) = serde_json::to_string_pretty(&detector.alerts) {
        let report_path = format!("/tmp/compromise-report-{}.json", 
            chrono::Local::now().format("%Y%m%d-%H%M%S"));
        if fs::write(&report_path, report_json).is_ok() {
            println!("\nDetailed report saved to: {}", report_path.green());
        }
    }
    
    Ok(())
}

fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    let cli = Cli::parse();

    match cli.command {
        Commands::Detect { format: _ } => {
            detect_compromise()?;
        }
        Commands::Harden { dry_run: _ } => {
            println!("{}", "System hardening not yet implemented in Rust version".yellow());
            println!("Use the bash script: ./macos-security-hardening.sh");
        }
        Commands::Monitor { continuous: _ } => {
            println!("{}", "Real-time monitoring not yet implemented in Rust version".yellow());
            println!("Use the bash script: ./macos-threat-monitor.sh");
        }
    }

    Ok(())
} 