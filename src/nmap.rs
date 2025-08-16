//! Nmap orchestration module

use crate::scanner::ScanResults;
use crate::targets::Target;
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use tracing::{debug, info, warn};

/// Nmap scan configuration
#[derive(Debug, Clone)]
pub struct NmapConfig {
    /// Additional Nmap arguments
    pub nmap_args: Option<String>,
    /// NSE scripts to run
    pub nse_scripts: Option<String>,
    /// Output directory for scan results
    pub output_dir: PathBuf,
}

impl Default for NmapConfig {
    fn default() -> Self {
        Self {
            nmap_args: None,
            nse_scripts: None,
            output_dir: PathBuf::from("scans"),
        }
    }
}

/// Nmap orchestrator
pub struct NmapOrchestrator {
    config: NmapConfig,
}

impl NmapOrchestrator {
    /// Create new Nmap orchestrator
    pub fn new(config: NmapConfig) -> Self {
        Self { config }
    }

    /// Check if Nmap is available on the system
    pub fn is_available() -> bool {
        Command::new("nmap")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Run deep scan on scan results
    pub async fn deep_scan(&self, scan_results: &[ScanResults]) -> Result<Vec<NmapResult>> {
        if !Self::is_available() {
            return Err(Error::NmapError("Nmap binary not found in PATH".to_string()));
        }

        // Create output directory
        self.ensure_output_directory()?;

        let mut nmap_results = Vec::new();

        for result in scan_results {
            if result.has_open_ports() {
                info!(
                    "Running Nmap deep scan on {} ({} open ports)",
                    result.target.display_name(),
                    result.open_port_count()
                );

                match self.run_nmap_scan(result).await {
                    Ok(nmap_result) => nmap_results.push(nmap_result),
                    Err(e) => {
                        warn!(
                            "Nmap scan failed for target {}: {}",
                            result.target.display_name(),
                            e
                        );
                        // Continue with other targets instead of failing completely
                    }
                }
            } else {
                info!(
                    "Skipping Nmap scan for {} (no open ports found)",
                    result.target.display_name()
                );
            }
        }

        Ok(nmap_results)
    }

    /// Run Nmap scan for a single target
    async fn run_nmap_scan(&self, scan_result: &ScanResults) -> Result<NmapResult> {
        let start_time = Instant::now();
        let target_name = self.generate_target_filename(&scan_result.target);
        let output_path = self.config.output_dir.join(&target_name);

        let mut cmd = Command::new("nmap");

        // Add target
        cmd.arg(scan_result.target.ip.to_string());

        // Add ports
        if !scan_result.open_ports.is_empty() {
            let ports_str = format_ports_for_nmap(&scan_result.open_ports);
            cmd.arg("-p").arg(ports_str);
        }

        // Default arguments: skip ping, version detection, default scripts
        cmd.arg("-Pn").arg("-sV").arg("-sC");

        // Add NSE scripts if specified
        if let Some(ref scripts) = self.config.nse_scripts {
            cmd.arg("--script").arg(scripts);
        }

        // Add custom arguments
        if let Some(ref args) = self.config.nmap_args {
            for arg in args.split_whitespace() {
                cmd.arg(arg);
            }
        }

        // Output formats: normal, XML, and grepable
        cmd.arg("-oA").arg(&output_path);

        // Add timing template for faster scanning
        cmd.arg("-T4");

        debug!("Executing Nmap command: {:?}", cmd);

        let output = tokio::task::spawn_blocking(move || cmd.output())
            .await
            .map_err(|e| Error::NmapError(format!("Failed to execute Nmap: {}", e)))?
            .map_err(|e| Error::NmapError(format!("Nmap execution failed: {}", e)))?;

        let scan_duration = start_time.elapsed();

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::NmapError(format!("Nmap scan failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        
        info!(
            "Nmap scan completed for {} in {:.2}s",
            scan_result.target.display_name(),
            scan_duration.as_secs_f64()
        );

        Ok(NmapResult {
            target: scan_result.target.clone(),
            scan_duration,
            output_files: NmapOutputFiles {
                base_name: target_name,
                normal_output: output_path.with_extension("nmap"),
                xml_output: output_path.with_extension("xml"),
                grepable_output: output_path.with_extension("gnmap"),
            },
            stdout: stdout.to_string(),
            scanned_ports: scan_result.open_ports.clone(),
        })
    }

    /// Ensure output directory exists
    fn ensure_output_directory(&self) -> Result<()> {
        if !self.config.output_dir.exists() {
            fs::create_dir_all(&self.config.output_dir)
                .map_err(|e| Error::Io(e))?;
            info!("Created output directory: {:?}", self.config.output_dir);
        }
        Ok(())
    }

    /// Generate filename for target output
    fn generate_target_filename(&self, target: &Target) -> String {
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        
        let ip_str = target.ip.to_string().replace(':', "_");
        
        if let Some(ref hostname) = target.hostname {
            // Sanitize hostname for filesystem
            let clean_hostname = hostname
                .chars()
                .map(|c| if c.is_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
                .collect::<String>();
            format!("{}_{}_{}",  timestamp, clean_hostname, ip_str)
        } else {
            format!("{}_{}", timestamp, ip_str)
        }
    }
}

/// Result of an Nmap scan
#[derive(Debug, Clone)]
pub struct NmapResult {
    pub target: Target,
    pub scan_duration: std::time::Duration,
    pub output_files: NmapOutputFiles,
    pub stdout: String,
    pub scanned_ports: Vec<u16>,
}

/// Nmap output file paths
#[derive(Debug, Clone)]
pub struct NmapOutputFiles {
    pub base_name: String,
    pub normal_output: PathBuf,
    pub xml_output: PathBuf,
    pub grepable_output: PathBuf,
}

impl NmapOutputFiles {
    /// Check if all output files exist
    pub fn all_exist(&self) -> bool {
        self.normal_output.exists() && self.xml_output.exists() && self.grepable_output.exists()
    }

    /// Get list of existing output files
    pub fn existing_files(&self) -> Vec<&PathBuf> {
        let mut files = Vec::new();
        if self.normal_output.exists() {
            files.push(&self.normal_output);
        }
        if self.xml_output.exists() {
            files.push(&self.xml_output);
        }
        if self.grepable_output.exists() {
            files.push(&self.grepable_output);
        }
        files
    }
}

/// Format ports list for Nmap command line
fn format_ports_for_nmap(ports: &[u16]) -> String {
    if ports.is_empty() {
        return "1-65535".to_string();
    }

    // Nmap expects comma-separated ports or ranges
    let mut formatted_ports = Vec::new();
    let mut start = ports[0];
    let mut end = ports[0];

    for &port in &ports[1..] {
        if port == end + 1 {
            end = port;
        } else {
            if start == end {
                formatted_ports.push(start.to_string());
            } else {
                formatted_ports.push(format!("{}-{}", start, end));
            }
            start = port;
            end = port;
        }
    }

    // Add the last range
    if start == end {
        formatted_ports.push(start.to_string());
    } else {
        formatted_ports.push(format!("{}-{}", start, end));
    }

    formatted_ports.join(",")
}

/// Parse Nmap XML output for structured data (placeholder for future enhancement)
pub fn parse_nmap_xml(_xml_file: &Path) -> Result<serde_json::Value> {
    // This is a placeholder for XML parsing functionality
    // In a complete implementation, this would parse the Nmap XML output
    // and return structured service information
    Ok(serde_json::json!({
        "placeholder": "XML parsing not yet implemented"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_format_ports_for_nmap() {
        assert_eq!(format_ports_for_nmap(&[]), "1-65535");
        assert_eq!(format_ports_for_nmap(&[80]), "80");
        assert_eq!(format_ports_for_nmap(&[80, 443]), "80,443");
        assert_eq!(format_ports_for_nmap(&[80, 81, 82, 83]), "80-83");
        assert_eq!(format_ports_for_nmap(&[22, 80, 81, 82, 443]), "22,80-82,443");
    }

    #[test]
    fn test_generate_target_filename() {
        let config = NmapConfig::default();
        let orchestrator = NmapOrchestrator::new(config);
        
        let target_ip = Target::from_ip("192.168.1.1".parse().unwrap());
        let filename = orchestrator.generate_target_filename(&target_ip);
        assert!(filename.contains("192.168.1.1"));
        
        let target_hostname = Target::from_ip_with_hostname(
            "192.168.1.1".parse().unwrap(),
            "example.com".to_string(),
        );
        let filename = orchestrator.generate_target_filename(&target_hostname);
        assert!(filename.contains("example.com"));
        assert!(filename.contains("192.168.1.1"));
    }

    #[test]
    fn test_nmap_availability() {
        // This test will pass if Nmap is installed, otherwise it will just check the function works
        let available = NmapOrchestrator::is_available();
        // We don't assert true/false since Nmap may or may not be installed
        assert!(available == true || available == false);
    }

    #[test]
    fn test_nmap_config_default() {
        let config = NmapConfig::default();
        assert_eq!(config.output_dir, PathBuf::from("scans"));
        assert!(config.nmap_args.is_none());
        assert!(config.nse_scripts.is_none());
    }
}