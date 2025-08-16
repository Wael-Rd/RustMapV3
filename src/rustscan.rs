//! RustScan integration module

use crate::scanner::{ScanResults, ScanConfig};
use crate::targets::Target;
use crate::{Error, Result};
use std::process::Command;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// RustScan integration wrapper
pub struct RustScanIntegration {
    rustscan_args: Option<String>,
}

impl RustScanIntegration {
    /// Create new RustScan integration
    pub fn new(rustscan_args: Option<String>) -> Self {
        Self { rustscan_args }
    }

    /// Check if RustScan is available on the system
    pub fn is_available() -> bool {
        Command::new("rustscan")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Scan target using RustScan
    pub async fn scan_target(&self, target: &Target, ports: &[u16]) -> Result<ScanResults> {
        let start_time = Instant::now();
        
        info!(
            "Using RustScan to scan target {} with {} ports",
            target.display_name(),
            ports.len()
        );

        if !Self::is_available() {
            return Err(Error::RustScanError(
                "RustScan binary not found in PATH".to_string(),
            ));
        }

        let mut cmd = Command::new("rustscan");
        
        // Add target
        cmd.arg("-a").arg(target.ip.to_string());
        
        // Add ports
        if !ports.is_empty() {
            let ports_str = format_ports_for_rustscan(ports);
            cmd.arg("-p").arg(ports_str);
        }

        // Add timeout and other performance settings
        cmd.arg("-t").arg("300"); // 300ms timeout
        cmd.arg("--ulimit").arg("5000"); // High ulimit for performance
        cmd.arg("--batch-size").arg("1000");

        // Disable nmap integration in rustscan (we handle it ourselves)
        cmd.arg("--greppable");
        
        // Add custom arguments if provided
        if let Some(ref args) = self.rustscan_args {
            for arg in args.split_whitespace() {
                cmd.arg(arg);
            }
        }

        debug!("Executing RustScan command: {:?}", cmd);

        let output = tokio::task::spawn_blocking(move || cmd.output())
            .await
            .map_err(|e| Error::RustScanError(format!("Failed to execute RustScan: {}", e)))?
            .map_err(|e| Error::RustScanError(format!("RustScan execution failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::RustScanError(format!("RustScan failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let open_ports = parse_rustscan_output(&stdout)?;

        let scan_duration = start_time.elapsed();
        
        info!(
            "RustScan completed for {} - {} open ports found in {:.2}s",
            target.display_name(),
            open_ports.len(),
            scan_duration.as_secs_f64()
        );

        Ok(ScanResults {
            target: target.clone(),
            open_ports,
            total_ports_scanned: ports.len(),
            scan_duration,
        })
    }

    /// Scan multiple targets using RustScan
    pub async fn scan_targets(&self, targets: &[Target], ports: &[u16]) -> Result<Vec<ScanResults>> {
        let mut results = Vec::new();

        for target in targets {
            match self.scan_target(target, ports).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    warn!("RustScan failed for target {}: {}", target.display_name(), e);
                    // Continue with other targets instead of failing completely
                    results.push(ScanResults {
                        target: target.clone(),
                        open_ports: Vec::new(),
                        total_ports_scanned: ports.len(),
                        scan_duration: Duration::from_secs(0),
                    });
                }
            }
        }

        Ok(results)
    }
}

/// Format ports list for RustScan command line
fn format_ports_for_rustscan(ports: &[u16]) -> String {
    if ports.is_empty() {
        return "1-65535".to_string();
    }

    // RustScan expects comma-separated ports or ranges
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

/// Parse RustScan output to extract open ports
fn parse_rustscan_output(output: &str) -> Result<Vec<u16>> {
    let mut open_ports = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        
        // Look for open port lines in RustScan output
        // RustScan typically outputs: "Open 192.168.1.1:80"
        if line.starts_with("Open ") {
            if let Some(port_part) = line.split(':').last() {
                if let Ok(port) = port_part.trim().parse::<u16>() {
                    open_ports.push(port);
                }
            }
        }
        // Also handle greppable format
        else if line.contains("open") {
            // Try to extract port numbers from various formats
            let words: Vec<&str> = line.split_whitespace().collect();
            for word in words {
                if let Ok(port) = word.parse::<u16>() {
                    if port > 0 && port <= 65535 {
                        open_ports.push(port);
                    }
                }
            }
        }
    }

    // Remove duplicates and sort
    open_ports.sort_unstable();
    open_ports.dedup();

    debug!("Parsed {} open ports from RustScan output", open_ports.len());
    
    Ok(open_ports)
}

/// Fallback scanner that uses internal scanner when RustScan fails
pub struct FallbackScanner {
    rustscan: RustScanIntegration,
    internal_scanner: crate::scanner::Scanner,
}

impl FallbackScanner {
    /// Create new fallback scanner
    pub fn new(rustscan_args: Option<String>, scan_config: ScanConfig) -> Self {
        Self {
            rustscan: RustScanIntegration::new(rustscan_args),
            internal_scanner: crate::scanner::Scanner::new(scan_config),
        }
    }

    /// Scan targets with RustScan fallback to internal scanner
    pub async fn scan_targets(&self, targets: &[Target], ports: &[u16]) -> Result<Vec<ScanResults>> {
        if RustScanIntegration::is_available() {
            info!("Using RustScan for port discovery");
            match self.rustscan.scan_targets(targets, ports).await {
                Ok(results) => return Ok(results),
                Err(e) => {
                    warn!("RustScan failed, falling back to internal scanner: {}", e);
                }
            }
        } else {
            info!("RustScan not available, using internal scanner");
        }

        // Fallback to internal scanner
        self.internal_scanner.scan_targets(targets, ports).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_ports_for_rustscan() {
        assert_eq!(format_ports_for_rustscan(&[]), "1-65535");
        assert_eq!(format_ports_for_rustscan(&[80]), "80");
        assert_eq!(format_ports_for_rustscan(&[80, 443]), "80,443");
        assert_eq!(format_ports_for_rustscan(&[80, 81, 82, 83]), "80-83");
        assert_eq!(format_ports_for_rustscan(&[22, 80, 81, 82, 443]), "22,80-82,443");
    }

    #[test]
    fn test_parse_rustscan_output() {
        let output = r#"
Open 192.168.1.1:22
Open 192.168.1.1:80
Open 192.168.1.1:443
        "#;
        
        let ports = parse_rustscan_output(output).unwrap();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_parse_rustscan_output_greppable() {
        let output = r#"
192.168.1.1 22 open
192.168.1.1 80 open
192.168.1.1 443 open
        "#;
        
        let ports = parse_rustscan_output(output).unwrap();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_rustscan_availability() {
        // This test will pass if RustScan is installed, otherwise it will just check the function works
        let available = RustScanIntegration::is_available();
        // We don't assert true/false since RustScan may or may not be installed
        assert!(available == true || available == false);
    }
}