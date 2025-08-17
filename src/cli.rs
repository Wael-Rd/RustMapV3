//! CLI argument parsing for RustMapV3

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "RustMapV3",
    version = "0.2.0",
    about = "Ultra-fast TCP port discovery with smart Nmap orchestration",
    long_about = "RustMapV3 discovers open TCP ports at high speed and orchestrates Nmap with targeted scripts for maximum signal per second."
)]
pub struct Cli {
    /// Target(s): IP (192.168.1.1), hostname (example.com), list (a,b), or CIDR (192.168.1.0/24)
    #[arg(value_name = "TARGETS")]
    pub targets: String,

    /// Preset for speed vs. depth. Overrides individual flags unless explicitly set.
    #[arg(long = "preset", value_enum, default_value = "full")]
    pub preset: Preset,

    /// Ports to scan [default: 1-65535]
    #[arg(short = 'p', long = "ports", default_value = "1-65535")]
    pub ports: String,

    /// Scan top N common ports (overrides --ports)
    #[arg(short = 't', long = "top", value_name = "N", conflicts_with = "ports")]
    pub top_ports: Option<usize>,

    /// Per-target concurrency (connections in flight per host)
    #[arg(long = "concurrency", value_name = "N")]
    pub concurrency: Option<usize>,

    /// Concurrent targets scanned in parallel
    #[arg(long = "targets-concurrency", value_name = "N")]
    pub targets_concurrency: Option<usize>,

    /// Timeout in milliseconds per connection attempt
    #[arg(long = "timeout", value_name = "MS")]
    pub timeout: Option<u64>,

    /// Global connection attempts per second
    #[arg(short = 'r', long = "rate", value_name = "N")]
    pub rate_limit: Option<u64>,

    /// Internal batch size (ports per chunk)
    #[arg(long = "batch-size", value_name = "N")]
    pub batch_size: Option<usize>,

    /// Confirm open ports with a quick second pass (reduces false positives)
    #[arg(long = "confirm-open")]
    pub confirm_open: bool,

    /// Use RustScan for discovery (fallback to internal scanner)
    #[arg(long = "use-rustscan")]
    pub use_rustscan: bool,

    /// Additional arguments for RustScan
    #[arg(long = "rustscan-args", requires = "use_rustscan")]
    pub rustscan_args: Option<String>,

    /// Additional arguments for Nmap (shorthand normalized, e.g., sCV -> -sC -sV)
    #[arg(long = "nmap-args")]
    pub nmap_args: Option<String>,

    /// NSE scripts: default,vuln,auth or specific scripts
    #[arg(long = "nse")]
    pub nse_scripts: Option<String>,

    /// Nmap mode: smart targets scripts for discovered ports vs plain default scripts
    #[arg(long = "nmap-mode", value_enum, default_value = "smart")]
    pub nmap_mode: NmapMode,

    /// Output directory for Nmap results
    #[arg(short = 'o', long = "output", default_value = "scans")]
    pub output_dir: PathBuf,

    /// Skip Nmap deep scanning
    #[arg(long = "no-nmap")]
    pub no_nmap: bool,

    /// Output format: json, yaml, table
    #[arg(long = "format", value_enum, default_value = "table")]
    pub output_format: OutputFormat,

    /// Verbose output
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Quiet mode
    #[arg(short = 'q', long = "quiet", conflicts_with = "verbose")]
    pub quiet: bool,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum OutputFormat { Json, Yaml, Table }

#[derive(Clone, Debug, ValueEnum)]
pub enum Preset { Fast, Full, Thorough }

#[derive(Clone, Debug, ValueEnum)]
pub enum NmapMode { Smart, Plain }

pub struct Effective {
    pub ports: String,
    pub concurrency: usize,
    pub targets_concurrency: usize,
    pub timeout_ms: u64,
    pub rate_limit: Option<u64>,
    pub batch_size: usize,
    pub confirm_open: bool,
}

impl Cli {
    pub fn parse_args() -> Self { Self::parse() }

    pub fn validate(&self) -> crate::Result<()> {
        if let Some(top) = self.top_ports {
            if top == 0 || top > 65535 {
                return Err(crate::Error::General("Top ports must be between 1 and 65535".into()));
            }
        }
        Ok(())
    }

    pub fn effective(&self) -> Effective {
        let (mut ports, mut concurrency, mut targets_concurrency, mut timeout_ms, mut rate, mut batch, confirm) = match self.preset {
            Preset::Fast => (
                self.top_ports.map(|n| n.to_string()).unwrap_or_else(|| "top1000".to_string()),
                8192, 32, 200, Some(20000), 1500, self.confirm_open,
            ),
            Preset::Full => (
                "1-65535".to_string(),
                8192, 32, 250, Some(15000), 2000, self.confirm_open,
            ),
            Preset::Thorough => (
                "1-65535".to_string(),
                4096, 16, 600, Some(6000), 1500, true,
            ),
        };

        if let Some(user_ports) = self.top_ports.map(|n| format!("top{}", n)).or_else(|| if !self.ports.trim().is_empty() { Some(self.ports.clone()) } else { None }) {
            ports = user_ports;
        }
        if let Some(c) = self.concurrency { concurrency = c; }
        if let Some(tc) = self.targets_concurrency { targets_concurrency = tc; }
        if let Some(t) = self.timeout { timeout_ms = t; }
        if let Some(r) = self.rate_limit { rate = Some(r); }
        if let Some(b) = self.batch_size { batch = b; }

        Effective { ports, concurrency, targets_concurrency, timeout_ms, rate_limit: rate, batch_size: batch, confirm_open: confirm }
    }
}