//! CLI argument parsing for RustMapV3

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "RustMapV3",
    version = "0.3.0",
    about = "Ultra-fast TCP port discovery with smart Nmap orchestration",
    long_about = "RustMapV3 discovers open TCP ports at high speed and orchestrates Nmap with targeted scripts for maximum signal per second."
)]
pub struct Cli {
    /// Target(s): IP (192.168.1.1), hostname (example.com), list (a,b), or CIDR (192.168.1.0/24)
    #[arg(value_name = "TARGETS")]
    pub targets: String,

    /// Profile for speed vs. stealth
    #[arg(long = "profile", value_enum, default_value = "balanced")]
    pub profile: Profile,

    /// Ports to scan ("top1000", "top100", or ranges like 1-65535)
    #[arg(short = 'p', long = "ports", default_value = "top1000")]
    pub ports: String,

    /// Skip Nmap deep scanning
    #[arg(long = "no-nmap")]
    pub no_nmap: bool,

    /// Output directory for Nmap results
    #[arg(short = 'o', long = "output", default_value = "scans")]
    pub output_dir: PathBuf,

    /// Output format: json, yaml, table
    #[arg(long = "format", value_enum, default_value = "table")]
    pub output_format: OutputFormat,

    /// Stream JSON event objects to stdout as the scan progresses
    #[arg(long = "stream-events")]
    pub stream_events: bool,

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
pub enum Profile { Fast, Balanced, Stealth }

pub struct Effective {
    pub ports: String,
    pub concurrency: usize,
    pub targets_concurrency: usize,
    pub timeout_ms: u64,
    pub rate_limit: Option<u64>,
    pub batch_size: usize,
    pub confirm_open: bool,
    pub enable_probes: bool,
    pub stream_events: bool,
}

impl Cli {
    pub fn parse_args() -> Self { Self::parse() }

    pub fn validate(&self) -> crate::Result<()> {
        if self.ports.trim().is_empty() {
            return Err(crate::Error::General("Port selection cannot be empty".into()));
        }
        Ok(())
    }

    pub fn effective(&self) -> Effective {
        let ports = self.ports.clone();

        let (concurrency, targets_concurrency, timeout_ms, rate, batch, confirm_open) = match self.profile {
            Profile::Fast => (12288, 64, 180, Some(25000), 2200, false),
            Profile::Balanced => (8192, 32, 250, Some(15000), 2000, true),
            Profile::Stealth => (512, 8, 1200, Some(400), 800, true),
        };

        Effective {
            ports,
            concurrency,
            targets_concurrency,
            timeout_ms,
            rate_limit: rate,
            batch_size: batch,
            confirm_open,
            enable_probes: true,
            stream_events: self.stream_events,
        }
    }
}