//! CLI argument parsing for RustMapV3

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "rustmapv3",
    version = "0.1.0",
    about = "Ultra-fast TCP port discovery engine with Nmap orchestration",
    long_about = "RustMapV3 combines a lightning-fast Rust-based port scanner with Nmap's \
                  comprehensive feature set. It quickly discovers open TCP ports and then \
                  orchestrates Nmap for detailed service detection and vulnerability scanning."
)]
pub struct Cli {
    /// Target(s) to scan: IP, hostname, comma-separated list, or CIDR notation
    #[arg(
        value_name = "TARGETS",
        help = "Target(s): IP (192.168.1.1), hostname (example.com), list (192.168.1.1,example.com), or CIDR (192.168.1.0/24)"
    )]
    pub targets: String,

    /// Port specification: ranges and lists (e.g., "1-1024,3306,8080-8090")
    #[arg(
        short = 'p',
        long = "ports",
        value_name = "PORTS",
        help = "Port ranges/lists: 1-1024,3306,8080-8090",
        default_value = "1-65535"
    )]
    pub ports: String,

    /// Scan top N common ports (overrides --ports)
    #[arg(
        short = 't',
        long = "top",
        value_name = "N",
        help = "Scan top N common ports (100, 1000, 5000)",
        conflicts_with = "ports"
    )]
    pub top_ports: Option<usize>,

    /// Number of concurrent connections
    #[arg(
        short = 'c',
        long = "concurrency",
        value_name = "N",
        help = "Concurrent connection limit",
        default_value = "4096"
    )]
    pub concurrency: usize,

    /// Per-connection timeout in milliseconds
    #[arg(
        long = "timeout",
        value_name = "MS",
        help = "Connection timeout in milliseconds",
        default_value = "300"
    )]
    pub timeout: u64,

    /// Maximum connection attempts per second
    #[arg(
        short = 'r',
        long = "rate",
        value_name = "N",
        help = "Max connection attempts per second"
    )]
    pub rate_limit: Option<u64>,

    /// Internal batching size for reduced overhead
    #[arg(
        long = "batch-size",
        value_name = "N",
        help = "Internal batch size for processing",
        default_value = "1024"
    )]
    pub batch_size: usize,

    /// Use RustScan for port discovery (if available)
    #[arg(
        long = "use-rustscan",
        help = "Use RustScan binary for port discovery (fallback to internal scanner)"
    )]
    pub use_rustscan: bool,

    /// Additional arguments to pass to RustScan
    #[arg(
        long = "rustscan-args",
        value_name = "ARGS",
        help = "Additional arguments for RustScan",
        requires = "use_rustscan"
    )]
    pub rustscan_args: Option<String>,

    /// Additional arguments to pass to Nmap
    #[arg(
        long = "nmap-args",
        value_name = "ARGS",
        help = "Additional arguments for Nmap (default: -Pn -sV -sC)"
    )]
    pub nmap_args: Option<String>,

    /// NSE script categories or specific scripts
    #[arg(
        long = "nse",
        value_name = "SCRIPTS",
        help = "NSE scripts: default,vuln,auth or specific script names"
    )]
    pub nse_scripts: Option<String>,

    /// Output directory for scan results
    #[arg(
        short = 'o',
        long = "output",
        value_name = "DIR",
        help = "Output directory for scan results",
        default_value = "scans"
    )]
    pub output_dir: PathBuf,

    /// Disable Nmap deep scanning (port discovery only)
    #[arg(
        long = "no-nmap",
        help = "Skip Nmap deep scanning, only perform port discovery"
    )]
    pub no_nmap: bool,

    /// Verbose output
    #[arg(short = 'v', long = "verbose", help = "Enable verbose output")]
    pub verbose: bool,

    /// Quiet mode (minimal output)
    #[arg(short = 'q', long = "quiet", help = "Quiet mode", conflicts_with = "verbose")]
    pub quiet: bool,

    /// Output format for results
    #[arg(
        long = "format",
        value_name = "FORMAT",
        help = "Output format: json, yaml, table",
        default_value = "table"
    )]
    pub output_format: OutputFormat,
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum OutputFormat {
    Json,
    Yaml,
    Table,
}

impl Cli {
    /// Parse command line arguments
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Get the effective Nmap arguments
    pub fn get_nmap_args(&self) -> String {
        let mut args = vec!["-Pn".to_string(), "-sV".to_string(), "-sC".to_string()];
        
        if let Some(ref nse) = self.nse_scripts {
            args.push(format!("--script={}", nse));
        }
        
        if let Some(ref extra_args) = self.nmap_args {
            args.extend(extra_args.split_whitespace().map(String::from));
        }
        
        args.join(" ")
    }

    /// Validate CLI arguments
    pub fn validate(&self) -> crate::Result<()> {
        // Validate concurrency
        if self.concurrency == 0 {
            return Err(crate::Error::General("Concurrency must be greater than 0".to_string()));
        }

        // Validate timeout
        if self.timeout == 0 {
            return Err(crate::Error::General("Timeout must be greater than 0".to_string()));
        }

        // Validate batch size
        if self.batch_size == 0 {
            return Err(crate::Error::General("Batch size must be greater than 0".to_string()));
        }

        // Validate rate limit
        if let Some(rate) = self.rate_limit {
            if rate == 0 {
                return Err(crate::Error::General("Rate limit must be greater than 0".to_string()));
            }
        }

        // Validate top ports
        if let Some(top) = self.top_ports {
            if top == 0 || top > 65535 {
                return Err(crate::Error::General("Top ports must be between 1 and 65535".to_string()));
            }
        }

        Ok(())
    }
}