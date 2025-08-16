use anyhow::Result;
use rustmapv3::cli::{Cli, OutputFormat};
use rustmapv3::nmap::{NmapConfig, NmapOrchestrator};
use rustmapv3::rustscan::FallbackScanner;
use rustmapv3::scanner::ScanConfig;
use rustmapv3::{ports, targets};
use std::time::Duration;
use tracing::{error, info, warn};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse_args();

    // Initialize logging
    let log_level = if cli.quiet {
        tracing::Level::WARN
    } else if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    // Validate CLI arguments
    if let Err(e) = cli.validate() {
        error!("Invalid arguments: {}", e);
        std::process::exit(1);
    }

    // Display banner
    if !cli.quiet {
        display_banner();
    }

    // Parse targets
    info!("Parsing targets: {}", cli.targets);
    let targets = match targets::parse_targets(&cli.targets).await {
        Ok(targets) => targets,
        Err(e) => {
            error!("Failed to parse targets: {}", e);
            std::process::exit(1);
        }
    };

    info!("Found {} valid targets", targets.len());

    // Parse ports
    let ports = if let Some(top_count) = cli.top_ports {
        info!("Using top {} common ports", top_count);
        ports::get_top_ports(top_count)
    } else {
        info!("Parsing port specification: {}", cli.ports);
        match ports::parse_ports(&cli.ports) {
            Ok(ports) => ports,
            Err(e) => {
                error!("Failed to parse ports: {}", e);
                std::process::exit(1);
            }
        }
    };

    info!("Scanning {} ports: {}", ports.len(), ports::format_ports_summary(&ports));

    // Create scan configuration
    let scan_config = ScanConfig {
        concurrency: cli.concurrency,
        timeout: Duration::from_millis(cli.timeout),
        rate_limit: cli.rate_limit,
        batch_size: cli.batch_size,
    };

    // Perform port scanning
    let scan_results = if cli.use_rustscan {
        info!("Using RustScan integration with fallback to internal scanner");
        let fallback_scanner = FallbackScanner::new(cli.rustscan_args.clone(), scan_config);
        fallback_scanner.scan_targets(&targets, &ports).await
    } else {
        info!("Using internal high-performance scanner");
        let scanner = rustmapv3::scanner::Scanner::new(scan_config);
        scanner.scan_targets(&targets, &ports).await
    };

    let scan_results = match scan_results {
        Ok(results) => results,
        Err(e) => {
            error!("Port scanning failed: {}", e);
            std::process::exit(1);
        }
    };

    // Display scan results
    display_scan_results(&scan_results, &cli.output_format);

    // Run Nmap deep scanning if enabled
    if !cli.no_nmap {
        info!("Starting Nmap deep scanning phase");
        
        let nmap_config = NmapConfig {
            nmap_args: cli.nmap_args.clone(),
            nse_scripts: cli.nse_scripts.clone(),
            output_dir: cli.output_dir.clone(),
        };

        let nmap_orchestrator = NmapOrchestrator::new(nmap_config);
        
        match nmap_orchestrator.deep_scan(&scan_results).await {
            Ok(nmap_results) => {
                info!("Nmap deep scanning completed successfully");
                display_nmap_results(&nmap_results, &cli.output_format);
            }
            Err(e) => {
                error!("Nmap deep scanning failed: {}", e);
                // Don't exit here, port scanning was successful
            }
        }
    } else {
        info!("Nmap deep scanning disabled by --no-nmap flag");
    }

    info!("RustMapV3 scan completed successfully");
    Ok(())
}

/// Display the application banner
fn display_banner() {
    println!(r#"
    ____            __  __            __   _____
   / __ \__  ______/ /_/ /_   ____  / /  / ___/
  / /_/ / / / / ___/ __/ __ \ / __ \/ /   \__ \ 
 / _, _/ /_/ (__  ) /_/ / / // /_/ / /   ___/ / 
/_/ |_|\__,_/____/\__/_/ /_(_)____/_/   /____/  
                                      
Ultra-fast TCP port discovery engine with Nmap orchestration
Version 0.1.0 | https://github.com/Wael-Rd/RustMapV3
"#);
}

/// Display scan results
fn display_scan_results(results: &[rustmapv3::scanner::ScanResults], format: &OutputFormat) {
    match format {
        OutputFormat::Table => display_scan_results_table(results),
        OutputFormat::Json => display_scan_results_json(results),
        OutputFormat::Yaml => display_scan_results_yaml(results),
    }
}

/// Display scan results in table format
fn display_scan_results_table(results: &[rustmapv3::scanner::ScanResults]) {
    println!("\n📊 Port Scan Results");
    println!("═══════════════════════════════════════════════════════════════");
    
    let mut total_open_ports = 0;
    let mut targets_with_open_ports = 0;

    for result in results {
        println!("\n🎯 Target: {}", result.target.display_name());
        println!("   Scan Duration: {:.2}s", result.scan_duration.as_secs_f64());
        println!("   Ports Scanned: {}", result.total_ports_scanned);
        
        if result.has_open_ports() {
            targets_with_open_ports += 1;
            total_open_ports += result.open_port_count();
            
            println!("   Open Ports: {}", ports::format_ports_summary(&result.open_ports));
            println!("   🟢 {} open ports found", result.open_port_count());
        } else {
            println!("   🔴 No open ports found");
        }
    }

    println!("\n📈 Summary");
    println!("   Targets Scanned: {}", results.len());
    println!("   Targets with Open Ports: {}", targets_with_open_ports);
    println!("   Total Open Ports: {}", total_open_ports);
}

/// Display scan results in JSON format
fn display_scan_results_json(results: &[rustmapv3::scanner::ScanResults]) {
    let json_results: Vec<serde_json::Value> = results
        .iter()
        .map(|result| {
            serde_json::json!({
                "target": {
                    "ip": result.target.ip.to_string(),
                    "hostname": result.target.hostname,
                    "display_name": result.target.display_name()
                },
                "scan_duration_seconds": result.scan_duration.as_secs_f64(),
                "total_ports_scanned": result.total_ports_scanned,
                "open_ports": result.open_ports,
                "open_port_count": result.open_port_count(),
                "has_open_ports": result.has_open_ports()
            })
        })
        .collect();

    let output = serde_json::json!({
        "scan_results": json_results,
        "summary": {
            "targets_scanned": results.len(),
            "targets_with_open_ports": results.iter().filter(|r| r.has_open_ports()).count(),
            "total_open_ports": results.iter().map(|r| r.open_port_count()).sum::<usize>()
        }
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

/// Display scan results in YAML format (simplified version)
fn display_scan_results_yaml(results: &[rustmapv3::scanner::ScanResults]) {
    // For now, convert to JSON and display as YAML-like format
    // In a full implementation, we'd use a proper YAML library
    display_scan_results_json(results);
    warn!("YAML output format not fully implemented, showing JSON instead");
}

/// Display Nmap results
fn display_nmap_results(results: &[rustmapv3::nmap::NmapResult], format: &OutputFormat) {
    println!("\n🔬 Nmap Deep Scan Results");
    println!("═══════════════════════════════════════════════════════════════");

    for result in results {
        println!("\n🎯 Target: {}", result.target.display_name());
        println!("   Scan Duration: {:.2}s", result.scan_duration.as_secs_f64());
        println!("   Ports Scanned: {}", result.scanned_ports.len());
        
        println!("   📁 Output Files:");
        for file in result.output_files.existing_files() {
            println!("     - {}", file.display());
        }

        if matches!(format, OutputFormat::Table) && !result.stdout.is_empty() {
            println!("   📋 Nmap Output Preview:");
            // Show first few lines of output
            for (i, line) in result.stdout.lines().take(10).enumerate() {
                if i == 0 || line.trim().starts_with("PORT") || line.contains("open") {
                    println!("     {}", line);
                }
            }
            if result.stdout.lines().count() > 10 {
                println!("     ... (see output files for complete results)");
            }
        }
    }

    println!("\n📈 Nmap Summary");
    println!("   Targets Scanned: {}", results.len());
    println!("   Output Directory: {}", 
             results.first()
                 .map(|r| r.output_files.normal_output.parent().unwrap().display().to_string())
                 .unwrap_or_else(|| "scans/".to_string()));
}

/// Legal and ethics disclaimer
#[allow(dead_code)]
fn display_disclaimer() {
    println!(r#"
⚠️  LEGAL AND ETHICAL DISCLAIMER ⚠️

RustMapV3 is a network security tool intended for legitimate security testing,
network administration, and educational purposes only.

IMPORTANT:
• Only scan networks and systems you own or have explicit permission to test
• Unauthorized scanning of networks may violate local, state, or federal laws
• The developers assume no liability for any misuse of this tool
• Users are solely responsible for compliance with all applicable laws and regulations

By using this tool, you acknowledge that you have read and understood this disclaimer
and agree to use RustMapV3 responsibly and legally.
"#);
}
