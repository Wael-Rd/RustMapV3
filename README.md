  # RustMapV3
![011001010101010](https://raw.githubusercontent.com/Wael-Rd/RustMapV3/main/011001010101010.png)

**Ultra-fast TCP port discovery engine with Nmap orchestration**

RustMapV3 combines the lightning-fast performance of Rust-based port scanning with the comprehensive feature set of Nmap. It quickly discovers open TCP ports and then orchestrates Nmap for detailed service detection, vulnerability scanning, and deep network analysis.

## 🚀 Features

### High-Performance Port Discovery
- **Blazing Fast**: Rust-powered TCP port scanner with configurable concurrency (up to 4096+ concurrent connections)
- **Smart Rate Limiting**: Optional connection rate limiting with token bucket algorithm
- **Efficient Memory Usage**: Batch processing to handle large port ranges and target lists
- **Timeout Control**: Configurable per-connection timeouts (default: 300ms)

### Flexible Target Specification
- **Multiple Formats**: Single IPs, hostnames, CIDR notation, comma-separated lists
- **IPv4 & IPv6**: Full support for both IP versions
- **DNS Resolution**: Automatic hostname resolution with caching
- **CIDR Expansion**: Intelligent expansion of network ranges (with safety limits)

### Port Selection Options
- **Custom Ranges**: Flexible port specification (e.g., `1-1024,3306,8080-8090`)
- **Top Ports**: Predefined lists of most common ports (top 100, 1000, 5000)
- **Full Range**: Complete 1-65535 port scanning capability

### RustScan Integration
- **Optional Integration**: Use RustScan for ultra-fast port discovery when available
- **Graceful Fallback**: Automatically falls back to internal scanner if RustScan unavailable
- **Pass-through Arguments**: Custom RustScan arguments support

### Nmap Orchestration
- **Deep Scanning**: Automatic Nmap execution on discovered open ports
- **Service Detection**: Version detection (`-sV`) and default scripts (`-sC`)
- **Custom Scripts**: NSE script specification (default, vuln, auth, custom)
- **Multiple Outputs**: Normal, XML, and grepable output formats
- **Organized Results**: Timestamped output files in structured directories

### User Experience
- **Rich CLI**: Comprehensive command-line interface with clap v4
- **Multiple Output Formats**: Table, JSON, and YAML output options
- **Progress Feedback**: Real-time scanning progress and statistics
- **Verbose Logging**: Configurable logging levels with tracing
- **Error Handling**: Graceful error handling and recovery

## 📦 Installation

### Quick Install (One-Line)
```bash
curl -sSL https://raw.githubusercontent.com/Wael-Rd/RustMapV3/main/install.sh | bash && echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

### Prerequisites
- **Rust** (Edition 2021+): Install from [rustup.rs](https://rustup.rs/)
- **Nmap** (Optional but recommended): Install from [nmap.org](https://nmap.org/)
- **RustScan** (Optional): Install from [rustscan.github.io](https://rustscan.github.io/RustScan/)


### Manual Installation
```bash
cargo install --path .
RustMapV3 --help
```

### Verify Installation
```bash
# Test with localhost
RustMapV3 127.0.0.1 --preset fast --top 10 --no-nmap
```

## 🛠️ Usage

### Basic Examples

#### Single Target Scan
```bash
# Quick scan with fast preset
RustMapV3 192.168.1.1 --preset fast

# Full port range with thorough preset  
RustMapV3 192.168.1.1 --preset thorough

# Scan specific ports
RustMapV3 192.168.1.1 --ports "22,80,443,3306,8080-8090"

# Scan hostname with top 100 ports
RustMapV3 example.com --top 100
```

#### Multiple Targets
```bash
# Multiple IPs
RustMapV3 "192.168.1.1,192.168.1.10,example.com"

# CIDR notation with full preset
RustMapV3 192.168.1.0/24 --preset full

# Mixed targets with custom options
RustMapV3 "192.168.1.1,example.com,10.0.0.0/28" --ports "1-1024" --confirm-open
```

#### Performance Tuning
```bash
# High concurrency scan with custom settings
RustMapV3 192.168.1.0/24 --concurrency 8192 --targets-concurrency 64 --timeout 200

# Rate limited scan for stealth
RustMapV3 192.168.1.0/24 --rate 1000 --batch-size 512

# Use RustScan for discovery (fallback to internal)
RustMapV3 192.168.1.1 --use-rustscan --rustscan-args "--ulimit 10000"
```

#### Nmap Integration
```bash
# Smart Nmap with targeted scripts
RustMapV3 192.168.1.1 --nmap-mode smart

# Custom Nmap arguments with normalization
RustMapV3 192.168.1.1 --nmap-args "sCV T4 script=vuln"

# Specific NSE scripts  
RustMapV3 192.168.1.1 --nse "vuln,auth,default"

# Skip Nmap deep scanning
RustMapV3 192.168.1.1 --no-nmap

# Custom output directory with timestamped files
RustMapV3 192.168.1.1 --output /tmp/scan_results
```

#### Presets and Output Formats
```bash
# Fast preset: top 1000 ports, high concurrency, no confirm
RustMapV3 192.168.1.1 --preset fast

# Full preset (default): all ports, balanced settings
RustMapV3 192.168.1.1 --preset full  

# Thorough preset: all ports, confirm pass, lower concurrency
RustMapV3 192.168.1.1 --preset thorough

# JSON output
RustMapV3 192.168.1.1 --format json

# YAML output  
RustMapV3 192.168.1.1 --format yaml

# Quiet mode
RustMapV3 192.168.1.1 --quiet

# Verbose logging
RustMapV3 192.168.1.1 --verbose
```

### Advanced Usage

#### Large Network Scan
```bash
RustMapV3 "10.0.0.0/20" \
  --preset full \
  --targets-concurrency 64 \
  --rate 15000 \
  --confirm-open \
  --nse "default,vuln" \
  --output ./enterprise_scan \
  --format json
```

#### Stealth Scan
```bash
RustMapV3 target.com \
  --ports "22,80,443" \
  --concurrency 10 \
  --rate 5 \
  --timeout 2000 \
  --nmap-args "T1 A" \
  --nmap-mode plain
```

## 📊 Output

### Console Output
RustMapV3 provides rich console output with scan progress, open port discovery, and result summaries:

```
🎯 Target: example.com (93.184.216.34)
   Scan Duration: 2.34s
   Ports Scanned: 1000
   Open Ports: 80,443
   🟢 2 open ports found

📈 Summary
   Targets Scanned: 1
   Targets with Open Ports: 1
   Total Open Ports: 2
```

### File Output
Nmap integration creates organized output files:
```
scans/
├── 20240816_143022_example.com_93.184.216.34.nmap    # Normal output
├── 20240816_143022_example.com_93.184.216.34.xml     # XML output
└── 20240816_143022_example.com_93.184.216.34.gnmap   # Grepable output
```

### JSON Output
Structured JSON output for automation and integration:
```json
{
  "scan_results": [
    {
      "target": {
        "ip": "93.184.216.34",
        "hostname": "example.com",
        "display_name": "example.com (93.184.216.34)"
      },
      "scan_duration_seconds": 2.34,
      "total_ports_scanned": 1000,
      "open_ports": [80, 443],
      "open_port_count": 2,
      "has_open_ports": true
    }
  ],
  "summary": {
    "targets_scanned": 1,
    "targets_with_open_ports": 1,
    "total_open_ports": 2
  }
}
```

## ⚙️ Configuration

### Command Line Options
```
USAGE:
    rustmapv3 [OPTIONS] <TARGETS>

ARGUMENTS:
    <TARGETS>    Target(s): IP (192.168.1.1), hostname (example.com), 
                 list (192.168.1.1,example.com), or CIDR (192.168.1.0/24)

OPTIONS:
    -p, --ports <PORTS>           Port ranges/lists: 1-1024,3306,8080-8090 [default: 1-65535]
    -t, --top <N>                 Scan top N common ports (100, 1000, 5000)
    -c, --concurrency <N>         Concurrent connection limit [default: 4096]
        --timeout <MS>            Connection timeout in milliseconds [default: 300]
    -r, --rate <N>                Max connection attempts per second
        --batch-size <N>          Internal batch size for processing [default: 1024]
        --use-rustscan            Use RustScan binary for port discovery
        --rustscan-args <ARGS>    Additional arguments for RustScan
        --nmap-args <ARGS>        Additional arguments for Nmap
        --nse <SCRIPTS>           NSE scripts: default,vuln,auth or specific script names
    -o, --output <DIR>            Output directory for scan results [default: scans]
        --no-nmap                 Skip Nmap deep scanning, only perform port discovery
    -v, --verbose                 Enable verbose output
    -q, --quiet                   Quiet mode
        --format <FORMAT>         Output format: json, yaml, table [default: table]
    -h, --help                    Print help
    -V, --version                 Print version
```

### Environment Variables
RustMapV3 respects standard environment variables:
- `RUST_LOG`: Set logging level (trace, debug, info, warn, error)
- `NO_COLOR`: Disable colored output

## 🔧 Development

### Building from Source
```bash
git clone https://github.com/Wael-Rd/RustMapV3.git
cd RustMapV3
cargo build --release
```

### Running Tests
```bash
cargo test
```

### Development Mode
```bash
cargo run -- --help
cargo run -- 127.0.0.1 --top 10 --verbose
```

### Code Structure
```
src/
├── main.rs         # CLI entry point and orchestration
├── lib.rs          # Library exports and common ports
├── cli.rs          # Command line argument parsing
├── scanner.rs      # Internal TCP port scanner
├── rustscan.rs     # RustScan integration
├── nmap.rs         # Nmap orchestration
├── targets.rs      # Target parsing and expansion
├── ports.rs        # Port range parsing
└── error.rs        # Error handling
```

## 🛡️ Security Considerations

### Performance Impact
- High concurrency can impact network performance
- Rate limiting helps prevent network congestion
- Batch processing reduces memory usage

### Network Behavior
- TCP SYN scanning (connect scans)
- Respects target network timeouts
- Configurable scan timing

### Best Practices
- Start with lower concurrency for unknown networks
- Use rate limiting in production environments
- Monitor network impact during scans
- Verify target ownership before scanning

## ⚠️ Legal and Ethical Disclaimer

**RustMapV3 is intended for legitimate security testing, network administration, and educational purposes only.**

### Important Guidelines:
- ✅ **DO**: Only scan networks and systems you own or have explicit written permission to test
- ✅ **DO**: Use for authorized penetration testing and security assessments
- ✅ **DO**: Follow responsible disclosure practices for any vulnerabilities found
- ✅ **DO**: Comply with all applicable local, state, and federal laws

- ❌ **DON'T**: Scan networks without explicit authorization
- ❌ **DON'T**: Use for malicious purposes or unauthorized access attempts
- ❌ **DON'T**: Violate terms of service or computer fraud laws
- ❌ **DON'T**: Scan networks you don't own without permission

### Legal Notice:
Unauthorized scanning of networks may violate:
- Computer Fraud and Abuse Act (CFAA) in the United States
- Computer Misuse Act in the United Kingdom
- Similar cybersecurity laws in other jurisdictions

**The developers assume no liability for any misuse of this tool. Users are solely responsible for compliance with all applicable laws and regulations.**

By using RustMapV3, you acknowledge that you have read and understood this disclaimer and agree to use the tool responsibly and legally.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Areas for Contribution:
- Additional output formats
- Performance optimizations
- More comprehensive NSE script integration
- IPv6 scanning enhancements
- GUI interface
- Docker containerization

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Wael-Rd/RustMapV3/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Wael-Rd/RustMapV3/discussions)
- **Documentation**: This README and inline code documentation

## 🙏 Acknowledgments

- **RustScan**: Inspiration for high-performance Rust-based scanning
- **Nmap**: The gold standard for network discovery and security auditing
- **Rust Community**: For excellent networking and async libraries
- **Security Community**: For continuous feedback and responsible disclosure practices

---

**RustMapV3** - Combining the speed of Rust with the power of Nmap for comprehensive network discovery.
