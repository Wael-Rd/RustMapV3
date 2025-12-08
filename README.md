# RustMapV3 �️
![011001010101010](https://raw.githubusercontent.com/Wael-Rd/RustMapV3/main/011001010101010.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) 
[![Rust Version](https://img.shields.io/badge/rust-1.70.0%2B-blue.svg)](https://www.rust-lang.org/) 
[![Build Status](https://img.shields.io/github/actions/workflow/status/Wael-Rd/RustMapV3/rust.yml?branch=main)](https://github.com/Wael-Rd/RustMapV3/actions)

**🔥 The Blazing-Fast, Nmap-Powered TCP Port Scanner 🔥**

RustMapV3 is not just another port scanner. It's a high-performance discovery engine, meticulously engineered in Rust to find open TCP ports with extreme speed, and then intelligently orchestrates the legendary **Nmap** for deep, comprehensive analysis.

It's the perfect fusion of **Rust's speed** and **Nmap's power**.

---

## 📜 Table of Contents
- [🚀 Features](#-features)
- [📦 Installation](#-installation)
- [🛠️ Usage](#-usage)
- [📊 Output](#-output)
- [⚙️ Configuration](#️-configuration)
- [🔧 Development](#-development)
- [🛡️ Security Considerations](#️-security-considerations)
- [⚠️ Legal and Ethical Disclaimer](#️-legal-and-ethical-disclaimer)
- [📄 License](#-license)
- [🤝 Contributing](#-contributing)
- [📞 Support](#-support)
- [🙏 Acknowledgments](#-acknowledgments)

---

## 🚀 Features

### High-Performance Port Discovery
- **Blazing Fast**: Asynchronous Rust-powered TCP scanner that screams through port ranges.
- **Configurable Concurrency**: Fine-tune performance with up to 4096+ concurrent connections.
- **Smart Rate Limiting**: Optional token bucket algorithm to keep your scanning polite and effective.
- **Memory Efficient**: Batch processing handles massive target lists and port ranges without breaking a sweat.
- **Timeout Control**: Configurable per-connection timeouts (default: 300ms).

### Flexible Target Specification
- **Multiple Formats**: IPs, hostnames, CIDR notation, or comma-separated lists.
- **IPv4 & IPv6**: Full support for both IP versions.
- **DNS Resolution**: Automatic and cached hostname resolution.
- **CIDR Expansion**: Intelligent and safe expansion of network ranges.

### Port Selection Options
- **Custom Ranges**: Define specific ports or ranges (`1-1024,3306,8080-8090`).
- **Top Ports**: Predefined lists of the most common ports (`top100`, `top1000`, `top5000`).
- **Full Range**: Scan all 65,535 ports.

### Nmap Orchestration
- **Deep Scanning**: Automatically run Nmap on discovered open ports.
- **Service & Version Detection**: Default scripts (`-sC`) and version detection (`-sV`).
- **Smart Scripts**: Automatic NSE script selection based on open-port probes.
- **Multiple Outputs**: Normal, XML, and grepable formats.
- **Organized Results**: Timestamped output files in structured directories.

### ✨ Awesome User Experience
- **Rich CLI**: A comprehensive and intuitive command-line interface built with `clap` v4.
- **Multiple Output Formats**: Choose from `table`, `json`, or `yaml`.
- **Real-Time Feedback**: Live progress updates and scanning statistics.
- **Verbose Logging**: Configurable logging levels with `tracing`.
- **Graceful Error Handling**: Robust error handling and recovery.

---

## 📦 Installation

### Quick & Easy (One-Line)
```bash
curl -sSL https://raw.githubusercontent.com/Wael-Rd/RustMapV3/main/install.sh | bash && echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

### Prerequisites
- **Rust** (Edition 2021+): Get it from [rustup.rs](https://rustup.rs/).
- **Nmap** (Optional but highly recommended): Get it from [nmap.org](https://nmap.org/).

### Manual Installation
```bash
cargo install --path .
RustMapV3 --help
```

### Verify Installation
```bash
# Test with localhost
RustMapV3 127.0.0.1 --profile fast -p top100 --no-nmap
```

---

## 🛠️ Usage

<details>
<summary><b>Click to expand Basic Examples</b></summary>

#### Single Target Scan
```bash
# Quick scan with fast profile
RustMapV3 192.168.1.1 --profile fast

# Full port range with stealth profile
RustMapV3 192.168.1.1 --profile stealth

# Scan specific ports
RustMapV3 192.168.1.1 --ports "22,80,443,3306,8080-8090"

# Scan hostname with top 100 ports
RustMapV3 example.com -p top100
```

#### Multiple Targets
```bash
# Multiple IPs
RustMapV3 "192.168.1.1,192.168.1.10,example.com"

# CIDR notation with balanced profile
RustMapV3 192.168.1.0/24 --profile balanced

# Mixed targets with custom options
RustMapV3 "192.168.1.1,example.com,10.0.0.0/28" --ports "1-1024"
```

#### Performance Tuning
```bash
# Pick a faster profile and smaller port set
RustMapV3 192.168.1.0/24 --profile fast -p top100

# Stream live events for automation pipelines
RustMapV3 192.168.1.0/24 --profile balanced --stream-events
```

#### Nmap Integration
```bash
# Skip Nmap deep scanning
RustMapV3 192.168.1.1 --no-nmap

# Custom output directory with timestamped files
RustMapV3 192.168.1.1 --output /tmp/scan_results
```

#### Profiles and Output Formats
```bash
# Fast profile: top 1000 ports, high concurrency, no confirm
RustMapV3 192.168.1.1 --profile fast

# Balanced profile (default): top 1000 ports, balanced settings
RustMapV3 192.168.1.1 --profile balanced

# Stealth profile: full ports, confirm pass, conservative pacing
RustMapV3 192.168.1.1 --profile stealth

# JSON output
RustMapV3 192.168.1.1 --format json

# YAML output
RustMapV3 192.168.1.1 --format yaml

# Quiet mode
RustMapV3 192.168.1.1 --quiet

# Verbose logging
RustMapV3 192.168.1.1 --verbose
```
</details>

<details>
<summary><b>Click to expand Advanced Usage</b></summary>

#### Large Network Scan
```bash
RustMapV3 "10.0.0.0/20" \
  --profile balanced \
  --output ./enterprise_scan \
  --format json
```

#### Stealth Scan
```bash
RustMapV3 target.com \
  --ports "22,80,443" \
  --profile stealth \
  --format json
```
</details>

---

## 📊 Output

### Console Output
Rich console output with progress, open ports, and summaries:
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
Organized Nmap output files:
```
scans/
├── 20240816_143022_example.com_93.184.216.34.nmap    # Normal output
├── 20240816_143022_example.com_93.184.216.34.xml     # XML output
└── 20240816_143022_example.com_93.184.216.34.gnmap   # Grepable output
```

### JSON Output
Structured JSON for easy integration and automation:
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

---

## ⚙️ Configuration

<details>
<summary><b>Click to expand Command Line Options</b></summary>

```
USAGE:
  rustmapv3 [OPTIONS] <TARGETS>

ARGUMENTS:
  <TARGETS>    IP, hostname, list (a,b), or CIDR (192.168.1.0/24)

OPTIONS:
  --profile <fast|balanced|stealth>   Speed/stealth profile [default: balanced]
  -p, --ports <PORTS>                 "top1000" (default), "top100", or ranges like 1-65535
  --no-nmap                           Skip Nmap deep scanning
  -o, --output <DIR>                  Output directory for Nmap results [default: scans]
  --format <json|yaml|table>          Output format [default: table]
  --stream-events                     Stream JSON events as results arrive
  -v, --verbose                       Verbose output
  -q, --quiet                         Quiet mode
  -h, --help                          Print help
  -V, --version                       Print version
```
</details>

<details>
<summary><b>Click to expand Environment Variables</b></summary>

RustMapV3 respects standard environment variables:
- `RUST_LOG`: Set logging level (`trace`, `debug`, `info`, `warn`, `error`).
- `NO_COLOR`: Disable colored output.
</details>

---

## 🔧 Development

<details>
<summary><b>Click to expand Development Details</b></summary>

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
├── rustscan.rs     # Legacy RustScan shim (internal scanner used)
├── nmap.rs         # Nmap orchestration
├── targets.rs      # Target parsing and expansion
├── ports.rs        # Port range parsing
└── error.rs        # Error handling
```
</details>

---

## 🛡️ Security Considerations

- **Performance Impact**: High concurrency can impact network performance. Use rate limiting.
- **Network Behavior**: Uses TCP SYN scans. Respects target network timeouts.
- **Best Practices**: Start with lower concurrency on unknown networks. Monitor network impact. **Only scan what you own or have permission to test.**

---

## ⚠️ Legal and Ethical Disclaimer

**RustMapV3 is for authorized security testing and educational purposes ONLY.**

- ✅ **DO**: Scan systems you own or have explicit, written permission to test.
- ❌ **DON'T**: Scan networks without authorization. This is illegal.
- ❌ **DON'T**: Use this tool for malicious purposes.

Unauthorized scanning is a crime. The developers assume **no liability** for misuse of this tool. You are solely responsible for your actions. **By using RustMapV3, you agree to use it legally and responsibly.**

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing
Contributions are welcome! Please submit a Pull Request or open an issue to discuss major changes.

### How you can help:
- Add more output formats.
- Optimize performance.
- Enhance NSE script integration.
- Improve IPv6 scanning.
- Build a GUI.
- Create a Docker container.

---

## 📞 Support
- **Issues**: [GitHub Issues](https://github.com/Wael-Rd/RustMapV3/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Wael-Rd/RustMapV3/discussions)

---

## 🙏 Acknowledgments
- **RustScan**: For the inspiration.
- **Nmap**: For being the gold standard.
- **The Rust Community**: For amazing libraries and support.

---

**RustMapV3** - Speed of Rust, Power of Nmap.
