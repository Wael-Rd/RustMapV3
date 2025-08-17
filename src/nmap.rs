use crate::scanner::ScanResults;
use crate::targets::Target;
use crate::{Error, Result};
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct NmapConfig { pub nmap_args: Option<String>, pub nse_scripts: Option<String>, pub output_dir: PathBuf, pub smart_mode: bool }
impl Default for NmapConfig { fn default() -> Self { Self { nmap_args: None, nse_scripts: None, output_dir: PathBuf::from("scans"), smart_mode: true } } }

pub struct NmapOrchestrator { config: NmapConfig }
impl NmapOrchestrator {
    pub fn new(config: NmapConfig) -> Self { Self { config } }
    pub fn is_available() -> bool { Command::new("nmap").arg("--version").output().map(|o| o.status.success()).unwrap_or(false) }
    pub async fn deep_scan(&self, scan_results: &[ScanResults]) -> Result<Vec<NmapResult>> {
        if !Self::is_available() { return Err(Error::NmapError("Nmap binary not found in PATH".into())); }
        self.ensure_output_directory()?; let mut out = Vec::new();
        for r in scan_results { if !r.has_open_ports() { info!("Skipping Nmap for {} (no open ports)", r.target.display_name()); continue; } match self.run_nmap_scan(r).await { Ok(n) => out.push(n), Err(e) => warn!("Nmap failed for {}: {}", r.target.display_name(), e) } }
        Ok(out)
    }
    async fn run_nmap_scan(&self, scan_result: &ScanResults) -> Result<NmapResult> {
        let started = Instant::now(); let target_name = self.generate_target_filename(&scan_result.target); let output_path = self.config.output_dir.clone().join(&target_name);
        let mut cmd = Command::new("nmap"); cmd.arg("-Pn").arg("-sV").arg("-sC").arg("-T4");
        if self.config.smart_mode && self.config.nse_scripts.is_none() { let smart_scripts = scripts_for_ports(&scan_result.open_ports); if !smart_scripts.is_empty() { cmd.arg("--script").arg(smart_scripts); } }
        if let Some(ref scripts) = self.config.nse_scripts { cmd.arg("--script").arg(scripts); }
        if let Some(ref args) = self.config.nmap_args { for a in normalize_nmap_args(args).split_whitespace() { cmd.arg(a); } }
        if !scan_result.open_ports.is_empty() { cmd.arg("-p").arg(format_ports_for_nmap(&scan_result.open_ports)); }
        cmd.arg("-oA").arg(&output_path); cmd.arg("--").arg(scan_result.target.ip.to_string());
        debug!("Executing Nmap: {:?}", cmd);
        let output = tokio::task::spawn_blocking(move || cmd.output()).await.map_err(|e| Error::NmapError(format!("Failed to execute Nmap: {}", e)))?.map_err(|e| Error::NmapError(format!("Nmap execution failed: {}", e)))?;
        let dur = started.elapsed(); if !output.status.success() { let stderr = String::from_utf8_lossy(&output.stderr); return Err(Error::NmapError(format!("Nmap failed: {}", stderr))); }
        let stdout = String::from_utf8_lossy(&output.stdout); info!("Nmap completed for {} in {:.2}s", scan_result.target.display_name(), dur.as_secs_f64());
        Ok(NmapResult { target: scan_result.target.clone(), scan_duration: dur, output_files: NmapOutputFiles { base_name: target_name, normal_output: output_path.with_extension("nmap"), xml_output: output_path.with_extension("xml"), grepable_output: output_path.with_extension("gnmap") }, stdout: stdout.to_string(), scanned_ports: scan_result.open_ports.clone() })
    }
    fn ensure_output_directory(&self) -> Result<()> { if !self.config.output_dir.exists() { fs::create_dir_all(&self.config.output_dir).map_err(Error::Io)?; info!("Created output directory: {:?}", self.config.output_dir); } Ok(()) }
    fn generate_target_filename(&self, target: &Target) -> String { let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S"); let ip = target.ip.to_string().replace(':', "_"); if let Some(h) = &target.hostname { let clean = h.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '.' { c } else { '_' }).collect::<String>(); format!("{}_{}_{}", ts, clean, ip) } else { format!("{}_{}", ts, ip) } }
}

#[derive(Debug, Clone)]
pub struct NmapResult { pub target: Target, pub scan_duration: std::time::Duration, pub output_files: NmapOutputFiles, pub stdout: String, pub scanned_ports: Vec<u16> }
#[derive(Debug, Clone)]
pub struct NmapOutputFiles { pub base_name: String, pub normal_output: PathBuf, pub xml_output: PathBuf, pub grepable_output: PathBuf }
impl NmapOutputFiles { pub fn all_exist(&self) -> bool { self.normal_output.exists() && self.xml_output.exists() && self.grepable_output.exists() } pub fn existing_files(&self) -> Vec<&PathBuf> { let mut v = Vec::new(); if self.normal_output.exists() { v.push(&self.normal_output); } if self.xml_output.exists() { v.push(&self.xml_output); } if self.grepable_output.exists() { v.push(&self.grepable_output); } v } }

static PORT_SCRIPT_MAP: Lazy<Vec<(u16, &'static str)>> = Lazy::new(|| vec![ (21, "ftp-*"), (22, "ssh-*"), (23, "telnet-*"), (25, "smtp-commands,smtp-enum-users,smtp-open-relay"), (53, "dns-*"), (80, "http-title,http-server-header,http-headers,http-methods,http-enum"), (110, "pop3-*"), (111, "rpcinfo"), (135, "msrpc-enum,msrpc-enum-shares"), (139, "smb2-security-mode,smb2-time,smb2-capabilities"), (143, "imap-*"), (161, "snmp-info,snmp-netstat,snmp-processes"), (389, "ldap*"), (443, "http-title,http-server-header,ssl-cert,ssl-enum-ciphers"), (445, "smb-enum-shares,smb-enum-users,smb-os-discovery,smb2-security-mode"), (465, "smtp-commands,ssl-enum-ciphers"), (587, "smtp-commands"), (631, "ipp*"), (993, "imap-*"), (995, "pop3-*"), (1352, "notes-ntlm-info"), (1433, "ms-sql-info,ms-sql-ntlm-info,ms-sql-dac"), (1521, "oracle-tns-version,oracle-tns-poison"), (2049, "nfs-ls,nfs-showmount"), (2375, "docker-version"), (27017, "mongodb-info"), (3306, "mysql-info,mysql-enum,mysql-audit"), (3389, "rdp-enum-encryption,rdp-ntlm-info"), (4433, "ssl-cert,ssl-enum-ciphers"), (5432, "pgsql-info,pgsql-brute"), (5601, "http-title,http-server-header"), (5672, "amqp-info"), (5900, "vnc-info"), (5985, "http-title,http-server-header"), (6379, "redis-info"), (6443, "http-title,http-server-header"), (8000, "http-title,http-methods"), (8080, "http-title,http-headers,http-methods,http-enum"), (8443, "http-title,ssl-cert,ssl-enum-ciphers"), (9000, "http-title"), (9200, "http-title,http-methods"), (11211, "memcached-info") ]);

fn scripts_for_ports(open_ports: &[u16]) -> String { let mut set = HashSet::new(); set.insert("default".to_string()); for p in open_ports { for (port, scripts) in PORT_SCRIPT_MAP.iter() { if p == port { for s in scripts.split(',') { set.insert(s.trim().to_string()); } } } } let mut v: Vec<_> = set.into_iter().collect(); v.sort(); v.join(",") }

fn normalize_nmap_args(input: &str) -> String { let mut out: Vec<String> = Vec::new(); for tok in input.split_whitespace() { if tok.starts_with('-') { out.push(tok.to_string()); continue; } let up = tok.to_ascii_uppercase(); match up.as_str() { "SCV" => { out.push("-sC".into()); out.push("-sV".into()); continue; }, "SC" => { out.push("-sC".into()); continue; }, "SV" => { out.push("-sV".into()); continue; }, "SS" => { out.push("-sS".into()); continue; }, "SU" => { out.push("-sU".into()); continue; }, "PN" => { out.push("-Pn".into()); continue; }, "A" => { out.push("-A".into()); continue; }, _ => {} } if up.len() == 2 && up.starts_with('T') && matches!(up.as_bytes()[1], b'0'..=b'5') { out.push(format!("-{}", up)); continue; } if let Some((k, v)) = tok.split_once('=') { let known = ["script","min-rate","max-retries","host-timeout","scan-delay","max-scan-delay","data-length","version-intensity","script-timeout"]; if known.iter().any(|kk| kk.eq_ignore_ascii_case(k)) { out.push(format!("--{}={}", k, v)); continue; } } if tok.len() <= 3 && tok.chars().all(|c| c.is_ascii_alphanumeric()) { out.push(format!("-{}", tok)); } else { out.push(tok.to_string()); } } out.join(" ") }

fn format_ports_for_nmap(ports: &[u16]) -> String { if ports.is_empty() { return "1-65535".into(); } let mut ret = Vec::new(); let mut start = ports[0]; let mut end = ports[0]; for &p in &ports[1..] { if p == end + 1 { end = p; } else { if start == end { ret.push(start.to_string()); } else { ret.push(format!("{}-{}", start, end)); } start = p; end = p; } } if start == end { ret.push(start.to_string()); } else { ret.push(format!("{}-{}", start, end)); } ret.join(",") }

#[cfg(test)]
mod tests { use super::*; #[test] fn test_format_ports() { assert_eq!(format_ports_for_nmap(&[]), "1-65535"); assert_eq!(format_ports_for_nmap(&[80,81,82,90,91]), "80-82,90-91"); } #[test] fn test_normalize_args() { assert_eq!(normalize_nmap_args("sCV"), "-sC -sV"); assert_eq!(normalize_nmap_args("T5 Pn script=default,vuln"), "-T5 -Pn --script=default,vuln"); } }