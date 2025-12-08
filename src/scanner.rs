use crate::targets::Target;
use crate::probes::{probe_port, ProbeResult};
use crate::Result;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info};

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub concurrency: usize,
    pub targets_concurrency: usize,
    pub timeout: Duration,
    pub rate_limit: Option<u64>,
    pub batch_size: usize,
    pub confirm_open: bool,
    pub enable_probes: bool,
    pub stream_events: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            concurrency: 8192,
            targets_concurrency: 32,
            timeout: Duration::from_millis(250),
            rate_limit: Some(15000),
            batch_size: 2000,
            confirm_open: true,
            enable_probes: true,
            stream_events: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanResults {
    pub target: Target,
    pub open_ports: Vec<u16>,
    pub total_ports_scanned: usize,
    pub scan_duration: Duration,
    pub probes: Vec<ProbeResult>,
}
impl ScanResults { pub fn has_open_ports(&self) -> bool { !self.open_ports.is_empty() } pub fn open_port_count(&self) -> usize { self.open_ports.len() } }

pub struct Scanner { pub(crate) config: ScanConfig }
impl Scanner {
    pub fn new(config: ScanConfig) -> Self { Self { config } }
    pub async fn scan_targets(&self, targets: &[Target], ports: &[u16]) -> Result<Vec<ScanResults>> {
        info!("Starting scan of {} targets over {} ports (target concurrency: {}, per-target concurrency: {})", targets.len(), ports.len(), self.config.targets_concurrency, self.config.concurrency);
        let futs = targets.iter().cloned().map(|t| self.scan_target_owned(t, ports.to_vec()));
        let results: Vec<ScanResults> = stream::iter(futs).buffer_unordered(self.config.targets_concurrency).collect().await; Ok(results)
    }
    async fn scan_target_owned(&self, target: Target, ports: Vec<u16>) -> ScanResults {
        match self.scan_target(&target, &ports).await {
            Ok(res) => res,
            Err(_) => ScanResults {
                target,
                open_ports: vec![],
                total_ports_scanned: ports.len(),
                scan_duration: Duration::from_secs(0),
                probes: vec![],
            },
        }
    }
    pub async fn scan_target(&self, target: &Target, ports: &[u16]) -> Result<ScanResults> {
        let start = Instant::now(); info!("Scanning {} ports on {}", ports.len(), target.display_name());
        let rate_limiter = self.config.rate_limit.map(|r| Arc::new(tokio::sync::Mutex::new(RateLimiter::new(r))));
        let mut open = Vec::new();
        let chunks = crate::ports::chunk_ports(ports, self.config.batch_size);
        for chunk in chunks {
            let tasks = chunk.into_iter().map(|port| {
                let target = target.clone();
                let rate_limiter = rate_limiter.clone();
                let to = self.config.timeout;
                async move {
                    if let Some(l) = &rate_limiter {
                        let mut l = l.lock().await;
                        l.wait().await;
                    }
                    if scan_port_once(&target, port, to).await { Some(port) } else { None }
                }
            });

            let mut found: Vec<u16> = stream::iter(tasks)
                .buffer_unordered(self.config.concurrency)
                .filter_map(|x| async move { x })
                .collect()
                .await;

            if self.config.stream_events {
                for p in &found {
                    println!(
                        "{}",
                        serde_json::json!({
                            "event": "port_open",
                            "target": target.display_name(),
                            "port": p
                        })
                    );
                }
            }

            open.append(&mut found);
        }
        let open_ports = if self.config.confirm_open && !open.is_empty() {
            let confirm_to = (self.config.timeout.as_millis() as u64 * 2).clamp(200, 1500);
            let confirm_to = Duration::from_millis(confirm_to);
            let tasks = open.into_iter().map(|p| confirm_open_port(target, p, confirm_to));
            let mut confirmed: Vec<u16> = stream::iter(tasks)
                .buffer_unordered(self.config.concurrency.min(1024))
                .filter_map(|x| async move { if x.1 { Some(x.0) } else { None } })
                .collect()
                .await;
            confirmed.sort_unstable();
            confirmed
        } else {
            let mut ports_vec = open;
            ports_vec.sort_unstable();
            ports_vec
        };

        let probes = if self.config.enable_probes && !open_ports.is_empty() {
            self.run_probes(target, &open_ports).await
        } else {
            Vec::new()
        };

        let dur = start.elapsed();
        info!(
            "Completed scan of {} — {} open ports in {:.2}s ({} probes)",
            target.display_name(),
            open_ports.len(),
            dur.as_secs_f64(),
            probes.len()
        );

        Ok(ScanResults {
            target: target.clone(),
            open_ports,
            total_ports_scanned: ports.len(),
            scan_duration: dur,
            probes,
        })
    }

    async fn run_probes(&self, target: &Target, open_ports: &[u16]) -> Vec<ProbeResult> {
        let tasks = open_ports.iter().copied().map(|p| {
            let target = target.clone();
            let timeout = self.config.timeout;
            async move { probe_port(&target, p, timeout).await }
        });

        let mut results: Vec<ProbeResult> = stream::iter(tasks)
            .buffer_unordered(self.config.concurrency.min(512))
            .filter_map(|r| async move { r })
            .collect()
            .await;

        results.sort_by_key(|r| r.port);
        if self.config.stream_events {
            for r in &results {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "probe_result",
                        "target": target.display_name(),
                        "port": r.port,
                        "protocol": r.protocol,
                        "summary": r.summary,
                    })
                );
            }
        }
        results
    }
}

async fn scan_port_once(target: &Target, port: u16, timeout_duration: Duration) -> bool { let addr = std::net::SocketAddr::new(target.ip, port); match timeout(timeout_duration, TcpStream::connect(addr)).await { Ok(Ok(mut stream)) => { let _ = stream.set_nodelay(true); let _ = stream.shutdown(); debug!("Open: {}:{}", target.display_name(), port); true }, _ => false } }
async fn confirm_open_port(target: &Target, port: u16, timeout_duration: Duration) -> (u16, bool) { let addr = std::net::SocketAddr::new(target.ip, port); let ok = match timeout(timeout_duration, TcpStream::connect(addr)).await { Ok(Ok(mut stream)) => { let _ = stream.set_nodelay(true); let mut buf = [0u8; 1]; let _ = timeout(Duration::from_millis(50), stream.read(&mut buf)).await; let _ = stream.shutdown(); true }, _ => false }; (port, ok) }

struct RateLimiter { last_refill: Instant, tokens: f64, max_tokens: f64, refill_rate: f64 }
impl RateLimiter { fn new(rate_per_sec: u64) -> Self { let max = rate_per_sec as f64; Self { last_refill: Instant::now(), tokens: max, max_tokens: max, refill_rate: max } } async fn wait(&mut self) { let now = Instant::now(); let elapsed = now.duration_since(self.last_refill).as_secs_f64(); self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens); self.last_refill = now; if self.tokens < 1.0 { let wait_for = Duration::from_secs_f64((1.0 - self.tokens) / self.refill_rate); tokio::time::sleep(wait_for).await; self.tokens = 1.0; } self.tokens -= 1.0; } }