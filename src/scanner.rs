//! High-performance TCP port scanner

use crate::targets::Target;
use crate::{Error, Result};
use futures::stream::{self, StreamExt};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Configuration for the port scanner
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Maximum number of concurrent connections
    pub concurrency: usize,
    /// Connection timeout per port
    pub timeout: Duration,
    /// Optional rate limiting (connections per second)
    pub rate_limit: Option<u64>,
    /// Batch size for processing
    pub batch_size: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            concurrency: 4096,
            timeout: Duration::from_millis(300),
            rate_limit: None,
            batch_size: 1024,
        }
    }
}

/// Result of scanning a single port
#[derive(Debug, Clone)]
pub struct PortResult {
    pub target: Target,
    pub port: u16,
    pub is_open: bool,
    pub response_time: Duration,
}

/// Results of scanning a target
#[derive(Debug, Clone)]
pub struct ScanResults {
    pub target: Target,
    pub open_ports: Vec<u16>,
    pub total_ports_scanned: usize,
    pub scan_duration: Duration,
}

impl ScanResults {
    /// Check if any ports were found open
    pub fn has_open_ports(&self) -> bool {
        !self.open_ports.is_empty()
    }

    /// Get count of open ports
    pub fn open_port_count(&self) -> usize {
        self.open_ports.len()
    }
}

/// High-performance TCP port scanner
pub struct Scanner {
    config: ScanConfig,
}

impl Scanner {
    /// Create a new scanner with the given configuration
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    /// Scan multiple targets and ports
    pub async fn scan_targets(
        &self,
        targets: &[Target],
        ports: &[u16],
    ) -> Result<Vec<ScanResults>> {
        info!(
            "Starting scan of {} targets with {} ports (concurrency: {})",
            targets.len(),
            ports.len(),
            self.config.concurrency
        );

        let mut results = Vec::new();

        for target in targets {
            let target_result = self.scan_target(target, ports).await?;
            results.push(target_result);
        }

        Ok(results)
    }

    /// Scan a single target across multiple ports
    pub async fn scan_target(&self, target: &Target, ports: &[u16]) -> Result<ScanResults> {
        let start_time = Instant::now();
        
        info!(
            "Scanning target {} with {} ports",
            target.display_name(),
            ports.len()
        );

        let semaphore = Arc::new(Semaphore::new(self.config.concurrency));
        let mut open_ports = Vec::new();

        // Create rate limiter if specified
        let rate_limiter = if let Some(rate) = self.config.rate_limit {
            Some(Arc::new(tokio::sync::Mutex::new(RateLimiter::new(rate))))
        } else {
            None
        };

        // Process ports in chunks to manage memory usage
        let port_chunks = crate::ports::chunk_ports(ports, self.config.batch_size);
        
        for chunk in port_chunks {
            let chunk_results = self.scan_port_chunk(
                target,
                &chunk,
                semaphore.clone(),
                rate_limiter.clone(),
            ).await?;

            for result in chunk_results {
                if result.is_open {
                    open_ports.push(result.port);
                    debug!(
                        "Open port found: {}:{} ({}ms)",
                        target.display_name(),
                        result.port,
                        result.response_time.as_millis()
                    );
                }
            }
        }

        // Sort open ports
        open_ports.sort_unstable();
        
        let scan_duration = start_time.elapsed();
        
        info!(
            "Completed scan of {} - {} open ports found in {:.2}s",
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

    /// Scan a chunk of ports for a target
    async fn scan_port_chunk(
        &self,
        target: &Target,
        ports: &[u16],
        semaphore: Arc<Semaphore>,
        rate_limiter: Option<Arc<tokio::sync::Mutex<RateLimiter>>>,
    ) -> Result<Vec<PortResult>> {
        let scan_tasks = ports.iter().map(|&port| {
            let target = target.clone();
            let semaphore = semaphore.clone();
            let rate_limiter = rate_limiter.clone();
            let timeout_duration = self.config.timeout;

            async move {
                // Acquire semaphore permit
                let _permit = semaphore.acquire().await.unwrap();

                // Apply rate limiting if configured
                if let Some(limiter) = rate_limiter {
                    let mut limiter = limiter.lock().await;
                    limiter.wait().await;
                }

                self.scan_port(&target, port, timeout_duration).await
            }
        });

        // Execute all scans concurrently
        let results: Vec<PortResult> = stream::iter(scan_tasks)
            .buffer_unordered(self.config.concurrency)
            .collect()
            .await;

        Ok(results)
    }

    /// Scan a single port on a target
    async fn scan_port(
        &self,
        target: &Target,
        port: u16,
        timeout_duration: Duration,
    ) -> PortResult {
        let start_time = Instant::now();
        let socket_addr = SocketAddr::new(target.ip, port);

        let is_open = match timeout(timeout_duration, TcpStream::connect(socket_addr)).await {
            Ok(Ok(_)) => true,
            Ok(Err(_)) => false,
            Err(_) => false, // Timeout
        };

        let response_time = start_time.elapsed();

        PortResult {
            target: target.clone(),
            port,
            is_open,
            response_time,
        }
    }
}

/// Simple rate limiter using token bucket algorithm
struct RateLimiter {
    last_refill: Instant,
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
}

impl RateLimiter {
    fn new(rate_per_second: u64) -> Self {
        let max_tokens = rate_per_second as f64;
        Self {
            last_refill: Instant::now(),
            tokens: max_tokens,
            max_tokens,
            refill_rate: rate_per_second as f64,
        }
    }

    async fn wait(&mut self) {
        // Refill tokens based on elapsed time
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;

        // If no tokens available, wait
        if self.tokens < 1.0 {
            let wait_time = Duration::from_secs_f64((1.0 - self.tokens) / self.refill_rate);
            tokio::time::sleep(wait_time).await;
            self.tokens = 1.0;
        }

        // Consume a token
        self.tokens -= 1.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_scanner_creation() {
        let config = ScanConfig::default();
        let scanner = Scanner::new(config);
        assert_eq!(scanner.config.concurrency, 4096);
    }

    #[tokio::test]
    async fn test_scan_localhost() {
        let config = ScanConfig {
            concurrency: 10,
            timeout: Duration::from_millis(100),
            rate_limit: None,
            batch_size: 5,
        };
        
        let scanner = Scanner::new(config);
        let target = Target::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let ports = vec![80, 443, 22, 8080]; // Common ports that are likely closed on localhost
        
        let result = scanner.scan_target(&target, &ports).await;
        assert!(result.is_ok());
        
        let scan_result = result.unwrap();
        assert_eq!(scan_result.target.ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(scan_result.total_ports_scanned, 4);
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(10); // 10 tokens per second
        assert!(limiter.tokens > 0.0);
        assert_eq!(limiter.max_tokens, 10.0);
        assert_eq!(limiter.refill_rate, 10.0);
    }
}