//! Lightweight protocol probes for quick fingerprinting without persistent storage

use crate::targets::Target;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// Result of a single probe
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub port: u16,
    pub protocol: String,
    pub summary: String,
}

/// Run a minimal probe against an open port. Returns None if nothing useful is learned.
pub async fn probe_port(target: &Target, port: u16, timeout_dur: Duration) -> Option<ProbeResult> {
    // Quick routing by common port to avoid costly heuristics
    if [22u16, 2222, 222].contains(&port) {
        return probe_banner(target, port, timeout_dur, "ssh").await;
    }
    if [25, 110, 143, 465, 587, 993, 995].contains(&port) {
        return probe_banner(target, port, timeout_dur, "mail").await;
    }
    if [6379].contains(&port) {
        return probe_redis(target, port, timeout_dur).await;
    }
    if [3306].contains(&port) {
        return probe_mysql(target, port, timeout_dur).await;
    }
    if [80, 443, 8080, 8081, 8000, 8443, 5601, 9000, 9200].contains(&port) {
        if let Some(r) = probe_http(target, port, timeout_dur).await { return Some(r); }
    }
    // Generic fallback banner grab
    probe_banner(target, port, timeout_dur, "tcp").await
}

async fn connect(target: &Target, port: u16, timeout_dur: Duration) -> Option<TcpStream> {
    let addr = std::net::SocketAddr::new(target.ip, port);
    match timeout(timeout_dur, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => Some(stream),
        _ => None,
    }
}

async fn probe_banner(target: &Target, port: u16, timeout_dur: Duration, proto: &str) -> Option<ProbeResult> {
    let mut stream = connect(target, port, timeout_dur).await?;
    let mut buf = vec![0u8; 256];
    let read = match timeout(timeout_dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => 0,
    };
    let snippet = if read > 0 { sanitize(&buf[..read]) } else { "".to_string() };
    let summary = if snippet.is_empty() { format!("open {}", proto) } else { snippet.clone() };
    let _ = stream.shutdown();
    Some(ProbeResult { port, protocol: proto.to_string(), summary })
}

async fn probe_http(target: &Target, port: u16, timeout_dur: Duration) -> Option<ProbeResult> {
    let mut stream = connect(target, port, timeout_dur).await?;
    let ip_fallback = target.ip.to_string();
    let host = target.hostname.as_deref().unwrap_or(&ip_fallback);
    let req = format!("HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: rustmapv3-probe\r\n\r\n");
    let _ = timeout(timeout_dur, stream.write_all(req.as_bytes())).await.ok()?;
    let mut buf = vec![0u8; 512];
    let n = timeout(timeout_dur, stream.read(&mut buf)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
    let snippet = if n > 0 { sanitize(&buf[..n]) } else { "".to_string() };
    let summary = if snippet.is_empty() { "http-ish".to_string() } else { snippet.clone() };
    let _ = stream.shutdown();
    Some(ProbeResult { port, protocol: "http".to_string(), summary })
}

async fn probe_redis(target: &Target, port: u16, timeout_dur: Duration) -> Option<ProbeResult> {
    let mut stream = connect(target, port, timeout_dur).await?;
    let _ = timeout(timeout_dur, stream.write_all(b"PING\r\n")).await.ok()?;
    let mut buf = [0u8; 64];
    let n = timeout(timeout_dur, stream.read(&mut buf)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
    let snippet = if n > 0 { sanitize(&buf[..n]) } else { "".to_string() };
    let _ = stream.shutdown();
    Some(ProbeResult { port, protocol: "redis".to_string(), summary: if snippet.is_empty() { "+PONG?".to_string() } else { snippet } })
}

async fn probe_mysql(target: &Target, port: u16, timeout_dur: Duration) -> Option<ProbeResult> {
    let mut stream = connect(target, port, timeout_dur).await?;
    let mut buf = [0u8; 96];
    let n = timeout(timeout_dur, stream.read(&mut buf)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
    let snippet = if n > 0 { sanitize(&buf[..n]) } else { "".to_string() };
    let _ = stream.shutdown();
    Some(ProbeResult { port, protocol: "mysql".to_string(), summary: if snippet.is_empty() { "mysql-handshake".to_string() } else { snippet } })
}

fn sanitize(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes.iter().take(200) {
        let c = b as char;
        if c.is_ascii_graphic() || c.is_ascii_whitespace() {
            s.push(c);
        }
    }
    s.split_whitespace().take(6).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn test_sanitize() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n";
        let s = sanitize(raw);
        assert!(s.contains("HTTP/1.1"));
    }
}
