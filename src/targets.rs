//! Target parsing and expansion module

use crate::{Error, Result};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use trust_dns_resolver::TokioAsyncResolver;

/// Represents a scan target
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub ip: IpAddr,
    pub hostname: Option<String>,
}

impl Target {
    /// Create a new target from an IP address
    pub fn from_ip(ip: IpAddr) -> Self {
        Self { ip, hostname: None }
    }

    /// Create a new target from an IP address with hostname
    pub fn from_ip_with_hostname(ip: IpAddr, hostname: String) -> Self {
        Self {
            ip,
            hostname: Some(hostname),
        }
    }

    /// Get the display name for this target
    pub fn display_name(&self) -> String {
        if let Some(ref hostname) = self.hostname {
            format!("{} ({})", hostname, self.ip)
        } else {
            self.ip.to_string()
        }
    }
}

/// Parse and expand targets from a string
pub async fn parse_targets(targets_str: &str) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .map_err(|e| Error::DnsResolution(format!("Failed to create DNS resolver: {}", e)))?;

    for target_str in targets_str.split(',') {
        let target_str = target_str.trim();
        if target_str.is_empty() {
            continue;
        }

        // Try to parse as CIDR
        if let Ok(parsed_targets) = parse_cidr_targets(target_str).await {
            targets.extend(parsed_targets);
        }
        // Try to parse as IP address
        else if let Ok(ip) = IpAddr::from_str(target_str) {
            targets.push(Target::from_ip(ip));
        }
        // Treat as hostname
        else {
            match resolve_hostname(&resolver, target_str).await {
                Ok(resolved_targets) => targets.extend(resolved_targets),
                Err(e) => {
                    eprintln!("Warning: Failed to resolve hostname '{}': {}", target_str, e);
                    continue;
                }
            }
        }
    }

    if targets.is_empty() {
        return Err(Error::InvalidTarget("No valid targets found".to_string()));
    }

    // Remove duplicates while preserving order
    let mut seen = std::collections::HashSet::new();
    targets.retain(|target| seen.insert(target.clone()));

    Ok(targets)
}

/// Parse CIDR notation targets
async fn parse_cidr_targets(cidr_str: &str) -> Result<Vec<Target>> {
    let network = IpNetwork::from_str(cidr_str)
        .map_err(|_| Error::InvalidTarget(format!("Invalid CIDR notation: {}", cidr_str)))?;

    let targets = match network {
        IpNetwork::V4(net) => expand_ipv4_network(net)?,
        IpNetwork::V6(net) => expand_ipv6_network(net)?,
    };

    Ok(targets)
}

/// Expand IPv4 network to individual targets
fn expand_ipv4_network(network: Ipv4Network) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    
    // Limit expansion to reasonable sizes to prevent memory issues
    if network.prefix() < 16 {
        return Err(Error::InvalidTarget(
            "CIDR blocks larger than /16 are not supported for IPv4".to_string(),
        ));
    }

    for ip in network.iter() {
        // Skip network and broadcast addresses for /31 and smaller networks
        if network.prefix() < 31 {
            if ip == network.network() || ip == network.broadcast() {
                continue;
            }
        }
        targets.push(Target::from_ip(IpAddr::V4(ip)));
    }

    Ok(targets)
}

/// Expand IPv6 network to individual targets (with reasonable limits)
fn expand_ipv6_network(network: Ipv6Network) -> Result<Vec<Target>> {
    // For IPv6, we need to be very conservative about expansion
    if network.prefix() < 120 {
        return Err(Error::InvalidTarget(
            "CIDR blocks larger than /120 are not supported for IPv6".to_string(),
        ));
    }

    let mut targets = Vec::new();
    for ip in network.iter() {
        targets.push(Target::from_ip(IpAddr::V6(ip)));
    }

    Ok(targets)
}

/// Resolve hostname to IP addresses
async fn resolve_hostname(
    resolver: &TokioAsyncResolver,
    hostname: &str,
) -> Result<Vec<Target>> {
    let mut targets = Vec::new();

    // Try IPv4 resolution
    match resolver.lookup_ip(hostname).await {
        Ok(lookup) => {
            for ip in lookup.iter() {
                targets.push(Target::from_ip_with_hostname(ip, hostname.to_string()));
            }
        }
        Err(e) => {
            return Err(Error::DnsResolution(format!(
                "Failed to resolve hostname '{}': {}",
                hostname, e
            )));
        }
    }

    if targets.is_empty() {
        return Err(Error::DnsResolution(format!(
            "No IP addresses found for hostname '{}'",
            hostname
        )));
    }

    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_display_name() {
        let target_ip = Target::from_ip("192.168.1.1".parse().unwrap());
        assert_eq!(target_ip.display_name(), "192.168.1.1");

        let target_hostname = Target::from_ip_with_hostname(
            "192.168.1.1".parse().unwrap(),
            "example.com".to_string(),
        );
        assert_eq!(target_hostname.display_name(), "example.com (192.168.1.1)");
    }

    #[test]
    fn test_expand_ipv4_network() {
        let network = "192.168.1.0/30".parse().unwrap();
        let targets = expand_ipv4_network(network).unwrap();
        assert_eq!(targets.len(), 2); // .1 and .2 (excluding network and broadcast)
    }

    #[tokio::test]
    async fn test_invalid_large_cidr() {
        let result = parse_cidr_targets("10.0.0.0/8").await;
        assert!(result.is_err());
    }
}