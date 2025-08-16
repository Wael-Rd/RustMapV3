//! Port range parsing and management

use crate::{Error, Result};
use std::collections::HashSet;

/// Parse port specification string into a sorted vector of unique ports
pub fn parse_ports(ports_str: &str) -> Result<Vec<u16>> {
    let mut ports = HashSet::new();

    for part in ports_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if part.contains('-') {
            // Parse range
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(Error::InvalidPort(format!("Invalid port range: {}", part)));
            }

            let start = parse_single_port(range_parts[0])?;
            let end = parse_single_port(range_parts[1])?;

            if start > end {
                return Err(Error::InvalidPort(format!(
                    "Invalid port range: start ({}) > end ({})",
                    start, end
                )));
            }

            for port in start..=end {
                ports.insert(port);
            }
        } else {
            // Parse single port
            let port = parse_single_port(part)?;
            ports.insert(port);
        }
    }

    if ports.is_empty() {
        return Err(Error::InvalidPort("No valid ports specified".to_string()));
    }

    let mut sorted_ports: Vec<u16> = ports.into_iter().collect();
    sorted_ports.sort_unstable();
    Ok(sorted_ports)
}

/// Parse a single port number
fn parse_single_port(port_str: &str) -> Result<u16> {
    let port_str = port_str.trim();
    
    port_str
        .parse::<u16>()
        .map_err(|_| Error::InvalidPort(format!("Invalid port number: {}", port_str)))
        .and_then(|port| {
            if port == 0 {
                Err(Error::InvalidPort("Port number cannot be 0".to_string()))
            } else {
                Ok(port)
            }
        })
}

/// Get top N common ports from the predefined lists
pub fn get_top_ports(count: usize) -> Vec<u16> {
    crate::common_ports::get_top_ports(count).to_vec()
}

/// Validate that all ports are in valid range
pub fn validate_ports(ports: &[u16]) -> Result<()> {
    for &port in ports {
        if port == 0 {
            return Err(Error::InvalidPort("Port 0 is not valid".to_string()));
        }
    }
    Ok(())
}

/// Split ports into chunks for batch processing
pub fn chunk_ports(ports: &[u16], chunk_size: usize) -> Vec<Vec<u16>> {
    if chunk_size == 0 {
        return vec![ports.to_vec()];
    }

    ports
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

/// Format ports for display
pub fn format_ports_summary(ports: &[u16]) -> String {
    if ports.is_empty() {
        return "none".to_string();
    }

    if ports.len() <= 10 {
        // For small lists, try to create ranges for better readability
        let mut ranges = Vec::new();
        let mut start = ports[0];
        let mut end = ports[0];

        for &port in &ports[1..] {
            if port == end + 1 {
                end = port;
            } else {
                if start == end {
                    ranges.push(start.to_string());
                } else if end - start >= 2 {
                    ranges.push(format!("{}-{}", start, end));
                } else {
                    // For ranges of 2, list individually
                    for p in start..=end {
                        ranges.push(p.to_string());
                    }
                }
                start = port;
                end = port;
            }
        }

        // Add the last range
        if start == end {
            ranges.push(start.to_string());
        } else if end - start >= 2 {
            ranges.push(format!("{}-{}", start, end));
        } else {
            // For ranges of 2, list individually
            for p in start..=end {
                ranges.push(p.to_string());
            }
        }

        return ranges.join(",");
    }

    let mut ranges = Vec::new();
    let mut start = ports[0];
    let mut end = ports[0];

    for &port in &ports[1..] {
        if port == end + 1 {
            end = port;
        } else {
            if start == end {
                ranges.push(start.to_string());
            } else {
                ranges.push(format!("{}-{}", start, end));
            }
            start = port;
            end = port;
        }
    }

    // Add the last range
    if start == end {
        ranges.push(start.to_string());
    } else {
        ranges.push(format!("{}-{}", start, end));
    }

    if ranges.len() <= 5 {
        ranges.join(",")
    } else {
        format!("{} ranges ({} ports total)", ranges.len(), ports.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_port() {
        assert_eq!(parse_single_port("80").unwrap(), 80);
        assert_eq!(parse_single_port("443").unwrap(), 443);
        assert!(parse_single_port("0").is_err());
        assert!(parse_single_port("65536").is_err());
        assert!(parse_single_port("abc").is_err());
    }

    #[test]
    fn test_parse_port_range() {
        let ports = parse_ports("80-85").unwrap();
        assert_eq!(ports, vec![80, 81, 82, 83, 84, 85]);
    }

    #[test]
    fn test_parse_mixed_ports() {
        let ports = parse_ports("22,80-82,443,8080").unwrap();
        assert_eq!(ports, vec![22, 80, 81, 82, 443, 8080]);
    }

    #[test]
    fn test_parse_invalid_range() {
        assert!(parse_ports("100-50").is_err()); // start > end
        assert!(parse_ports("80-").is_err());    // incomplete range
        assert!(parse_ports("-80").is_err());    // incomplete range
    }

    #[test]
    fn test_deduplicate_ports() {
        let ports = parse_ports("80,80,443,80").unwrap();
        assert_eq!(ports, vec![80, 443]);
    }

    #[test]
    fn test_chunk_ports() {
        let ports = vec![22, 80, 443, 8080, 9000];
        let chunks = chunk_ports(&ports, 2);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], vec![22, 80]);
        assert_eq!(chunks[1], vec![443, 8080]);
        assert_eq!(chunks[2], vec![9000]);
    }

    #[test]
    fn test_format_ports_summary() {
        assert_eq!(format_ports_summary(&[]), "none");
        assert_eq!(format_ports_summary(&[80]), "80");
        assert_eq!(format_ports_summary(&[80, 443]), "80,443");
        assert_eq!(format_ports_summary(&[80, 81, 82, 83]), "80-83");
        assert_eq!(format_ports_summary(&[22, 80, 81, 82, 443]), "22,80-82,443");
    }

    #[test]
    fn test_get_top_ports() {
        let top_10 = get_top_ports(10);
        assert_eq!(top_10.len(), 10);
        assert!(top_10.contains(&80));
        assert!(top_10.contains(&22));
        assert!(top_10.contains(&21));
        
        let top_20 = get_top_ports(20);
        assert_eq!(top_20.len(), 20);
        assert!(top_20.contains(&443));
    }
}