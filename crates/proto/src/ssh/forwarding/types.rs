//! Common types and utilities for port forwarding.

use fynx_platform::{FynxError, FynxResult};
use std::net::{IpAddr, SocketAddr};

/// Forward address specification.
///
/// Can be either a socket address (IP:port) or a host:port pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardAddr {
    /// Host or IP address
    pub host: String,
    /// Port number
    pub port: u16,
}

impl ForwardAddr {
    /// Creates a new forward address.
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }

    /// Converts to a socket address if the host is an IP address.
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            Some(SocketAddr::new(ip, self.port))
        } else {
            None
        }
    }

    /// Converts to a string in "host:port" format.
    pub fn to_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Parses a forward address from a string.
///
/// Accepts formats:
/// - "host:port" - e.g., "localhost:8080"
/// - "[host]:port" - e.g., "[::1]:8080" for IPv6
///
/// # Example
///
/// ```rust
/// use fynx_proto::ssh::forwarding::parse_forward_addr;
///
/// let addr = parse_forward_addr("localhost:8080").unwrap();
/// assert_eq!(addr.host, "localhost");
/// assert_eq!(addr.port, 8080);
///
/// let addr = parse_forward_addr("192.168.1.1:3306").unwrap();
/// assert_eq!(addr.host, "192.168.1.1");
/// assert_eq!(addr.port, 3306);
/// ```
pub fn parse_forward_addr(addr: &str) -> FynxResult<ForwardAddr> {
    // Handle IPv6 with brackets: [::1]:8080
    if addr.starts_with('[') {
        let end_bracket = addr.find(']').ok_or_else(|| {
            FynxError::Protocol(format!("Invalid IPv6 address: missing ']': {}", addr))
        })?;

        let host = addr[1..end_bracket].to_string();

        let port_part = &addr[end_bracket + 1..];
        if !port_part.starts_with(':') {
            return Err(FynxError::Protocol(format!(
                "Invalid address format: missing ':' after ']': {}",
                addr
            )));
        }

        let port = port_part[1..].parse::<u16>().map_err(|_| {
            FynxError::Protocol(format!("Invalid port number: {}", &port_part[1..]))
        })?;

        return Ok(ForwardAddr { host, port });
    }

    // Handle regular host:port format
    let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(FynxError::Protocol(format!(
            "Invalid address format: expected 'host:port', got '{}'",
            addr
        )));
    }

    let port = parts[0].parse::<u16>().map_err(|_| {
        FynxError::Protocol(format!("Invalid port number: {}", parts[0]))
    })?;

    let host = parts[1].to_string();

    Ok(ForwardAddr { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_localhost() {
        let addr = parse_forward_addr("localhost:8080").unwrap();
        assert_eq!(addr.host, "localhost");
        assert_eq!(addr.port, 8080);
    }

    #[test]
    fn test_parse_ipv4() {
        let addr = parse_forward_addr("192.168.1.1:3306").unwrap();
        assert_eq!(addr.host, "192.168.1.1");
        assert_eq!(addr.port, 3306);
    }

    #[test]
    fn test_parse_ipv6() {
        let addr = parse_forward_addr("[::1]:8080").unwrap();
        assert_eq!(addr.host, "::1");
        assert_eq!(addr.port, 8080);

        let addr = parse_forward_addr("[2001:db8::1]:22").unwrap();
        assert_eq!(addr.host, "2001:db8::1");
        assert_eq!(addr.port, 22);
    }

    #[test]
    fn test_parse_wildcard() {
        let addr = parse_forward_addr("0.0.0.0:80").unwrap();
        assert_eq!(addr.host, "0.0.0.0");
        assert_eq!(addr.port, 80);
    }

    #[test]
    fn test_parse_domain_with_dots() {
        let addr = parse_forward_addr("database.internal.company.com:3306").unwrap();
        assert_eq!(addr.host, "database.internal.company.com");
        assert_eq!(addr.port, 3306);
    }

    #[test]
    fn test_parse_invalid_missing_port() {
        let result = parse_forward_addr("localhost");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_port() {
        let result = parse_forward_addr("localhost:99999");
        assert!(result.is_err());

        let result = parse_forward_addr("localhost:abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_to_socket_addr() {
        let addr = parse_forward_addr("127.0.0.1:8080").unwrap();
        let socket = addr.to_socket_addr().unwrap();
        assert_eq!(socket.port(), 8080);

        let addr = parse_forward_addr("localhost:8080").unwrap();
        assert!(addr.to_socket_addr().is_none()); // Domain names can't convert to SocketAddr
    }

    #[test]
    fn test_to_string() {
        let addr = ForwardAddr::new("localhost".to_string(), 8080);
        assert_eq!(addr.to_string(), "localhost:8080");
    }
}
