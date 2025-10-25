//! NAT Traversal (NAT-T) Implementation
//!
//! Implements NAT detection and UDP encapsulation as defined in RFC 3948.
//!
//! # Overview
//!
//! NAT (Network Address Translation) breaks IPSec because:
//! - NAT modifies IP headers, breaking ESP integrity checks
//! - NAT devices often drop ESP packets (IP protocol 50)
//! - Stateful firewalls may block ESP traffic
//!
//! NAT-T solves these problems by:
//! 1. **NAT Detection**: Detect NAT presence during IKE_SA_INIT
//! 2. **UDP Encapsulation**: Encapsulate ESP packets in UDP
//! 3. **Port Floating**: Switch from port 500 to port 4500
//!
//! # NAT Detection Algorithm
//!
//! During IKE_SA_INIT, both peers exchange NAT_DETECTION_SOURCE_IP and
//! NAT_DETECTION_DESTINATION_IP payloads containing:
//!
//! ```text
//! HASH = SHA-1(SPIi | SPIr | IP | Port)
//!
//! Each peer sends:
//! - NAT_DETECTION_SOURCE_IP: SHA-1(SPIi | SPIr | Local_IP | Local_Port)
//! - NAT_DETECTION_DESTINATION_IP: SHA-1(SPIi | SPIr | Remote_IP | Remote_Port)
//!
//! NAT Detection:
//! - Compare received source hash with locally computed hash
//! - Compare received destination hash with locally computed hash
//! - If mismatch: NAT detected
//! ```
//!
//! # UDP Encapsulation Format
//!
//! ## IKE Messages (port 4500)
//! ```text
//! +-------------------+
//! | UDP Header        |
//! +-------------------+
//! | Non-ESP Marker    | (4 bytes of zeros: 0x00000000)
//! +-------------------+
//! | IKE Message       |
//! +-------------------+
//! ```
//!
//! ## ESP Packets (port 4500)
//! ```text
//! +-------------------+
//! | UDP Header        |
//! +-------------------+
//! | ESP Packet        | (No marker - starts with SPI)
//! +-------------------+
//! ```
//!
//! # Port Floating
//!
//! ```text
//! Before NAT Detection:
//! - IKE messages: UDP port 500
//! - ESP packets: IP protocol 50 (no UDP)
//!
//! After NAT Detection (if NAT present):
//! - IKE messages: UDP port 4500 (with Non-ESP marker)
//! - ESP packets: UDP port 4500 (no marker)
//! ```
//!
//! # References
//!
//! - [RFC 3948](https://datatracker.ietf.org/doc/html/rfc3948) - UDP Encapsulation
//! - [RFC 7296 Section 2.23](https://datatracker.ietf.org/doc/html/rfc7296#section-2.23) - NAT Detection

use crate::ipsec::{Error, Result};
use sha1::{Digest, Sha1};
use std::net::IpAddr;

/// Default IKE port (UDP 500)
pub const IKE_PORT: u16 = 500;

/// NAT-T port (UDP 4500)
pub const NAT_T_PORT: u16 = 4500;

/// Non-ESP marker (4 bytes of zeros)
///
/// Prepended to IKE messages when using port 4500 to distinguish
/// them from ESP packets (which start with a non-zero SPI).
pub const NON_ESP_MARKER: [u8; 4] = [0, 0, 0, 0];

/// NAT Detection Hash
///
/// Contains SHA-1 hash used for detecting NAT presence.
/// Hash is computed as: SHA-1(SPIi | SPIr | IP | Port)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatDetectionHash {
    /// 20-byte SHA-1 hash
    pub hash: [u8; 20],
}

impl NatDetectionHash {
    /// Compute NAT detection hash
    ///
    /// # Arguments
    ///
    /// * `spi_i` - Initiator's SPI (8 bytes)
    /// * `spi_r` - Responder's SPI (8 bytes)
    /// * `ip` - IP address (IPv4 or IPv6)
    /// * `port` - UDP port (2 bytes)
    ///
    /// # Algorithm
    ///
    /// ```text
    /// HASH = SHA-1(SPIi | SPIr | IP | Port)
    ///
    /// Where:
    /// - SPIi: 8 bytes (big-endian)
    /// - SPIr: 8 bytes (big-endian)
    /// - IP: 4 bytes (IPv4) or 16 bytes (IPv6)
    /// - Port: 2 bytes (big-endian)
    /// ```
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use fynx_proto::ipsec::nat::NatDetectionHash;
    /// use std::net::IpAddr;
    ///
    /// let hash = NatDetectionHash::compute(
    ///     0x1234567890abcdef,  // SPIi
    ///     0xfedcba0987654321,  // SPIr
    ///     "192.168.1.100".parse().unwrap(),
    ///     500,
    /// );
    /// ```
    pub fn compute(spi_i: u64, spi_r: u64, ip: IpAddr, port: u16) -> Self {
        let mut hasher = Sha1::new();

        // Add SPIi (8 bytes, big-endian)
        hasher.update(spi_i.to_be_bytes());

        // Add SPIr (8 bytes, big-endian)
        hasher.update(spi_r.to_be_bytes());

        // Add IP address
        match ip {
            IpAddr::V4(ipv4) => {
                hasher.update(ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                hasher.update(ipv6.octets());
            }
        }

        // Add port (2 bytes, big-endian)
        hasher.update(port.to_be_bytes());

        // Compute SHA-1 hash
        let result = hasher.finalize();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&result);

        NatDetectionHash { hash }
    }

    /// Create from raw hash bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 20 {
            return Err(Error::InvalidLength {
                expected: 20,
                actual: bytes.len(),
            });
        }

        let mut hash = [0u8; 20];
        hash.copy_from_slice(bytes);
        Ok(NatDetectionHash { hash })
    }

    /// Get hash as slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.hash
    }
}

/// NAT Detection Result
///
/// Indicates whether NAT is present based on hash comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatStatus {
    /// No NAT detected
    NoNat,

    /// NAT detected on local side (source IP/port changed)
    LocalNat,

    /// NAT detected on remote side (destination IP/port changed)
    RemoteNat,

    /// NAT detected on both sides
    BothNat,
}

impl NatStatus {
    /// Check if any NAT is present
    pub fn is_nat_present(&self) -> bool {
        !matches!(self, NatStatus::NoNat)
    }

    /// Check if local NAT is present
    pub fn has_local_nat(&self) -> bool {
        matches!(self, NatStatus::LocalNat | NatStatus::BothNat)
    }

    /// Check if remote NAT is present
    pub fn has_remote_nat(&self) -> bool {
        matches!(self, NatStatus::RemoteNat | NatStatus::BothNat)
    }
}

/// NAT Detection
///
/// Detects NAT presence by comparing hash values exchanged during IKE_SA_INIT.
#[derive(Debug, Clone)]
pub struct NatDetection {
    /// Local source hash (what we sent)
    local_source: NatDetectionHash,

    /// Local destination hash (what we sent)
    local_dest: NatDetectionHash,

    /// Remote source hash (what we received)
    remote_source: Option<NatDetectionHash>,

    /// Remote destination hash (what we received)
    remote_dest: Option<NatDetectionHash>,
}

impl NatDetection {
    /// Create new NAT detection with local hashes
    ///
    /// # Arguments
    ///
    /// * `spi_i` - Initiator's SPI
    /// * `spi_r` - Responder's SPI
    /// * `local_ip` - Our IP address
    /// * `local_port` - Our UDP port
    /// * `remote_ip` - Peer's IP address
    /// * `remote_port` - Peer's UDP port
    pub fn new(
        spi_i: u64,
        spi_r: u64,
        local_ip: IpAddr,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
    ) -> Self {
        let local_source = NatDetectionHash::compute(spi_i, spi_r, local_ip, local_port);
        let local_dest = NatDetectionHash::compute(spi_i, spi_r, remote_ip, remote_port);

        NatDetection {
            local_source,
            local_dest,
            remote_source: None,
            remote_dest: None,
        }
    }

    /// Set remote source hash (received from peer)
    pub fn set_remote_source(&mut self, hash: NatDetectionHash) {
        self.remote_source = Some(hash);
    }

    /// Set remote destination hash (received from peer)
    pub fn set_remote_dest(&mut self, hash: NatDetectionHash) {
        self.remote_dest = Some(hash);
    }

    /// Get local source hash
    pub fn local_source(&self) -> &NatDetectionHash {
        &self.local_source
    }

    /// Get local destination hash
    pub fn local_dest(&self) -> &NatDetectionHash {
        &self.local_dest
    }

    /// Detect NAT presence
    ///
    /// Compares local and remote hashes to determine if NAT is present.
    ///
    /// # Algorithm
    ///
    /// ```text
    /// Local NAT Detection:
    /// - Remote received our source hash
    /// - Compare remote's destination hash with our source hash
    /// - If different: Local NAT present (our IP/port was changed)
    ///
    /// Remote NAT Detection:
    /// - We received remote's source hash
    /// - Compare with our destination hash (their expected IP/port)
    /// - If different: Remote NAT present (their IP/port was changed)
    /// ```
    ///
    /// # Returns
    ///
    /// Returns `NatStatus` indicating NAT presence, or `None` if
    /// remote hashes haven't been received yet.
    pub fn detect_nat(&self) -> Option<NatStatus> {
        let remote_source = self.remote_source.as_ref()?;
        let remote_dest = self.remote_dest.as_ref()?;

        // Check if local NAT is present
        // Remote's destination hash should match our source hash
        let local_nat = remote_dest.hash != self.local_source.hash;

        // Check if remote NAT is present
        // Remote's source hash should match our destination hash
        let remote_nat = remote_source.hash != self.local_dest.hash;

        let status = match (local_nat, remote_nat) {
            (false, false) => NatStatus::NoNat,
            (true, false) => NatStatus::LocalNat,
            (false, true) => NatStatus::RemoteNat,
            (true, true) => NatStatus::BothNat,
        };

        Some(status)
    }
}

/// Packet Type (IKE or ESP)
///
/// Distinguishes between IKE messages and ESP packets when both
/// are encapsulated in UDP on port 4500.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// IKE message (starts with Non-ESP marker)
    Ike,

    /// ESP packet (starts with non-zero SPI)
    Esp,
}

/// UDP Encapsulation
///
/// Handles UDP encapsulation of IKE messages and ESP packets for NAT-T.
pub struct UdpEncapsulation;

impl UdpEncapsulation {
    /// Encapsulate IKE message in UDP
    ///
    /// Adds Non-ESP marker before the IKE message.
    ///
    /// # Format
    ///
    /// ```text
    /// +-------------------+
    /// | Non-ESP Marker    | (4 bytes: 0x00000000)
    /// +-------------------+
    /// | IKE Message       |
    /// +-------------------+
    /// ```
    ///
    /// # Arguments
    ///
    /// * `msg` - IKE message bytes
    ///
    /// # Returns
    ///
    /// UDP payload with Non-ESP marker + IKE message
    pub fn encapsulate_ike(msg: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(4 + msg.len());
        result.extend_from_slice(&NON_ESP_MARKER);
        result.extend_from_slice(msg);
        result
    }

    /// Encapsulate ESP packet in UDP
    ///
    /// No marker is added - ESP packet is used directly as UDP payload.
    ///
    /// # Format
    ///
    /// ```text
    /// +-------------------+
    /// | ESP Packet        | (starts with SPI)
    /// +-------------------+
    /// ```
    ///
    /// # Arguments
    ///
    /// * `packet` - ESP packet bytes
    ///
    /// # Returns
    ///
    /// UDP payload (same as ESP packet)
    pub fn encapsulate_esp(packet: &[u8]) -> Vec<u8> {
        packet.to_vec()
    }

    /// Decapsulate UDP payload
    ///
    /// Removes Non-ESP marker if present (IKE message).
    /// Returns ESP packet as-is.
    ///
    /// # Arguments
    ///
    /// * `data` - UDP payload
    ///
    /// # Returns
    ///
    /// Tuple of (packet_type, payload_without_marker)
    pub fn decapsulate(data: &[u8]) -> Result<(PacketType, &[u8])> {
        if data.len() < 4 {
            return Err(Error::InvalidLength {
                expected: 4,
                actual: data.len(),
            });
        }

        // Check for Non-ESP marker
        if data[0..4] == NON_ESP_MARKER {
            // IKE message - remove marker
            Ok((PacketType::Ike, &data[4..]))
        } else {
            // ESP packet - no marker
            Ok((PacketType::Esp, data))
        }
    }

    /// Detect packet type without decapsulation
    ///
    /// # Arguments
    ///
    /// * `data` - UDP payload
    ///
    /// # Returns
    ///
    /// Packet type (IKE or ESP)
    pub fn detect_packet_type(data: &[u8]) -> Result<PacketType> {
        if data.len() < 4 {
            return Err(Error::InvalidLength {
                expected: 4,
                actual: data.len(),
            });
        }

        if data[0..4] == NON_ESP_MARKER {
            Ok(PacketType::Ike)
        } else {
            Ok(PacketType::Esp)
        }
    }
}

/// Port Floating
///
/// Manages transition from port 500 to port 4500 when NAT is detected.
#[derive(Debug, Clone)]
pub struct PortFloating {
    /// Initial IKE port (500)
    initial_port: u16,

    /// NAT-T port (4500)
    nat_t_port: u16,

    /// NAT detected flag
    nat_detected: bool,

    /// Port floating performed
    floated: bool,
}

impl PortFloating {
    /// Create new port floating manager
    pub fn new() -> Self {
        PortFloating {
            initial_port: IKE_PORT,
            nat_t_port: NAT_T_PORT,
            nat_detected: false,
            floated: false,
        }
    }

    /// Mark NAT as detected
    pub fn set_nat_detected(&mut self, detected: bool) {
        self.nat_detected = detected;
    }

    /// Check if NAT was detected
    pub fn is_nat_detected(&self) -> bool {
        self.nat_detected
    }

    /// Check if port floating should occur
    ///
    /// Returns true if NAT is detected but port hasn't floated yet.
    pub fn should_float(&self) -> bool {
        self.nat_detected && !self.floated
    }

    /// Perform port floating
    ///
    /// Transitions from initial port (500) to NAT-T port (4500).
    pub fn float_port(&mut self) {
        self.floated = true;
    }

    /// Get active port
    ///
    /// Returns NAT-T port (4500) if floated, otherwise initial port (500).
    pub fn get_active_port(&self) -> u16 {
        if self.floated {
            self.nat_t_port
        } else {
            self.initial_port
        }
    }

    /// Check if port has floated
    pub fn is_floated(&self) -> bool {
        self.floated
    }

    /// Reset to initial state
    pub fn reset(&mut self) {
        self.nat_detected = false;
        self.floated = false;
    }
}

impl Default for PortFloating {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_nat_detection_hash_compute_ipv4() {
        let spi_i = 0x1234567890abcdef;
        let spi_r = 0xfedcba0987654321;
        let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 100).into();
        let port = 500;

        let hash = NatDetectionHash::compute(spi_i, spi_r, ip, port);

        // Hash should be 20 bytes
        assert_eq!(hash.hash.len(), 20);

        // Same inputs should produce same hash
        let hash2 = NatDetectionHash::compute(spi_i, spi_r, ip, port);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_nat_detection_hash_compute_ipv6() {
        let spi_i = 0x1234567890abcdef;
        let spi_r = 0xfedcba0987654321;
        let ip: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into();
        let port = 500;

        let hash = NatDetectionHash::compute(spi_i, spi_r, ip, port);

        // Hash should be 20 bytes
        assert_eq!(hash.hash.len(), 20);
    }

    #[test]
    fn test_nat_detection_hash_different_inputs() {
        let spi_i = 0x1234567890abcdef;
        let spi_r = 0xfedcba0987654321;
        let ip1: IpAddr = Ipv4Addr::new(192, 168, 1, 100).into();
        let ip2: IpAddr = Ipv4Addr::new(192, 168, 1, 101).into();
        let port = 500;

        let hash1 = NatDetectionHash::compute(spi_i, spi_r, ip1, port);
        let hash2 = NatDetectionHash::compute(spi_i, spi_r, ip2, port);

        // Different IPs should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_nat_detection_hash_from_bytes() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        ];

        let hash = NatDetectionHash::from_bytes(&bytes).unwrap();
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_nat_detection_hash_from_bytes_invalid_length() {
        let bytes = [0x01, 0x02, 0x03]; // Too short

        let result = NatDetectionHash::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_nat_detection_no_nat() {
        let spi_i = 0x1234567890abcdef;
        let spi_r = 0xfedcba0987654321;
        let local_ip: IpAddr = Ipv4Addr::new(192, 168, 1, 100).into();
        let remote_ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let local_port = 500;
        let remote_port = 500;

        let mut detection =
            NatDetection::new(spi_i, spi_r, local_ip, local_port, remote_ip, remote_port);

        // Simulate peer sending correct hashes (no NAT)
        let peer_source = NatDetectionHash::compute(spi_i, spi_r, remote_ip, remote_port);
        let peer_dest = NatDetectionHash::compute(spi_i, spi_r, local_ip, local_port);

        detection.set_remote_source(peer_source);
        detection.set_remote_dest(peer_dest);

        let status = detection.detect_nat().unwrap();
        assert_eq!(status, NatStatus::NoNat);
        assert!(!status.is_nat_present());
    }

    #[test]
    fn test_nat_detection_local_nat() {
        let spi_i = 0x1234567890abcdef;
        let spi_r = 0xfedcba0987654321;
        let local_ip: IpAddr = Ipv4Addr::new(192, 168, 1, 100).into();
        let nat_ip: IpAddr = Ipv4Addr::new(203, 0, 113, 1).into(); // Public IP after NAT
        let remote_ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let local_port = 500;
        let nat_port = 54321; // Port changed by NAT
        let remote_port = 500;

        let mut detection =
            NatDetection::new(spi_i, spi_r, local_ip, local_port, remote_ip, remote_port);

        // Peer sees our NAT'd address
        let peer_source = NatDetectionHash::compute(spi_i, spi_r, remote_ip, remote_port);
        let peer_dest = NatDetectionHash::compute(spi_i, spi_r, nat_ip, nat_port);

        detection.set_remote_source(peer_source);
        detection.set_remote_dest(peer_dest);

        let status = detection.detect_nat().unwrap();
        assert_eq!(status, NatStatus::LocalNat);
        assert!(status.is_nat_present());
        assert!(status.has_local_nat());
        assert!(!status.has_remote_nat());
    }

    #[test]
    fn test_nat_detection_remote_nat() {
        let spi_i = 0x1234567890abcdef;
        let spi_r = 0xfedcba0987654321;
        let local_ip: IpAddr = Ipv4Addr::new(192, 168, 1, 100).into();
        let remote_ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let remote_nat_ip: IpAddr = Ipv4Addr::new(203, 0, 113, 2).into();
        let local_port = 500;
        let remote_port = 500;
        let remote_nat_port = 12345;

        let mut detection =
            NatDetection::new(spi_i, spi_r, local_ip, local_port, remote_ip, remote_port);

        // We see peer's NAT'd address
        let peer_source = NatDetectionHash::compute(spi_i, spi_r, remote_nat_ip, remote_nat_port);
        let peer_dest = NatDetectionHash::compute(spi_i, spi_r, local_ip, local_port);

        detection.set_remote_source(peer_source);
        detection.set_remote_dest(peer_dest);

        let status = detection.detect_nat().unwrap();
        assert_eq!(status, NatStatus::RemoteNat);
        assert!(status.is_nat_present());
        assert!(!status.has_local_nat());
        assert!(status.has_remote_nat());
    }

    #[test]
    fn test_nat_detection_both_nat() {
        let spi_i = 0x1234567890abcdef;
        let spi_r = 0xfedcba0987654321;
        let local_ip: IpAddr = Ipv4Addr::new(192, 168, 1, 100).into();
        let local_nat_ip: IpAddr = Ipv4Addr::new(203, 0, 113, 1).into();
        let remote_ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let remote_nat_ip: IpAddr = Ipv4Addr::new(203, 0, 113, 2).into();

        let mut detection = NatDetection::new(spi_i, spi_r, local_ip, 500, remote_ip, 500);

        // Both sides see NAT'd addresses
        let peer_source = NatDetectionHash::compute(spi_i, spi_r, remote_nat_ip, 12345);
        let peer_dest = NatDetectionHash::compute(spi_i, spi_r, local_nat_ip, 54321);

        detection.set_remote_source(peer_source);
        detection.set_remote_dest(peer_dest);

        let status = detection.detect_nat().unwrap();
        assert_eq!(status, NatStatus::BothNat);
        assert!(status.is_nat_present());
        assert!(status.has_local_nat());
        assert!(status.has_remote_nat());
    }

    #[test]
    fn test_udp_encapsulation_ike() {
        let ike_msg = vec![0x01, 0x02, 0x03, 0x04];
        let encapsulated = UdpEncapsulation::encapsulate_ike(&ike_msg);

        // Should have Non-ESP marker + IKE message
        assert_eq!(encapsulated.len(), 4 + ike_msg.len());
        assert_eq!(&encapsulated[0..4], &NON_ESP_MARKER);
        assert_eq!(&encapsulated[4..], &ike_msg[..]);
    }

    #[test]
    fn test_udp_encapsulation_esp() {
        let esp_packet = vec![0x12, 0x34, 0x56, 0x78, 0xAA, 0xBB];
        let encapsulated = UdpEncapsulation::encapsulate_esp(&esp_packet);

        // Should be identical to ESP packet (no marker)
        assert_eq!(encapsulated, esp_packet);
    }

    #[test]
    fn test_udp_decapsulation_ike() {
        let ike_msg = vec![0x01, 0x02, 0x03, 0x04];
        let mut data = Vec::new();
        data.extend_from_slice(&NON_ESP_MARKER);
        data.extend_from_slice(&ike_msg);

        let (packet_type, payload) = UdpEncapsulation::decapsulate(&data).unwrap();

        assert_eq!(packet_type, PacketType::Ike);
        assert_eq!(payload, &ike_msg[..]);
    }

    #[test]
    fn test_udp_decapsulation_esp() {
        let esp_packet = vec![0x12, 0x34, 0x56, 0x78, 0xAA, 0xBB];

        let (packet_type, payload) = UdpEncapsulation::decapsulate(&esp_packet).unwrap();

        assert_eq!(packet_type, PacketType::Esp);
        assert_eq!(payload, &esp_packet[..]);
    }

    #[test]
    fn test_udp_detect_packet_type_ike() {
        let mut data = Vec::new();
        data.extend_from_slice(&NON_ESP_MARKER);
        data.extend_from_slice(&[0x01, 0x02, 0x03]);

        let packet_type = UdpEncapsulation::detect_packet_type(&data).unwrap();
        assert_eq!(packet_type, PacketType::Ike);
    }

    #[test]
    fn test_udp_detect_packet_type_esp() {
        let data = vec![0x12, 0x34, 0x56, 0x78];

        let packet_type = UdpEncapsulation::detect_packet_type(&data).unwrap();
        assert_eq!(packet_type, PacketType::Esp);
    }

    #[test]
    fn test_port_floating_initial_state() {
        let floating = PortFloating::new();

        assert!(!floating.is_nat_detected());
        assert!(!floating.is_floated());
        assert!(!floating.should_float());
        assert_eq!(floating.get_active_port(), IKE_PORT);
    }

    #[test]
    fn test_port_floating_nat_detected() {
        let mut floating = PortFloating::new();

        floating.set_nat_detected(true);

        assert!(floating.is_nat_detected());
        assert!(floating.should_float());
        assert!(!floating.is_floated());
        assert_eq!(floating.get_active_port(), IKE_PORT);
    }

    #[test]
    fn test_port_floating_after_float() {
        let mut floating = PortFloating::new();

        floating.set_nat_detected(true);
        floating.float_port();

        assert!(floating.is_nat_detected());
        assert!(floating.is_floated());
        assert!(!floating.should_float());
        assert_eq!(floating.get_active_port(), NAT_T_PORT);
    }

    #[test]
    fn test_port_floating_reset() {
        let mut floating = PortFloating::new();

        floating.set_nat_detected(true);
        floating.float_port();
        floating.reset();

        assert!(!floating.is_nat_detected());
        assert!(!floating.is_floated());
        assert_eq!(floating.get_active_port(), IKE_PORT);
    }

    #[test]
    fn test_port_floating_no_nat() {
        let mut floating = PortFloating::new();

        floating.set_nat_detected(false);

        assert!(!floating.should_float());
        assert_eq!(floating.get_active_port(), IKE_PORT);
    }
}
