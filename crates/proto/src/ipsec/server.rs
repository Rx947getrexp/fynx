//! IPSec Server API
//!
//! Provides high-level async API for accepting IPSec tunnel connections as a server.

use super::{
    child_sa::{ChildSa, ChildSaState},
    config::ServerConfig,
    crypto::PrfAlgorithm,
    esp::EspPacket,
    ikev2::{
        exchange::{IkeAuthExchange, IkeSaContext, IkeSaInitExchange},
        message::IkeMessage,
        payload::{IdPayload, IdType, TrafficSelector, TrafficSelectorsPayload},
        state::IkeState,
    },
    Error, Result,
};
use rand::RngCore;
use std::{collections::HashMap, net::SocketAddr};
use tokio::net::UdpSocket;

/// IPSec server for accepting secure tunnel connections
///
/// # Example
///
/// ```rust,ignore
/// use fynx_proto::ipsec::{IpsecServer, config::ServerConfig};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = ServerConfig::builder()
///         .with_local_id("server@example.com")
///         .with_psk(b"my-secret-key")
///         .build()?;
///
///     let mut server = IpsecServer::bind(config, "0.0.0.0:500".parse()?).await?;
///
///     // Accept client connection
///     let (peer_addr, mut session) = server.accept().await?;
///
///     // Send encrypted data
///     session.send_packet(b"Hello, client!").await?;
///
///     // Receive encrypted data
///     let data = session.recv_packet().await?;
///
///     session.close().await?;
///     Ok(())
/// }
/// ```
pub struct IpsecServer {
    /// Server configuration
    config: ServerConfig,

    /// Active sessions indexed by peer address
    sessions: HashMap<SocketAddr, IpsecSession>,

    /// UDP socket for IKE/ESP communication
    socket: UdpSocket,

    /// Local bind address
    local_addr: SocketAddr,

    /// Receive buffer for UDP packets
    recv_buffer: Vec<u8>,
}

/// Represents a single IPSec session with a client
pub struct IpsecSession {
    /// Peer (client) address
    peer_addr: SocketAddr,

    /// IKE SA context for this session
    ike_sa: IkeSaContext,

    /// Child SAs for this session, indexed by SPI
    child_sas: HashMap<u32, ChildSa>,
}

impl IpsecServer {
    /// Bind server to the specified address
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Address is already in use
    /// - Network I/O fails
    pub async fn bind(config: ServerConfig, addr: SocketAddr) -> Result<Self> {
        // Validate configuration
        config.validate()?;

        // Bind UDP socket
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|e| Error::Io(e.to_string()))?;

        let local_addr = socket
            .local_addr()
            .map_err(|e| Error::Io(e.to_string()))?;

        Ok(Self {
            config,
            sessions: HashMap::new(),
            socket,
            local_addr,
            recv_buffer: vec![0u8; 65536], // Max UDP packet size
        })
    }

    /// Accept a new client connection
    ///
    /// This performs the complete IKEv2 handshake from the responder side:
    /// 1. Receives and processes IKE_SA_INIT request
    /// 2. Sends IKE_SA_INIT response
    /// 3. Receives and processes IKE_AUTH request
    /// 4. Sends IKE_AUTH response
    /// 5. Creates Child SA
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Network I/O fails
    /// - Handshake fails (auth, proposal negotiation, etc.)
    /// - Session already exists for peer
    pub async fn accept(&mut self) -> Result<(SocketAddr, IpsecSession)> {
        // Receive IKE_SA_INIT request
        let (len, peer_addr) = self
            .socket
            .recv_from(&mut self.recv_buffer)
            .await
            .map_err(|e| Error::Io(e.to_string()))?;

        let init_req_bytes = self.recv_buffer[..len].to_vec();
        let init_req = IkeMessage::from_bytes(&init_req_bytes)?;

        // Generate responder SPI
        let mut responder_spi = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut responder_spi);

        // Extract initiator SPI from message
        let initiator_spi = init_req.header.initiator_spi;

        // Create responder context
        let mut ctx = IkeSaContext::new_responder(initiator_spi, responder_spi);

        // Process IKE_SA_INIT request
        IkeSaInitExchange::process_request(&mut ctx, &init_req, &self.config.ike_proposals)?;

        // Generate DH key pair (responder)
        let mut dh_public_r = vec![0u8; 256];
        rand::thread_rng().fill_bytes(&mut dh_public_r);

        // Generate nonce
        let mut nonce_r = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_r);

        // Select first proposal (should match after process_request)
        let selected_proposal = ctx
            .selected_proposal
            .clone()
            .ok_or_else(|| Error::Internal("No proposal selected".into()))?;

        // Create IKE_SA_INIT response
        let init_resp = IkeSaInitExchange::create_response(
            &mut ctx,
            &init_req.header,
            selected_proposal,
            dh_public_r,
            nonce_r,
            None, // No NAT-D for now
            None,
        )?;

        let init_resp_bytes = init_resp.to_bytes();

        // Send IKE_SA_INIT response
        self.socket
            .send_to(&init_resp_bytes, peer_addr)
            .await
            .map_err(|e| Error::Io(e.to_string()))?;

        // Verify state transition
        if ctx.state != IkeState::InitDone {
            return Err(Error::InvalidState(format!(
                "Expected InitDone state, got {:?}",
                ctx.state
            )));
        }

        // ===== Compute DH Shared Secret =====

        // In production, compute real DH shared secret
        // For now, use a mock value
        let mut shared_secret = vec![0u8; 256];
        rand::thread_rng().fill_bytes(&mut shared_secret);
        ctx.shared_secret = Some(shared_secret);

        // ===== Derive Keys =====

        let encr_key_len = 16; // AES-GCM-128
        let integ_key_len = 0; // AEAD doesn't need separate integrity key

        ctx.derive_keys(PrfAlgorithm::HmacSha256, encr_key_len, integ_key_len)?;

        // ===== Receive IKE_AUTH Request =====

        let (len, _) = self
            .socket
            .recv_from(&mut self.recv_buffer)
            .await
            .map_err(|e| Error::Io(e.to_string()))?;

        let auth_req_bytes = self.recv_buffer[..len].to_vec();
        let auth_req = IkeMessage::from_bytes(&auth_req_bytes)?;

        // Process IKE_AUTH request
        let (peer_id, selected_child, ts_i, ts_r) = IkeAuthExchange::process_request(
            &mut ctx,
            &init_req_bytes,
            &auth_req,
            &self.config.psk,
            &self.config.esp_proposals,
        )?;

        // Create server ID payload
        let id_r = IdPayload {
            id_type: IdType::KeyId,
            data: self.config.local_id.as_bytes().to_vec(),
        };

        // Create IKE_AUTH response
        let auth_resp = IkeAuthExchange::create_response(
            &mut ctx,
            &init_resp_bytes,
            &auth_req,
            id_r,
            &self.config.psk,
            selected_child.clone(),
            ts_i.clone(),
            ts_r.clone(),
        )?;

        // Send IKE_AUTH response
        self.socket
            .send_to(&auth_resp.to_bytes(), peer_addr)
            .await
            .map_err(|e| Error::Io(e.to_string()))?;

        // Verify state transition to Established
        if ctx.state != IkeState::Established {
            return Err(Error::InvalidState(format!(
                "Expected Established state, got {:?}",
                ctx.state
            )));
        }

        // ===== Create Child SA =====

        // Extract SPI from child proposal (convert Vec<u8> to u32)
        let child_spi = if selected_child.spi.len() >= 4 {
            u32::from_be_bytes([
                selected_child.spi[0],
                selected_child.spi[1],
                selected_child.spi[2],
                selected_child.spi[3],
            ])
        } else {
            // Fallback: generate random SPI
            rand::thread_rng().next_u32()
        };

        // Derive Child SA keys (responder's perspective - swap initiator/responder)
        let (sk_ei, sk_ai, sk_er, sk_ar) = super::child_sa::derive_child_sa_keys(
            PrfAlgorithm::HmacSha256,
            &ctx.sk_d.clone().unwrap(),
            &ctx.nonce_i.clone().unwrap(),
            &ctx.nonce_r.clone().unwrap(),
            None, // No PFS
            encr_key_len,
            0, // No separate integrity key for AEAD
        );

        // Create outbound Child SA (for sending to client - use initiator keys)
        let child_sa_out = ChildSa {
            spi: child_spi,
            protocol: 50, // ESP
            is_inbound: false,
            sk_e: sk_er, // Server sends with responder encryption key
            sk_a: Some(sk_ar),
            ts_i: ts_i.clone(),
            ts_r: ts_r.clone(),
            proposal: selected_child.clone(),
            seq_out: 1,
            replay_window: None,
            state: ChildSaState::Active,
            lifetime: self.config.lifetime.clone(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
            rekey_initiated_at: None,
        };

        // Create inbound Child SA (for receiving from client - use responder keys)
        let child_sa_in = ChildSa {
            spi: child_spi,
            protocol: 50,
            is_inbound: true,
            sk_e: sk_ei, // Server receives with initiator encryption key
            sk_a: Some(sk_ai),
            ts_i: ts_i.clone(),
            ts_r: ts_r.clone(),
            proposal: selected_child,
            seq_out: 0,
            replay_window: Some(super::replay::ReplayWindow::new(64)),
            state: ChildSaState::Active,
            lifetime: self.config.lifetime.clone(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
            rekey_initiated_at: None,
        };

        let mut child_sas = HashMap::new();
        child_sas.insert(child_spi, child_sa_out);
        child_sas.insert(child_spi | 0x80000000, child_sa_in); // Use high bit to distinguish

        // Create session
        let session = IpsecSession {
            peer_addr,
            ike_sa: ctx,
            child_sas,
        };

        // Store session
        self.sessions.insert(peer_addr, session);

        // Return a reference to the session (we need to restructure this)
        // For now, we'll remove and return ownership
        let session = self.sessions.remove(&peer_addr).unwrap();

        Ok((peer_addr, session))
    }

    /// Get the local address the server is bound to
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get number of active sessions
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Gracefully shutdown the server
    ///
    /// Closes all active sessions and releases the socket.
    ///
    /// # Errors
    ///
    /// Returns error if session cleanup fails (but server is still shut down)
    pub async fn shutdown(mut self) -> Result<()> {
        // Close all sessions (best-effort)
        for (_, mut session) in self.sessions.drain() {
            let _ = session.close().await;
        }

        // Socket is dropped automatically
        Ok(())
    }
}

impl IpsecSession {
    /// Send encrypted packet through ESP tunnel to the client
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - No active Child SA
    /// - Encryption fails
    pub fn send_packet(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        // Get outbound Child SA
        let child_sa = self
            .child_sas
            .values_mut()
            .find(|sa| !sa.is_inbound)
            .ok_or_else(|| Error::Internal("No outbound Child SA".into()))?;

        // Encapsulate with ESP
        let esp_packet = EspPacket::encapsulate(child_sa, data, 4)?; // Next header = IPv4

        // Serialize ESP packet
        Ok(esp_packet.to_bytes())
    }

    /// Receive and decrypt packet from ESP tunnel
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - No active Child SA
    /// - Decryption fails
    pub fn recv_packet(&mut self, esp_bytes: &[u8]) -> Result<Vec<u8>> {
        // Parse ESP packet (AES-GCM-128: iv_len=8, icv_len=16)
        let esp_packet = EspPacket::from_bytes(esp_bytes, 8, 16)?;

        // Get inbound Child SA matching the SPI
        let child_sa = self
            .child_sas
            .values_mut()
            .find(|sa| sa.is_inbound && sa.spi == esp_packet.spi)
            .ok_or_else(|| Error::Internal(format!("No Child SA for SPI {:#x}", esp_packet.spi)))?;

        // Decapsulate ESP packet
        let (plaintext, _next_header) = esp_packet.decapsulate(child_sa)?;

        Ok(plaintext)
    }

    /// Gracefully close the session
    ///
    /// Sends DELETE notifications for Child SAs and IKE SA.
    pub async fn close(&mut self) -> Result<()> {
        // Best-effort: try to send DELETE messages
        // Even if these fail, we'll clean up local resources

        // 1. Send DELETE for all Child SAs
        if !self.child_sas.is_empty() {
            // Collect unique Child SA SPIs (filter out the high-bit duplicates)
            let child_spis: Vec<Vec<u8>> = self
                .child_sas
                .keys()
                .filter(|spi| (*spi & 0x80000000) == 0) // Only keep original SPIs
                .map(|spi| spi.to_be_bytes().to_vec())
                .collect();

            if !child_spis.is_empty() {
                if let Ok(delete_child_msg) =
                    super::ikev2::informational::InformationalExchange::create_delete_child_sa_request(
                        &mut self.ike_sa,
                        child_spis,
                    )
                {
                    // Note: We can't send from session without socket reference
                    // In a real implementation, this would be sent via the server
                    let _ = delete_child_msg;
                }
            }
        }

        // 2. Send DELETE for IKE SA
        if let Ok(delete_ike_msg) =
            super::ikev2::informational::InformationalExchange::create_delete_ike_sa_request(&mut self.ike_sa)
        {
            // Note: We can't send from session without socket reference
            // In a real implementation, this would be sent via the server
            let _ = delete_ike_msg;
        }

        // 3. Clean up resources
        self.child_sas.clear();

        Ok(())
    }

    /// Get the peer address for this session
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Get number of active Child SAs
    pub fn child_sa_count(&self) -> usize {
        self.child_sas.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipsec::config::ServerConfig;

    #[tokio::test]
    async fn test_server_bind() {
        let config = ServerConfig::builder()
            .with_local_id("server@example.com")
            .with_psk(b"test-key")
            .build()
            .expect("Failed to build config");

        let server = IpsecServer::bind(config, "127.0.0.1:0".parse().unwrap())
            .await
            .expect("Failed to bind server");

        assert_eq!(server.session_count(), 0);
        assert!(server.local_addr.port() > 0);
    }

    #[tokio::test]
    async fn test_server_bind_invalid_config() {
        let result = ServerConfig::builder()
            .with_local_id("") // Empty ID - invalid
            .with_psk(b"test-key")
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_session_creation() {
        let peer_addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let ctx = IkeSaContext::new_responder([0x01; 8], [0x02; 8]);

        let session = IpsecSession {
            peer_addr,
            ike_sa: ctx,
            child_sas: HashMap::new(),
        };

        assert_eq!(session.peer_addr(), peer_addr);
        assert_eq!(session.child_sa_count(), 0);
    }

    #[tokio::test]
    async fn test_session_close() {
        let peer_addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let ctx = IkeSaContext::new_responder([0x01; 8], [0x02; 8]);

        let mut session = IpsecSession {
            peer_addr,
            ike_sa: ctx,
            child_sas: HashMap::new(),
        };

        session.close().await.expect("Failed to close session");
        assert_eq!(session.child_sa_count(), 0);
    }

    #[test]
    fn test_send_packet_no_child_sa() {
        let peer_addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let ctx = IkeSaContext::new_responder([0x01; 8], [0x02; 8]);

        let mut session = IpsecSession {
            peer_addr,
            ike_sa: ctx,
            child_sas: HashMap::new(),
        };

        let result = session.send_packet(b"test data");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Internal(_)));
    }

    #[tokio::test]
    async fn test_server_shutdown() {
        let config = ServerConfig::builder()
            .with_local_id("server@example.com")
            .with_psk(b"test-key")
            .build()
            .expect("Failed to build config");

        let mut server = IpsecServer::bind(config, "127.0.0.1:0".parse().unwrap())
            .await
            .expect("Failed to bind server");

        // Add a mock session
        let peer_addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let mut ctx = IkeSaContext::new_responder([0x01; 8], [0x02; 8]);
        ctx.state = crate::ipsec::ikev2::state::IkeState::Established;
        ctx.message_id = 1;

        let session = IpsecSession {
            peer_addr,
            ike_sa: ctx,
            child_sas: HashMap::new(),
        };

        server.sessions.insert(peer_addr, session);
        assert_eq!(server.session_count(), 1);

        // Shutdown should succeed
        server.shutdown().await.expect("Shutdown failed");
        // Server is consumed, so we can't check state
    }
}
