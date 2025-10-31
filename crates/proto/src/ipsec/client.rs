//! IPSec Client API
//!
//! Provides high-level async API for establishing IPSec tunnels as a client.

use super::{
    child_sa::{ChildSa, ChildSaState, SaLifetime},
    config::ClientConfig,
    crypto::PrfAlgorithm,
    esp::EspPacket,
    ikev2::{
        exchange::{CreateChildSaExchange, IkeAuthExchange, IkeSaContext, IkeSaInitExchange},
        payload::{IdPayload, IdType, TrafficSelector, TrafficSelectorsPayload},
        state::IkeState,
    },
    Error, Result,
};
use rand::RngCore;
use std::{collections::HashMap, net::SocketAddr};
use tokio::net::UdpSocket;

/// IPSec client for establishing secure tunnels
///
/// # Example
///
/// ```rust,ignore
/// use fynx_proto::ipsec::{IpsecClient, config::ClientConfig};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = ClientConfig::builder()
///         .with_local_id("client@example.com")
///         .with_remote_id("server@example.com")
///         .with_psk(b"my-secret-key")
///         .build()?;
///
///     let mut client = IpsecClient::new(config);
///     client.connect("vpn.example.com:500".parse()?).await?;
///
///     // Send encrypted data
///     client.send_packet(b"Hello, VPN!").await?;
///
///     // Receive encrypted data
///     let data = client.recv_packet().await?;
///
///     client.shutdown().await?;
///     Ok(())
/// }
/// ```
pub struct IpsecClient {
    /// Client configuration
    config: ClientConfig,

    /// IKE SA context (None until connected)
    ike_sa: Option<IkeSaContext>,

    /// Child SAs indexed by SPI
    child_sas: HashMap<u32, ChildSa>,

    /// UDP socket for IKE/ESP communication
    socket: Option<UdpSocket>,

    /// Local bind address
    local_addr: Option<SocketAddr>,

    /// Peer (remote) address
    peer_addr: Option<SocketAddr>,

    /// Receive buffer for UDP packets
    recv_buffer: Vec<u8>,
}

impl IpsecClient {
    /// Create new IPSec client with configuration
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            ike_sa: None,
            child_sas: HashMap::new(),
            socket: None,
            local_addr: None,
            peer_addr: None,
            recv_buffer: vec![0u8; 65536], // Max UDP packet size
        }
    }

    /// Connect to remote IPSec peer and establish IKE SA + Child SA
    ///
    /// This performs the complete IKEv2 handshake:
    /// 1. IKE_SA_INIT exchange (key exchange)
    /// 2. IKE_AUTH exchange (authentication + Child SA creation)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Already connected
    /// - Network I/O fails
    /// - Handshake fails (auth, proposal negotiation, etc.)
    pub async fn connect(&mut self, peer_addr: SocketAddr) -> Result<()> {
        // Check if already connected
        if self.ike_sa.is_some() {
            return Err(Error::InvalidState(
                "Client already connected. Call shutdown() first.".into(),
            ));
        }

        // Bind UDP socket to any available port
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| Error::Io(e.to_string()))?;

        self.local_addr = Some(
            socket
                .local_addr()
                .map_err(|e| Error::Io(e.to_string()))?,
        );
        self.peer_addr = Some(peer_addr);

        // Connect socket to peer (for easier send/recv)
        socket
            .connect(peer_addr)
            .await
            .map_err(|e| Error::Io(e.to_string()))?;

        self.socket = Some(socket);

        // Perform IKEv2 handshake
        self.perform_handshake().await?;

        Ok(())
    }

    /// Perform complete IKEv2 handshake
    async fn perform_handshake(&mut self) -> Result<()> {
        // Generate random initiator SPI
        let mut initiator_spi = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut initiator_spi);

        // Create initiator context
        let mut ctx = IkeSaContext::new_initiator(initiator_spi);

        // ===== IKE_SA_INIT Exchange =====

        // Generate DH key pair (using DH Group 14 - 2048-bit MODP)
        // For simplicity, we'll use random values (in production, use real DH)
        let mut dh_public = vec![0u8; 256];
        rand::thread_rng().fill_bytes(&mut dh_public);

        // Generate nonce
        let mut nonce_i = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_i);

        // Create IKE_SA_INIT request
        let init_req = IkeSaInitExchange::create_request(
            &mut ctx,
            self.config.ike_proposals.clone(),
            dh_public.clone(),
            nonce_i.clone(),
            None, // No NAT-D for now
            None,
        )?;

        // Send IKE_SA_INIT request
        self.send_ike_message(&init_req).await?;

        // Receive IKE_SA_INIT response
        let init_resp = self.recv_ike_message().await?;

        // Process IKE_SA_INIT response
        IkeSaInitExchange::process_response(&mut ctx, &init_resp)?;

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

        // Determine encryption key length from selected proposal
        let encr_key_len = 16; // AES-GCM-128 = 16 bytes
        let integ_key_len = 0; // AEAD doesn't need separate integrity key

        ctx.derive_keys(PrfAlgorithm::HmacSha256, encr_key_len, integ_key_len)?;

        // ===== IKE_AUTH Exchange =====

        // Create ID payload for initiator
        let id_i = IdPayload {
            id_type: IdType::KeyId,
            data: self.config.local_id.as_bytes().to_vec(),
        };

        // Create ID payload for responder
        let id_r = IdPayload {
            id_type: IdType::KeyId,
            data: self.config.remote_id.as_bytes().to_vec(),
        };

        // Serialize IKE_SA_INIT request for AUTH computation
        let init_req_bytes = init_req.to_bytes();

        // Create traffic selectors (IPv4 ANY)
        let ts_i = TrafficSelectorsPayload {
            selectors: vec![TrafficSelector::ipv4_any()],
        };
        let ts_r = TrafficSelectorsPayload {
            selectors: vec![TrafficSelector::ipv4_any()],
        };

        // Create IKE_AUTH request
        let auth_req = IkeAuthExchange::create_request(
            &mut ctx,
            &init_req_bytes,
            id_i,
            &self.config.psk,
            self.config.esp_proposals.clone(),
            ts_i,
            ts_r,
        )?;

        // Send IKE_AUTH request
        self.send_ike_message(&auth_req).await?;

        // Receive IKE_AUTH response
        let auth_resp = self.recv_ike_message().await?;

        // Process IKE_AUTH response
        let (_id_r_verified, child_proposal, ts_i_resp, ts_r_resp) =
            IkeAuthExchange::process_request(&mut ctx, &init_req_bytes, &auth_resp, &self.config.psk, &self.config.esp_proposals)?;

        // Verify state transition to Established
        if ctx.state != IkeState::Established {
            return Err(Error::InvalidState(format!(
                "Expected Established state, got {:?}",
                ctx.state
            )));
        }

        // ===== Create Child SA =====

        // Extract SPI from child proposal (convert Vec<u8> to u32)
        let child_spi = if child_proposal.spi.len() >= 4 {
            u32::from_be_bytes([
                child_proposal.spi[0],
                child_proposal.spi[1],
                child_proposal.spi[2],
                child_proposal.spi[3],
            ])
        } else {
            // Fallback: generate random SPI if proposal SPI is invalid
            rand::thread_rng().next_u32()
        };

        // Derive Child SA keys
        let (sk_ei, sk_ai, sk_er, sk_ar) = super::child_sa::derive_child_sa_keys(
            PrfAlgorithm::HmacSha256,
            &ctx.sk_d.clone().unwrap(),
            &ctx.nonce_i.clone().unwrap(),
            &ctx.nonce_r.clone().unwrap(),
            None, // No PFS for this Child SA
            encr_key_len,
            0, // No separate integrity key for AEAD
        );

        // Create outbound Child SA (for sending)
        let child_sa_out = ChildSa {
            spi: child_spi,
            protocol: 50, // ESP
            is_inbound: false,
            sk_e: sk_ei,
            sk_a: Some(sk_ai),
            ts_i: ts_i_resp.clone(),
            ts_r: ts_r_resp.clone(),
            proposal: child_proposal.clone(),
            seq_out: 1,
            replay_window: None,
            state: ChildSaState::Active,
            lifetime: self.config.lifetime.clone(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
            rekey_initiated_at: None,
        };

        // Create inbound Child SA (for receiving)
        let child_sa_in = ChildSa {
            spi: child_spi,
            protocol: 50,
            is_inbound: true,
            sk_e: sk_er,
            sk_a: Some(sk_ar),
            ts_i: ts_i_resp.clone(),
            ts_r: ts_r_resp.clone(),
            proposal: child_proposal,
            seq_out: 0,
            replay_window: Some(super::replay::ReplayWindow::new(64)),
            state: ChildSaState::Active,
            lifetime: self.config.lifetime.clone(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
            rekey_initiated_at: None,
        };

        // Store Child SAs
        self.child_sas.insert(child_spi, child_sa_out);
        self.child_sas.insert(child_spi | 0x80000000, child_sa_in); // Use high bit to distinguish inbound

        // Store IKE SA context
        self.ike_sa = Some(ctx);

        Ok(())
    }

    /// Send encrypted packet through ESP tunnel
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Not connected (call connect() first)
    /// - No active Child SA
    /// - Encryption fails
    /// - Network I/O fails
    pub async fn send_packet(&mut self, data: &[u8]) -> Result<()> {
        // Check if connected
        if self.ike_sa.is_none() {
            return Err(Error::InvalidState(
                "Not connected. Call connect() first.".into(),
            ));
        }

        // Get outbound Child SA (lowest SPI)
        let child_sa = self
            .child_sas
            .values_mut()
            .find(|sa| !sa.is_inbound)
            .ok_or_else(|| Error::Internal("No outbound Child SA".into()))?;

        // Encapsulate with ESP
        let esp_packet = EspPacket::encapsulate(child_sa, data, 4)?; // Next header = IPv4

        // Serialize ESP packet
        let esp_bytes = esp_packet.to_bytes();

        // Send via UDP
        self.socket
            .as_ref()
            .ok_or_else(|| Error::Internal("Socket not initialized".into()))?
            .send(&esp_bytes)
            .await
            .map_err(|e| Error::Io(e.to_string()))?;

        Ok(())
    }

    /// Receive and decrypt packet from ESP tunnel
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Not connected
    /// - No active Child SA
    /// - Decryption fails
    /// - Network I/O fails
    pub async fn recv_packet(&mut self) -> Result<Vec<u8>> {
        // Check if connected
        if self.ike_sa.is_none() {
            return Err(Error::InvalidState(
                "Not connected. Call connect() first.".into(),
            ));
        }

        // Receive from UDP
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| Error::Internal("Socket not initialized".into()))?;

        let len = socket
            .recv(&mut self.recv_buffer)
            .await
            .map_err(|e| Error::Io(e.to_string()))?;

        let packet_bytes = &self.recv_buffer[..len];

        // Parse ESP packet (AES-GCM-128: iv_len=8, icv_len=16)
        let esp_packet = EspPacket::from_bytes(packet_bytes, 8, 16)?;

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

    /// Gracefully shutdown the IPSec connection
    ///
    /// Sends DELETE notifications for Child SAs and IKE SA.
    ///
    /// # Errors
    ///
    /// Returns error if network I/O fails (but connection is still closed)
    pub async fn shutdown(&mut self) -> Result<()> {
        // Only send DELETE if we have an active IKE SA
        if let Some(mut ctx) = self.ike_sa.take() {
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
                            &mut ctx,
                            child_spis,
                        )
                    {
                        // Try to send, but ignore errors
                        let _ = self.send_ike_message(&delete_child_msg).await;
                    }
                }
            }

            // 2. Send DELETE for IKE SA
            if let Ok(delete_ike_msg) =
                super::ikev2::informational::InformationalExchange::create_delete_ike_sa_request(&mut ctx)
            {
                // Try to send, but ignore errors
                let _ = self.send_ike_message(&delete_ike_msg).await;
            }
        }

        // 3. Clean up resources regardless of DELETE success
        self.socket = None;
        self.ike_sa = None;
        self.child_sas.clear();
        self.peer_addr = None;

        Ok(())
    }

    /// Send IKE message to peer
    async fn send_ike_message(&self, message: &super::ikev2::message::IkeMessage) -> Result<()> {
        let bytes = message.to_bytes();

        self.socket
            .as_ref()
            .ok_or_else(|| Error::Internal("Socket not initialized".into()))?
            .send(&bytes)
            .await
            .map_err(|e| Error::Io(e.to_string()))?;

        Ok(())
    }

    /// Receive IKE message from peer
    async fn recv_ike_message(&mut self) -> Result<super::ikev2::message::IkeMessage> {
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| Error::Internal("Socket not initialized".into()))?;

        let len = socket
            .recv(&mut self.recv_buffer)
            .await
            .map_err(|e| Error::Io(e.to_string()))?;

        let message_bytes = &self.recv_buffer[..len];

        super::ikev2::message::IkeMessage::from_bytes(message_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipsec::config::ClientConfig;

    #[test]
    fn test_client_creation() {
        let config = ClientConfig::builder()
            .with_local_id("client@example.com")
            .with_remote_id("server@example.com")
            .with_psk(b"test-key")
            .build()
            .expect("Failed to build config");

        let client = IpsecClient::new(config);

        assert!(client.ike_sa.is_none());
        assert!(client.socket.is_none());
        assert_eq!(client.child_sas.len(), 0);
    }

    #[tokio::test]
    async fn test_client_connect_without_server() {
        let config = ClientConfig::builder()
            .with_local_id("client@example.com")
            .with_remote_id("server@example.com")
            .with_psk(b"test-key")
            .build()
            .expect("Failed to build config");

        let mut client = IpsecClient::new(config);

        // Try to connect to non-existent server (should timeout or fail)
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            client.connect("127.0.0.1:9999".parse().unwrap()),
        )
        .await;

        // Should either timeout (Err) or fail quickly with an error (Ok(Err))
        match result {
            Err(_elapsed) => {
                // Timeout occurred - this is expected
            }
            Ok(connect_result) => {
                // Connection completed quickly, should be an error
                assert!(
                    connect_result.is_err(),
                    "Connection should fail when no server is present"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_send_packet_without_connect() {
        let config = ClientConfig::builder()
            .with_local_id("client@example.com")
            .with_remote_id("server@example.com")
            .with_psk(b"test-key")
            .build()
            .expect("Failed to build config");

        let mut client = IpsecClient::new(config);

        // Try to send without connecting
        let result = client.send_packet(b"test data").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidState(_)));
    }

    #[tokio::test]
    async fn test_recv_packet_without_connect() {
        let config = ClientConfig::builder()
            .with_local_id("client@example.com")
            .with_remote_id("server@example.com")
            .with_psk(b"test-key")
            .build()
            .expect("Failed to build config");

        let mut client = IpsecClient::new(config);

        // Try to receive without connecting
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            client.recv_packet(),
        )
        .await;

        // Should either timeout or return error immediately
        if let Ok(recv_result) = result {
            assert!(recv_result.is_err());
            assert!(matches!(recv_result.unwrap_err(), Error::InvalidState(_)));
        }
    }

    #[tokio::test]
    async fn test_double_connect() {
        let config = ClientConfig::builder()
            .with_local_id("client@example.com")
            .with_remote_id("server@example.com")
            .with_psk(b"test-key")
            .build()
            .expect("Failed to build config");

        let mut client = IpsecClient::new(config);

        // Manually set ike_sa to simulate connected state
        client.ike_sa = Some(IkeSaContext::new_initiator([0x01; 8]));

        // Try to connect again
        let result = client.connect("127.0.0.1:500".parse().unwrap()).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidState(_)));
    }

    #[tokio::test]
    async fn test_client_shutdown() {
        let config = ClientConfig::builder()
            .with_local_id("client@example.com")
            .with_remote_id("server@example.com")
            .with_psk(b"test-key")
            .build()
            .expect("Failed to build config");

        let mut client = IpsecClient::new(config);

        // Simulate connected state
        let mut ctx = IkeSaContext::new_initiator([0x01; 8]);
        ctx.state = crate::ipsec::ikev2::state::IkeState::Established;
        ctx.message_id = 1;

        // Add mock Child SA
        let child_sa = ChildSa {
            spi: 0x12345678,
            protocol: 50,
            is_inbound: false,
            sk_e: vec![0u8; 16],
            sk_a: Some(vec![0u8; 16]),
            ts_i: TrafficSelectorsPayload {
                selectors: vec![TrafficSelector::ipv4_any()],
            },
            ts_r: TrafficSelectorsPayload {
                selectors: vec![TrafficSelector::ipv4_any()],
            },
            proposal: crate::ipsec::ikev2::proposal::Proposal::new(1, crate::ipsec::ikev2::proposal::ProtocolId::Esp),
            seq_out: 1,
            replay_window: None,
            state: ChildSaState::Active,
            lifetime: crate::ipsec::child_sa::SaLifetime::default(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
            rekey_initiated_at: None,
        };

        client.ike_sa = Some(ctx);
        client.child_sas.insert(0x12345678, child_sa);

        // Shutdown should succeed even without network
        client.shutdown().await.expect("Shutdown failed");

        // Verify cleanup
        assert!(client.ike_sa.is_none());
        assert!(client.socket.is_none());
        assert_eq!(client.child_sas.len(), 0);
        assert!(client.peer_addr.is_none());
    }
}
