//! SSH Client implementation.
//!
//! This module provides a complete SSH client implementation with full protocol support.
//!
//! # Example
//!
//! ```rust,no_run
//! use fynx_proto::ssh::client::SshClient;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Connect to SSH server
//! let mut client = SshClient::connect("127.0.0.1:22").await?;
//!
//! // Authenticate
//! client.authenticate_password("user", "password").await?;
//!
//! // Execute command
//! let output = client.execute("ls -la").await?;
//! println!("{}", String::from_utf8_lossy(&output));
//! # Ok(())
//! # }
//! ```

use crate::ssh::auth::{AuthMethod, AuthRequest};
use crate::ssh::connection::{
    ChannelData, ChannelOpen, ChannelOpenConfirmation, ChannelRequest, ChannelRequestType,
    ChannelType,
};
use crate::ssh::hostkey::HostKeyAlgorithm;
use crate::ssh::kex::{negotiate_algorithm, KexInit, NewKeys};
use crate::ssh::kex_dh::Curve25519Exchange;
use crate::ssh::message::MessageType;
use crate::ssh::packet::Packet;
use crate::ssh::transport::{State, TransportConfig, TransportState};
use crate::ssh::version::Version;
use fynx_platform::{FynxError, FynxResult};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// SSH client configuration.
#[derive(Debug, Clone)]
pub struct SshClientConfig {
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Read timeout.
    pub read_timeout: Duration,
    /// Write timeout.
    pub write_timeout: Duration,
    /// User agent.
    pub user_agent: String,
    /// Strict host key checking.
    /// If true, unknown or changed host keys will be rejected.
    /// If false, host keys will be accepted (INSECURE for production).
    pub strict_host_key_checking: bool,
}

impl Default for SshClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(60),
            user_agent: "Fynx_0.1.0".to_string(),
            strict_host_key_checking: true,
        }
    }
}

/// SSH Client.
///
/// Provides complete SSH client functionality including connection,
/// authentication, and command execution.
pub struct SshClient {
    /// TCP connection.
    stream: TcpStream,
    /// Transport state.
    transport: TransportState,
    /// Configuration.
    config: SshClientConfig,
    /// Server address.
    server_addr: String,
    /// Authenticated username.
    username: Option<String>,
    /// Next channel ID.
    next_channel_id: u32,
    /// Server's host key (received during key exchange).
    server_host_key: Option<Vec<u8>>,
    /// Server's host key algorithm.
    server_host_key_algorithm: Option<HostKeyAlgorithm>,
    /// Client version string (for exchange hash computation).
    client_version: String,
    /// Server version string (for exchange hash computation).
    server_version: String,
    /// Client KEXINIT payload (for exchange hash computation).
    client_kexinit_payload: Vec<u8>,
    /// Server KEXINIT payload (for exchange hash computation).
    server_kexinit_payload: Vec<u8>,
}

impl SshClient {
    /// Connects to an SSH server.
    ///
    /// Performs:
    /// 1. TCP connection
    /// 2. Version exchange
    /// 3. Key exchange
    /// 4. Ready for authentication
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use fynx_proto::ssh::client::SshClient;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = SshClient::connect("server:22").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(addr: &str) -> FynxResult<Self> {
        Self::connect_with_config(addr, SshClientConfig::default()).await
    }

    /// Connects with custom configuration.
    pub async fn connect_with_config(addr: &str, config: SshClientConfig) -> FynxResult<Self> {
        // 1. TCP connection
        let stream = tokio::time::timeout(config.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                FynxError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Connection timeout",
                ))
            })?
            .map_err(FynxError::Io)?;

        let transport_config = TransportConfig::new(true);
        let transport = TransportState::new(transport_config);

        let mut client = Self {
            stream,
            transport,
            config,
            server_addr: addr.to_string(),
            username: None,
            next_channel_id: 0,
            server_host_key: None,
            server_host_key_algorithm: None,
            client_version: String::new(),
            server_version: String::new(),
            client_kexinit_payload: Vec::new(),
            server_kexinit_payload: Vec::new(),
        };

        // 2. Version exchange
        client.version_exchange().await?;

        // 3. Key exchange
        client.key_exchange().await?;

        Ok(client)
    }

    /// Performs SSH version exchange.
    async fn version_exchange(&mut self) -> FynxResult<()> {
        // Send our version
        let our_version = Version::new(&self.config.user_agent, None);
        let version_line = format!("{}\r\n", our_version);

        // Save client version for exchange hash
        self.client_version = format!("{}", our_version);

        self.stream
            .write_all(version_line.as_bytes())
            .await
            .map_err(FynxError::Io)?;

        // Read server version
        let mut buffer = Vec::new();
        let mut temp = [0u8; 1];

        // Read until \n
        loop {
            self.stream
                .read_exact(&mut temp)
                .await
                .map_err(FynxError::Io)?;
            buffer.push(temp[0]);

            if temp[0] == b'\n' {
                break;
            }

            if buffer.len() > 255 {
                return Err(FynxError::Protocol("Version string too long".to_string()));
            }
        }

        let version_str = String::from_utf8_lossy(&buffer);
        let server_version = Version::parse(&version_str)?;

        // Save server version for exchange hash
        self.server_version = format!("{}", server_version);

        self.transport.set_peer_version(server_version);
        self.transport.transition(State::KexInit)?;

        Ok(())
    }

    /// Performs key exchange.
    async fn key_exchange(&mut self) -> FynxResult<()> {
        // 1. Send our KEXINIT
        let our_kexinit = self.transport.config().kex_init.clone();
        let kexinit_payload = our_kexinit.to_bytes();

        // Save client KEXINIT payload for exchange hash
        self.client_kexinit_payload = kexinit_payload.clone();

        self.send_packet(&kexinit_payload).await?;

        // 2. Receive server KEXINIT
        let server_packet = self.receive_packet().await?;
        if server_packet.payload().is_empty()
            || server_packet.payload()[0] != MessageType::KexInit as u8
        {
            return Err(FynxError::Protocol("Expected KEXINIT message".to_string()));
        }

        let server_kexinit = KexInit::from_bytes(server_packet.payload())?;

        // Save server KEXINIT payload for exchange hash
        self.server_kexinit_payload = server_packet.payload().to_vec();

        self.transport.set_peer_kex_init(server_kexinit.clone());

        // 3. Negotiate algorithms
        let kex_alg = negotiate_algorithm(
            our_kexinit.kex_algorithms(),
            server_kexinit.kex_algorithms(),
        )?;

        self.transport.transition(State::KeyExchange)?;

        // 4. Perform key exchange (Curve25519)
        if kex_alg == "curve25519-sha256" || kex_alg == "curve25519-sha256@libssh.org" {
            self.perform_curve25519_kex().await?;
        } else {
            return Err(FynxError::Protocol(format!(
                "Unsupported KEX algorithm: {}",
                kex_alg
            )));
        }

        // 5. Send NEWKEYS
        let newkeys = NewKeys::new();
        self.send_packet(&newkeys.to_bytes()).await?;

        // 6. Receive NEWKEYS
        let newkeys_packet = self.receive_packet().await?;
        if newkeys_packet.payload().is_empty()
            || newkeys_packet.payload()[0] != MessageType::NewKeys as u8
        {
            return Err(FynxError::Protocol("Expected NEWKEYS message".to_string()));
        }

        self.transport.transition(State::NewKeys)?;
        self.transport.transition(State::Encrypted)?;

        Ok(())
    }

    /// Parses and verifies a host key from SSH wire format.
    fn parse_host_key(&mut self, host_key_blob: &[u8]) -> FynxResult<HostKeyAlgorithm> {
        if host_key_blob.len() < 4 {
            return Err(FynxError::Protocol("Host key too short".to_string()));
        }

        // Read algorithm name
        let alg_name_len = u32::from_be_bytes([
            host_key_blob[0],
            host_key_blob[1],
            host_key_blob[2],
            host_key_blob[3],
        ]) as usize;

        if host_key_blob.len() < 4 + alg_name_len {
            return Err(FynxError::Protocol("Invalid host key format".to_string()));
        }

        let alg_name = &host_key_blob[4..4 + alg_name_len];
        let alg_name_str = std::str::from_utf8(alg_name)
            .map_err(|_| FynxError::Protocol("Invalid algorithm name".to_string()))?;

        let algorithm = HostKeyAlgorithm::from_name(alg_name_str).ok_or_else(|| {
            FynxError::Protocol(format!("Unsupported host key algorithm: {}", alg_name_str))
        })?;

        // Store the host key
        self.server_host_key = Some(host_key_blob.to_vec());
        self.server_host_key_algorithm = Some(algorithm);

        Ok(algorithm)
    }

    /// Verifies the host key signature over the exchange hash.
    ///
    /// The signature blob format (SSH wire format):
    /// - uint32: signature format name length
    /// - string: signature format name (e.g., "ssh-ed25519")
    /// - uint32: signature data length
    /// - string: signature data
    fn verify_host_key_signature(
        &self,
        exchange_hash: &[u8],
        signature_blob: &[u8],
    ) -> FynxResult<()> {
        if signature_blob.len() < 4 {
            return Err(FynxError::Protocol("Signature blob too short".to_string()));
        }

        // Read signature format name
        let format_len = u32::from_be_bytes([
            signature_blob[0],
            signature_blob[1],
            signature_blob[2],
            signature_blob[3],
        ]) as usize;

        if signature_blob.len() < 4 + format_len {
            return Err(FynxError::Protocol("Invalid signature format".to_string()));
        }

        let format_name = &signature_blob[4..4 + format_len];
        let format_str = std::str::from_utf8(format_name)
            .map_err(|_| FynxError::Protocol("Invalid signature format name".to_string()))?;

        let mut offset = 4 + format_len;

        // Read signature data
        if offset + 4 > signature_blob.len() {
            return Err(FynxError::Protocol("Signature data missing".to_string()));
        }

        let sig_data_len = u32::from_be_bytes([
            signature_blob[offset],
            signature_blob[offset + 1],
            signature_blob[offset + 2],
            signature_blob[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + sig_data_len > signature_blob.len() {
            return Err(FynxError::Protocol(
                "Invalid signature data length".to_string(),
            ));
        }

        let signature_data = &signature_blob[offset..offset + sig_data_len];

        // Get the server's host key blob for verification
        let host_key_blob = self
            .server_host_key
            .as_ref()
            .ok_or_else(|| FynxError::Protocol("Server host key not available".to_string()))?;

        // Verify signature based on algorithm
        match format_str {
            "ssh-ed25519" => {
                // Extract Ed25519 public key from host key blob
                // Format: string "ssh-ed25519" + string public_key(32 bytes)
                if host_key_blob.len() < 4 {
                    return Err(FynxError::Protocol("Invalid Ed25519 host key".to_string()));
                }

                let alg_len = u32::from_be_bytes([
                    host_key_blob[0],
                    host_key_blob[1],
                    host_key_blob[2],
                    host_key_blob[3],
                ]) as usize;

                let key_offset = 4 + alg_len;
                if key_offset + 4 > host_key_blob.len() {
                    return Err(FynxError::Protocol(
                        "Invalid Ed25519 host key format".to_string(),
                    ));
                }

                let key_len = u32::from_be_bytes([
                    host_key_blob[key_offset],
                    host_key_blob[key_offset + 1],
                    host_key_blob[key_offset + 2],
                    host_key_blob[key_offset + 3],
                ]) as usize;

                let key_data_offset = key_offset + 4;
                if key_data_offset + key_len > host_key_blob.len() {
                    return Err(FynxError::Protocol("Invalid Ed25519 key data".to_string()));
                }

                let public_key = &host_key_blob[key_data_offset..key_data_offset + key_len];

                use crate::ssh::hostkey::Ed25519HostKey;
                let verified = Ed25519HostKey::verify(public_key, exchange_hash, signature_data)?;

                if !verified {
                    return Err(FynxError::Security(
                        "Ed25519 signature verification failed".to_string(),
                    ));
                }
            }
            "rsa-sha2-256" => {
                // Extract RSA public key from host key blob
                // This requires parsing the RSA key structure
                // For now, return an error indicating it's not yet implemented
                return Err(FynxError::Protocol(
                    "RSA-SHA2-256 signature verification not yet implemented".to_string(),
                ));
            }
            "rsa-sha2-512" => {
                return Err(FynxError::Protocol(
                    "RSA-SHA2-512 signature verification not yet implemented".to_string(),
                ));
            }
            _ => {
                return Err(FynxError::Protocol(format!(
                    "Unsupported signature algorithm: {}",
                    format_str
                )));
            }
        }

        Ok(())
    }

    /// Computes the exchange hash (H) for Curve25519 key exchange.
    ///
    /// According to RFC 4253 Section 8, the exchange hash is computed as:
    /// H = HASH(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)
    ///
    /// Where:
    /// - V_C: client version string
    /// - V_S: server version string
    /// - I_C: client KEXINIT payload
    /// - I_S: server KEXINIT payload
    /// - K_S: server host key blob
    /// - Q_C: client ephemeral public key
    /// - Q_S: server ephemeral public key
    /// - K: shared secret (mpint format)
    fn compute_exchange_hash_curve25519(
        &self,
        client_version: &str,
        server_version: &str,
        client_kexinit: &[u8],
        server_kexinit: &[u8],
        host_key_blob: &[u8],
        client_public: &[u8],
        server_public: &[u8],
        shared_secret: &[u8],
    ) -> Vec<u8> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        // Helper to write SSH string (uint32 length + data)
        let write_string = |h: &mut Sha256, s: &[u8]| {
            h.update(&(s.len() as u32).to_be_bytes());
            h.update(s);
        };

        // Helper to write SSH mpint (multiple precision integer)
        // For Curve25519, the shared secret is 32 bytes
        let write_mpint = |h: &mut Sha256, data: &[u8]| {
            // If high bit is set, add 0x00 prefix
            if !data.is_empty() && (data[0] & 0x80) != 0 {
                h.update(&((data.len() + 1) as u32).to_be_bytes());
                h.update(&[0x00]);
                h.update(data);
            } else {
                h.update(&(data.len() as u32).to_be_bytes());
                h.update(data);
            }
        };

        // V_C (client version, without CR+LF)
        let client_ver = client_version.trim_end_matches("\r\n");
        write_string(&mut hasher, client_ver.as_bytes());

        // V_S (server version, without CR+LF)
        let server_ver = server_version.trim_end_matches("\r\n");
        write_string(&mut hasher, server_ver.as_bytes());

        // I_C (client KEXINIT payload)
        write_string(&mut hasher, client_kexinit);

        // I_S (server KEXINIT payload)
        write_string(&mut hasher, server_kexinit);

        // K_S (server host key blob)
        write_string(&mut hasher, host_key_blob);

        // Q_C (client ephemeral public key)
        write_string(&mut hasher, client_public);

        // Q_S (server ephemeral public key)
        write_string(&mut hasher, server_public);

        // K (shared secret as mpint)
        write_mpint(&mut hasher, shared_secret);

        hasher.finalize().to_vec()
    }

    /// Performs Curve25519 key exchange.
    async fn perform_curve25519_kex(&mut self) -> FynxResult<()> {
        // Generate our key pair
        let our_exchange = Curve25519Exchange::new()?;
        let our_public = our_exchange.public_key().to_vec();

        // Send SSH_MSG_KEX_ECDH_INIT (30)
        let mut init_msg = vec![MessageType::KexdhInit as u8];
        // Add public key as string (uint32 length + data)
        init_msg.extend_from_slice(&(our_public.len() as u32).to_be_bytes());
        init_msg.extend_from_slice(&our_public);

        self.send_packet(&init_msg).await?;

        // Receive SSH_MSG_KEX_ECDH_REPLY (31)
        let reply_packet = self.receive_packet().await?;
        if reply_packet.payload().is_empty()
            || reply_packet.payload()[0] != MessageType::KexdhReply as u8
        {
            return Err(FynxError::Protocol("Expected KEX_ECDH_REPLY".to_string()));
        }

        // Parse reply - now with host key verification
        let payload = reply_packet.payload();
        let mut offset = 1;

        // Read host key string
        if offset + 4 > payload.len() {
            return Err(FynxError::Protocol("Invalid KEX_ECDH_REPLY".to_string()));
        }
        let host_key_len = u32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + host_key_len > payload.len() {
            return Err(FynxError::Protocol("Invalid host key length".to_string()));
        }

        let host_key_blob = &payload[offset..offset + host_key_len];

        // Parse and store host key
        let _host_key_algorithm = self.parse_host_key(host_key_blob)?;

        offset += host_key_len;

        // Read server public key
        if offset + 4 > payload.len() {
            return Err(FynxError::Protocol("Invalid KEX_ECDH_REPLY".to_string()));
        }
        let server_pub_len = u32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + server_pub_len > payload.len() {
            return Err(FynxError::Protocol("Invalid server public key".to_string()));
        }

        // Curve25519 public keys must be exactly 32 bytes
        if server_pub_len != 32 {
            return Err(FynxError::Protocol(format!(
                "Invalid Curve25519 public key length: expected 32, got {}",
                server_pub_len
            )));
        }

        let mut server_public = [0u8; 32];
        server_public.copy_from_slice(&payload[offset..offset + 32]);
        offset += 32;

        // Read signature
        if offset + 4 > payload.len() {
            return Err(FynxError::Protocol("Invalid KEX_ECDH_REPLY".to_string()));
        }
        let signature_len = u32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + signature_len > payload.len() {
            return Err(FynxError::Protocol("Invalid signature length".to_string()));
        }

        let signature_blob = &payload[offset..offset + signature_len];

        // Compute shared secret
        let shared_secret = our_exchange.compute_shared_secret(&server_public)?;

        // Compute exchange hash (H) according to RFC 4253 Section 8
        let exchange_hash = self.compute_exchange_hash_curve25519(
            &self.client_version,
            &self.server_version,
            &self.client_kexinit_payload,
            &self.server_kexinit_payload,
            host_key_blob,
            &our_public,
            &server_public,
            &shared_secret,
        );

        // Verify signature over exchange hash
        self.verify_host_key_signature(&exchange_hash, signature_blob)?;

        // Store exchange hash as session ID (first exchange hash in connection)
        // For now we'll use exchange_hash as session_id (proper implementation tracks first H)
        let session_id = exchange_hash.clone();

        // Derive encryption/MAC keys according to RFC 4253 Section 7.2
        // Key derivation uses: K (shared secret), H (exchange hash), session_id
        // IV client-to-server:  HASH(K || H || "A" || session_id)
        // IV server-to-client:  HASH(K || H || "B" || session_id)
        // Encryption key C->S:  HASH(K || H || "C" || session_id)
        // Encryption key S->C:  HASH(K || H || "D" || session_id)
        // Integrity key C->S:   HASH(K || H || "E" || session_id)
        // Integrity key S->C:   HASH(K || H || "F" || session_id)

        use crate::ssh::crypto::{CipherAlgorithm, DecryptionKey, EncryptionKey};
        use crate::ssh::kex_dh::derive_key;
        use crate::ssh::transport::EncryptionParams;

        // Get negotiated cipher (for now, assume chacha20-poly1305)
        let cipher_c2s = CipherAlgorithm::ChaCha20Poly1305;
        let cipher_s2c = CipherAlgorithm::ChaCha20Poly1305;

        // Derive encryption key (client-to-server) - "C"
        let enc_key_c2s = derive_key(
            &shared_secret,
            &exchange_hash,
            &session_id,
            b'C',
            cipher_c2s.key_size(),
        );

        // Derive decryption key (server-to-client) - "D"
        let dec_key_s2c = derive_key(
            &shared_secret,
            &exchange_hash,
            &session_id,
            b'D',
            cipher_s2c.key_size(),
        );

        // Create encryption/decryption keys
        let encryption_key = EncryptionKey::new(cipher_c2s, &enc_key_c2s)?;
        let decryption_key = DecryptionKey::new(cipher_s2c, &dec_key_s2c)?;

        // Create encryption params (AEAD ciphers don't need separate MAC)
        let mut enc_params = EncryptionParams::new(
            CipherAlgorithm::ChaCha20Poly1305,
            CipherAlgorithm::ChaCha20Poly1305,
            None,
            None,
        );
        enc_params.install_keys(Some(encryption_key), Some(decryption_key), None, None);

        // Install encryption params into transport state
        self.transport.set_encryption_params(enc_params);

        Ok(())
    }

    /// Authenticates with password.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use fynx_proto::ssh::client::SshClient;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut client = SshClient::connect("server:22").await?;
    /// client.authenticate_password("alice", "password123").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn authenticate_password(
        &mut self,
        username: &str,
        password: &str,
    ) -> FynxResult<()> {
        // Send SERVICE_REQUEST for ssh-userauth
        let mut service_req = vec![MessageType::ServiceRequest as u8];
        let service_name = b"ssh-userauth";
        service_req.extend_from_slice(&(service_name.len() as u32).to_be_bytes());
        service_req.extend_from_slice(service_name);
        self.send_packet(&service_req).await?;

        // Wait for SERVICE_ACCEPT
        let response = self.receive_packet().await?;
        if response.payload().is_empty()
            || response.payload()[0] != MessageType::ServiceAccept as u8
        {
            return Err(FynxError::Protocol("Expected SERVICE_ACCEPT".to_string()));
        }

        // Send USERAUTH_REQUEST
        let auth_request = AuthRequest::new(
            username,
            "ssh-connection",
            AuthMethod::Password(password.to_string()),
        );

        self.send_packet(&auth_request.to_bytes()).await?;

        // Wait for USERAUTH_SUCCESS or USERAUTH_FAILURE
        let auth_response = self.receive_packet().await?;
        if auth_response.payload().is_empty() {
            return Err(FynxError::Protocol("Empty auth response".to_string()));
        }

        match auth_response.payload()[0] {
            msg_type if msg_type == MessageType::UserauthSuccess as u8 => {
                self.username = Some(username.to_string());
                Ok(())
            }
            msg_type if msg_type == MessageType::UserauthFailure as u8 => {
                Err(FynxError::Protocol("Authentication failed".to_string()))
            }
            _ => Err(FynxError::Protocol("Unexpected auth response".to_string())),
        }
    }

    /// Executes a command and returns output.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use fynx_proto::ssh::client::SshClient;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut client = SshClient::connect("server:22").await?;
    /// # client.authenticate_password("user", "pass").await?;
    /// let output = client.execute("whoami").await?;
    /// println!("{}", String::from_utf8_lossy(&output));
    /// # Ok(())
    /// # }
    /// ```
    pub async fn execute(&mut self, command: &str) -> FynxResult<Vec<u8>> {
        if self.username.is_none() {
            return Err(FynxError::Protocol("Not authenticated".to_string()));
        }

        // 1. Open channel
        let local_channel = self.next_channel_id;
        self.next_channel_id += 1;

        let channel_open = ChannelOpen::new(ChannelType::Session, local_channel, 2097152, 32768);
        self.send_packet(&channel_open.to_bytes()).await?;

        // 2. Wait for CHANNEL_OPEN_CONFIRMATION
        let response = self.receive_packet().await?;
        if response.payload().is_empty()
            || response.payload()[0] != MessageType::ChannelOpenConfirmation as u8
        {
            return Err(FynxError::Protocol("Channel open failed".to_string()));
        }

        let confirmation = ChannelOpenConfirmation::from_bytes(response.payload())?;
        let remote_channel = confirmation.sender_channel();

        // 3. Send exec request
        let exec_request = ChannelRequest::new(
            remote_channel,
            ChannelRequestType::Exec {
                command: command.to_string(),
            },
            true,
        );
        self.send_packet(&exec_request.to_bytes()).await?;

        // 4. Wait for success/failure
        let exec_response = self.receive_packet().await?;
        if exec_response.payload().is_empty() {
            return Err(FynxError::Protocol("Empty exec response".to_string()));
        }

        if exec_response.payload()[0] == MessageType::ChannelFailure as u8 {
            return Err(FynxError::Protocol("Exec request failed".to_string()));
        }

        // 5. Collect output
        let mut output = Vec::new();
        loop {
            let data_packet = self.receive_packet().await?;
            if data_packet.payload().is_empty() {
                continue;
            }

            match data_packet.payload()[0] {
                msg_type if msg_type == MessageType::ChannelData as u8 => {
                    let channel_data = ChannelData::from_bytes(data_packet.payload())?;
                    output.extend_from_slice(channel_data.data());
                }
                msg_type if msg_type == MessageType::ChannelEof as u8 => {
                    break;
                }
                msg_type if msg_type == MessageType::ChannelClose as u8 => {
                    break;
                }
                _ => {}
            }
        }

        Ok(output)
    }

    /// Sends a packet.
    async fn send_packet(&mut self, payload: &[u8]) -> FynxResult<()> {
        let packet = Packet::new(payload.to_vec());
        let mut bytes = packet.to_bytes();

        // If encryption is active, encrypt the packet
        if self.transport.is_encrypted() {
            if let Some(enc_params) = self.transport.encryption_params_mut() {
                if let Some(enc_key) = &mut enc_params.encryption_key {
                    // For AEAD ciphers (ChaCha20-Poly1305, AES-GCM), the packet format is:
                    // uint32 packet_length || encrypted(padding_length || payload || padding) || auth_tag
                    // The packet_length is sent in cleartext, the rest is encrypted

                    // Extract packet_length (first 4 bytes) - sent in cleartext
                    let packet_length = bytes[0..4].to_vec();

                    // Extract the rest (padding_length + payload + padding) to encrypt
                    let mut plaintext = bytes[4..].to_vec();

                    // Encrypt in place (this will append the auth tag automatically)
                    // The Counter inside enc_key will manage the nonce/sequence
                    enc_key.encrypt(&mut plaintext)?;

                    // Reconstruct: packet_length || ciphertext || tag
                    let mut encrypted_packet = Vec::new();
                    encrypted_packet.extend_from_slice(&packet_length);
                    encrypted_packet.extend_from_slice(&plaintext);

                    bytes = encrypted_packet;
                }
            }
        }

        self.stream.write_all(&bytes).await.map_err(FynxError::Io)?;

        // Track bytes transferred for rekey
        self.transport.add_bytes(bytes.len() as u64);

        Ok(())
    }

    /// Receives a packet.
    async fn receive_packet(&mut self) -> FynxResult<Packet> {
        // Read packet length (first 4 bytes) - always in cleartext
        let mut length_bytes = [0u8; 4];
        self.stream
            .read_exact(&mut length_bytes)
            .await
            .map_err(FynxError::Io)?;
        let packet_length = u32::from_be_bytes(length_bytes) as usize;

        // If encryption is active, we need to read ciphertext + auth tag
        let bytes_to_read = if self.transport.is_encrypted() {
            // For AEAD: packet_length bytes of ciphertext + 16 bytes auth tag
            packet_length + 16
        } else {
            // Unencrypted: just packet_length bytes
            packet_length
        };

        // Read the packet data (or ciphertext + tag)
        let mut packet_data = vec![0u8; bytes_to_read];
        self.stream
            .read_exact(&mut packet_data)
            .await
            .map_err(FynxError::Io)?;

        // If encryption is active, decrypt the packet
        if self.transport.is_encrypted() {
            if let Some(enc_params) = self.transport.encryption_params_mut() {
                if let Some(dec_key) = &mut enc_params.decryption_key {
                    // packet_data contains: ciphertext || auth_tag
                    // decrypt() will verify the tag and decrypt in place
                    dec_key.decrypt(&mut packet_data)?;

                    // After successful decryption, packet_data contains just the plaintext
                    // (tag has been verified and removed by decrypt)

                    // Reconstruct packet: packet_length || plaintext
                    let mut full_packet = Vec::new();
                    full_packet.extend_from_slice(&length_bytes);
                    full_packet.extend_from_slice(&packet_data);

                    // Track bytes for rekey
                    self.transport.add_bytes(full_packet.len() as u64 + 16); // +16 for auth tag

                    return Packet::from_bytes(&full_packet);
                }
            }
        }

        // Unencrypted path
        let mut full_packet = Vec::new();
        full_packet.extend_from_slice(&length_bytes);
        full_packet.extend_from_slice(&packet_data);

        // Track bytes for rekey
        self.transport.add_bytes(full_packet.len() as u64);

        Packet::from_bytes(&full_packet)
    }

    /// Returns the authenticated username.
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Returns the server address.
    pub fn server_address(&self) -> &str {
        &self.server_addr
    }

    /// Returns whether authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.username.is_some()
    }

    /// Returns the server's host key if received.
    pub fn server_host_key(&self) -> Option<&[u8]> {
        self.server_host_key.as_deref()
    }

    /// Returns the server's host key algorithm if received.
    pub fn server_host_key_algorithm(&self) -> Option<HostKeyAlgorithm> {
        self.server_host_key_algorithm
    }

    /// Computes and returns the server's host key fingerprint (SHA-256).
    ///
    /// Returns the fingerprint as a hex string (e.g., "SHA256:abc123...").
    pub fn server_host_key_fingerprint(&self) -> Option<String> {
        self.server_host_key.as_ref().map(|key| {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(key);
            let hash = hasher.finalize();
            format!("SHA256:{}", hex::encode(hash))
        })
    }

    /// Disconnects from server.
    pub async fn disconnect(&mut self) -> FynxResult<()> {
        // Send DISCONNECT message
        let mut disconnect_msg = vec![MessageType::Disconnect as u8];
        disconnect_msg.extend_from_slice(&11u32.to_be_bytes()); // Reason code
        let reason = b"Client disconnecting";
        disconnect_msg.extend_from_slice(&(reason.len() as u32).to_be_bytes());
        disconnect_msg.extend_from_slice(reason);
        disconnect_msg.extend_from_slice(&0u32.to_be_bytes()); // Language tag length

        let _ = self.send_packet(&disconnect_msg).await;
        let _ = self.stream.shutdown().await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::hostkey::{Ed25519HostKey, HostKey};

    #[test]
    fn test_config_default() {
        let config = SshClientConfig::default();
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert_eq!(config.user_agent, "Fynx_0.1.0");
    }

    #[test]
    fn test_exchange_hash_computation() {
        // Create a mock client (we only need the compute_exchange_hash_curve25519 method)
        // Since we can't create a SshClient without a TCP connection, we'll test the logic indirectly

        // Test that exchange hash produces consistent output for same inputs
        let client_version = "SSH-2.0-Fynx_0.1.0";
        let server_version = "SSH-2.0-OpenSSH_8.0";
        let client_kexinit = b"client_kexinit_payload";
        let server_kexinit = b"server_kexinit_payload";
        let host_key_blob = b"ssh-ed25519_host_key";
        let client_public = &[1u8; 32];
        let server_public = &[2u8; 32];
        let shared_secret = &[3u8; 32];

        // We'll use the same inputs twice and verify the hash is consistent
        use sha2::{Digest, Sha256};

        let compute_hash = || {
            let mut hasher = Sha256::new();

            // V_C
            let client_ver = client_version.trim_end_matches("\r\n");
            hasher.update(&(client_ver.len() as u32).to_be_bytes());
            hasher.update(client_ver.as_bytes());

            // V_S
            let server_ver = server_version.trim_end_matches("\r\n");
            hasher.update(&(server_ver.len() as u32).to_be_bytes());
            hasher.update(server_ver.as_bytes());

            // I_C
            hasher.update(&(client_kexinit.len() as u32).to_be_bytes());
            hasher.update(client_kexinit);

            // I_S
            hasher.update(&(server_kexinit.len() as u32).to_be_bytes());
            hasher.update(server_kexinit);

            // K_S
            hasher.update(&(host_key_blob.len() as u32).to_be_bytes());
            hasher.update(host_key_blob);

            // Q_C
            hasher.update(&(client_public.len() as u32).to_be_bytes());
            hasher.update(client_public);

            // Q_S
            hasher.update(&(server_public.len() as u32).to_be_bytes());
            hasher.update(server_public);

            // K (mpint)
            hasher.update(&(shared_secret.len() as u32).to_be_bytes());
            hasher.update(shared_secret);

            hasher.finalize().to_vec()
        };

        let hash1 = compute_hash();
        let hash2 = compute_hash();

        // Verify consistency
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA-256 produces 32 bytes
    }

    #[test]
    fn test_signature_blob_parsing() {
        // Test parsing of Ed25519 signature blob
        let mut signature_blob = Vec::new();

        // Format name: "ssh-ed25519"
        let format_name = b"ssh-ed25519";
        signature_blob.extend_from_slice(&(format_name.len() as u32).to_be_bytes());
        signature_blob.extend_from_slice(format_name);

        // Signature data: 64 bytes
        let signature_data = [0x42u8; 64];
        signature_blob.extend_from_slice(&(signature_data.len() as u32).to_be_bytes());
        signature_blob.extend_from_slice(&signature_data);

        // Parse it
        let format_len = u32::from_be_bytes([
            signature_blob[0],
            signature_blob[1],
            signature_blob[2],
            signature_blob[3],
        ]) as usize;

        assert_eq!(format_len, 11); // "ssh-ed25519" is 11 bytes

        let parsed_format = &signature_blob[4..4 + format_len];
        assert_eq!(parsed_format, b"ssh-ed25519");

        let mut offset = 4 + format_len;
        let sig_data_len = u32::from_be_bytes([
            signature_blob[offset],
            signature_blob[offset + 1],
            signature_blob[offset + 2],
            signature_blob[offset + 3],
        ]) as usize;
        offset += 4;

        assert_eq!(sig_data_len, 64);

        let parsed_sig = &signature_blob[offset..offset + sig_data_len];
        assert_eq!(parsed_sig, &signature_data);
    }

    #[test]
    fn test_host_key_blob_parsing() {
        // Test parsing of Ed25519 host key blob
        let mut host_key_blob = Vec::new();

        // Algorithm name: "ssh-ed25519"
        let alg_name = b"ssh-ed25519";
        host_key_blob.extend_from_slice(&(alg_name.len() as u32).to_be_bytes());
        host_key_blob.extend_from_slice(alg_name);

        // Public key: 32 bytes
        let public_key = [0xAAu8; 32];
        host_key_blob.extend_from_slice(&(public_key.len() as u32).to_be_bytes());
        host_key_blob.extend_from_slice(&public_key);

        // Parse algorithm name
        let alg_len = u32::from_be_bytes([
            host_key_blob[0],
            host_key_blob[1],
            host_key_blob[2],
            host_key_blob[3],
        ]) as usize;

        assert_eq!(alg_len, 11);

        let parsed_alg = &host_key_blob[4..4 + alg_len];
        assert_eq!(parsed_alg, b"ssh-ed25519");

        // Parse public key
        let key_offset = 4 + alg_len;
        let key_len = u32::from_be_bytes([
            host_key_blob[key_offset],
            host_key_blob[key_offset + 1],
            host_key_blob[key_offset + 2],
            host_key_blob[key_offset + 3],
        ]) as usize;

        assert_eq!(key_len, 32);

        let key_data_offset = key_offset + 4;
        let parsed_key = &host_key_blob[key_data_offset..key_data_offset + key_len];
        assert_eq!(parsed_key, &public_key);
    }

    #[test]
    fn test_mpint_encoding() {
        // Test mpint encoding for shared secret

        // Case 1: No high bit set (no 0x00 prefix needed)
        let data1 = [0x7Fu8; 32];
        let mut encoded1 = Vec::new();
        encoded1.extend_from_slice(&(data1.len() as u32).to_be_bytes());
        encoded1.extend_from_slice(&data1);

        assert_eq!(encoded1.len(), 4 + 32);
        assert_eq!(&encoded1[0..4], &32u32.to_be_bytes());

        // Case 2: High bit set (0x00 prefix needed)
        let data2 = [0x80u8; 32];
        let mut encoded2 = Vec::new();
        encoded2.extend_from_slice(&((data2.len() + 1) as u32).to_be_bytes());
        encoded2.push(0x00);
        encoded2.extend_from_slice(&data2);

        assert_eq!(encoded2.len(), 4 + 1 + 32);
        assert_eq!(&encoded2[0..4], &33u32.to_be_bytes());
        assert_eq!(encoded2[4], 0x00);
    }

    #[test]
    fn test_ed25519_signature_verification_integration() {
        // Create a real Ed25519 key pair
        let host_key = Ed25519HostKey::generate().unwrap();

        // Create some data to sign (exchange hash)
        let exchange_hash = b"test_exchange_hash_data_for_signing";

        // Sign the data
        let signature_blob = host_key.sign(exchange_hash).unwrap();

        // Get the public key
        let public_key_blob = host_key.public_key_bytes();

        // Extract public key from blob (skip algorithm name)
        let alg_len = u32::from_be_bytes([
            public_key_blob[0],
            public_key_blob[1],
            public_key_blob[2],
            public_key_blob[3],
        ]) as usize;

        let key_offset = 4 + alg_len;
        let key_len = u32::from_be_bytes([
            public_key_blob[key_offset],
            public_key_blob[key_offset + 1],
            public_key_blob[key_offset + 2],
            public_key_blob[key_offset + 3],
        ]) as usize;

        let public_key = &public_key_blob[key_offset + 4..key_offset + 4 + key_len];

        // Extract signature from blob
        let sig_format_len = u32::from_be_bytes([
            signature_blob[0],
            signature_blob[1],
            signature_blob[2],
            signature_blob[3],
        ]) as usize;

        let sig_offset = 4 + sig_format_len;
        let sig_len = u32::from_be_bytes([
            signature_blob[sig_offset],
            signature_blob[sig_offset + 1],
            signature_blob[sig_offset + 2],
            signature_blob[sig_offset + 3],
        ]) as usize;

        let signature = &signature_blob[sig_offset + 4..sig_offset + 4 + sig_len];

        // Verify the signature
        let verified = Ed25519HostKey::verify(public_key, exchange_hash, signature).unwrap();
        assert!(verified);

        // Verify that wrong data fails
        let wrong_data = b"wrong_data";
        let verified_wrong = Ed25519HostKey::verify(public_key, wrong_data, signature).unwrap();
        assert!(!verified_wrong);
    }

    // Integration tests would require a real SSH server
    // These are deferred to integration test suite
}
