//! SSH Connection Manager.
//!
//! Low-level connection management separate from client logic.

use crate::ssh::transport::TransportState;
use fynx_platform::{FynxError, FynxResult};
use tokio::net::TcpStream;

/// SSH Connection - manages the low-level TCP connection and transport state.
///
/// This is separated from SshClient to enable multi-channel support.
/// The connection can be shared across multiple channels through Arc<Mutex<>>.
pub struct SshConnection {
    /// TCP stream
    stream: TcpStream,
    /// Transport layer state
    transport: TransportState,
    /// Next channel ID to allocate
    next_channel_id: u32,
}

impl SshConnection {
    /// Creates a new SSH connection.
    pub fn new(stream: TcpStream, transport: TransportState) -> Self {
        Self {
            stream,
            transport,
            next_channel_id: 0,
        }
    }

    /// Allocates the next channel ID.
    pub fn allocate_channel_id(&mut self) -> u32 {
        let id = self.next_channel_id;
        self.next_channel_id += 1;
        id
    }

    /// Gets a reference to the TCP stream.
    pub fn stream(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    /// Gets a reference to the transport state.
    pub fn transport(&mut self) -> &mut TransportState {
        &mut self.transport
    }

    /// Sends a raw packet (for use by dispatcher).
    pub async fn send_packet(&mut self, payload: &[u8]) -> FynxResult<()> {
        use crate::ssh::packet::Packet;
        use tokio::io::AsyncWriteExt;

        let packet = Packet::new(payload.to_vec());
        let mut bytes = packet.to_bytes();

        // If encryption is active, encrypt the packet
        if self.transport.is_encrypted() {
            if let Some(enc_params) = self.transport.encryption_params_mut() {
                if let Some(enc_key) = &mut enc_params.encryption_key {
                    // Extract packet_length (first 4 bytes) - sent in cleartext
                    let packet_length = bytes[0..4].to_vec();

                    // Extract the rest to encrypt
                    let mut plaintext = bytes[4..].to_vec();

                    // Encrypt in place
                    enc_key.encrypt(&mut plaintext)?;

                    // Reconstruct: packet_length || ciphertext || tag
                    let mut encrypted_packet = Vec::new();
                    encrypted_packet.extend_from_slice(&packet_length);
                    encrypted_packet.extend_from_slice(&plaintext);

                    bytes = encrypted_packet;
                }
            }
        }

        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;

        Ok(())
    }

    /// Receives a raw packet (for use by dispatcher).
    pub async fn receive_packet(&mut self) -> FynxResult<Vec<u8>> {
        use crate::ssh::packet::Packet;
        use tokio::io::AsyncReadExt;

        // Read packet length (4 bytes)
        let mut length_bytes = [0u8; 4];
        self.stream.read_exact(&mut length_bytes).await?;
        let packet_length = u32::from_be_bytes(length_bytes) as usize;

        if packet_length > 35000 {
            return Err(FynxError::Protocol(format!(
                "Packet too large: {} bytes",
                packet_length
            )));
        }

        // Read the rest of the packet
        let mut packet_data = Vec::with_capacity(4 + packet_length);
        packet_data.extend_from_slice(&length_bytes);
        packet_data.resize(4 + packet_length, 0);
        self.stream.read_exact(&mut packet_data[4..]).await?;

        // Decrypt if encryption is active
        if self.transport.is_encrypted() {
            if let Some(enc_params) = self.transport.encryption_params_mut() {
                if let Some(dec_key) = &mut enc_params.decryption_key {
                    // Ciphertext starts at byte 4
                    let mut ciphertext = packet_data[4..].to_vec();

                    // Decrypt in place
                    dec_key.decrypt(&mut ciphertext)?;

                    // Reconstruct plaintext packet
                    let mut plaintext_packet = Vec::new();
                    plaintext_packet.extend_from_slice(&length_bytes);
                    plaintext_packet.extend_from_slice(&ciphertext);

                    packet_data = plaintext_packet;
                }
            }
        }

        // Parse packet
        let packet = Packet::from_bytes(&packet_data)?;

        Ok(packet.payload().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::transport::TransportConfig;

    // Note: These tests require actual network connections, so they are basic structure tests

    #[test]
    fn test_channel_id_allocation() {
        let transport = TransportState::new(TransportConfig::new(true));
        // Can't create actual TcpStream without connection, so this test is limited
        // In real usage, we'd use mock streams
    }
}
