//! SSH Channel management.
//!
//! This module provides a Channel abstraction for managing individual SSH channels
//! over a single SSH connection.

use crate::ssh::connection::ChannelData;
use fynx_platform::{FynxError, FynxResult};
use tokio::sync::mpsc;

/// SSH Channel state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// Channel is opening
    Opening,
    /// Channel is open and ready
    Open,
    /// Channel is closing
    Closing,
    /// Channel is closed
    Closed,
}

/// Channel message type (for async communication).
#[derive(Debug)]
pub enum ChannelMessage {
    /// Data received on this channel
    Data(Vec<u8>),
    /// Extended data (stderr)
    ExtendedData(Vec<u8>),
    /// Channel EOF
    Eof,
    /// Channel close
    Close,
    /// Channel success
    Success,
    /// Channel failure
    Failure,
}

/// An SSH channel for data transfer.
///
/// Represents a single logical channel over an SSH connection.
/// Channels are multiplexed over a single TCP connection.
pub struct SshChannel {
    /// Local channel ID
    local_id: u32,
    /// Remote channel ID
    remote_id: u32,
    /// Channel state
    state: ChannelState,
    /// Window size (bytes we can receive)
    window_size: u32,
    /// Maximum packet size
    max_packet_size: u32,
    /// Message receiver (for async multi-channel support)
    rx: Option<mpsc::UnboundedReceiver<ChannelMessage>>,
    /// Message sender (for async multi-channel support)
    tx: Option<mpsc::UnboundedSender<ChannelMessage>>,
}

impl SshChannel {
    /// Creates a new SSH channel (legacy, without message channels).
    pub fn new(local_id: u32, remote_id: u32, window_size: u32, max_packet_size: u32) -> Self {
        Self {
            local_id,
            remote_id,
            state: ChannelState::Open,
            window_size,
            max_packet_size,
            rx: None,
            tx: None,
        }
    }

    /// Creates a new SSH channel with message channels for async communication.
    pub fn with_channels(
        local_id: u32,
        remote_id: u32,
        window_size: u32,
        max_packet_size: u32,
    ) -> (Self, mpsc::UnboundedSender<ChannelMessage>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let channel = Self {
            local_id,
            remote_id,
            state: ChannelState::Opening,
            window_size,
            max_packet_size,
            rx: Some(rx),
            tx: Some(tx.clone()),
        };
        (channel, tx)
    }

    /// Returns the local channel ID.
    pub fn local_id(&self) -> u32 {
        self.local_id
    }

    /// Returns the remote channel ID.
    pub fn remote_id(&self) -> u32 {
        self.remote_id
    }

    /// Returns the current state.
    pub fn state(&self) -> ChannelState {
        self.state
    }

    /// Returns the window size.
    pub fn window_size(&self) -> u32 {
        self.window_size
    }

    /// Creates a CHANNEL_DATA message for this channel.
    pub fn create_data_message(&self, data: &[u8]) -> Vec<u8> {
        let channel_data = ChannelData::new(self.remote_id, data.to_vec());
        channel_data.to_bytes()
    }

    /// Adjusts the window size.
    pub fn adjust_window(&mut self, bytes: u32) {
        self.window_size = self.window_size.saturating_add(bytes);
    }

    /// Consumes window space.
    pub fn consume_window(&mut self, bytes: u32) -> FynxResult<()> {
        if bytes > self.window_size {
            return Err(FynxError::Protocol("Not enough window space".to_string()));
        }
        self.window_size -= bytes;
        Ok(())
    }

    /// Marks the channel as closed.
    pub fn close(&mut self) {
        self.state = ChannelState::Closed;
    }

    /// Reads a message from the channel (async multi-channel mode).
    ///
    /// Returns None if the channel is in legacy mode (no message channels).
    pub async fn read(&mut self) -> FynxResult<Option<ChannelMessage>> {
        if let Some(rx) = &mut self.rx {
            match rx.recv().await {
                Some(msg) => Ok(Some(msg)),
                None => Err(FynxError::Protocol("Channel closed".to_string())),
            }
        } else {
            Ok(None) // Legacy mode, no message channel
        }
    }

    /// Sends data to the channel (returns the message bytes to be sent).
    ///
    /// In new architecture, this would be sent through a dispatcher.
    pub fn write_data(&self, data: &[u8]) -> Vec<u8> {
        self.create_data_message(data)
    }

    /// Updates the channel state.
    pub fn set_state(&mut self, state: ChannelState) {
        self.state = state;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_creation() {
        let channel = SshChannel::new(0, 100, 1048576, 32768);
        assert_eq!(channel.local_id(), 0);
        assert_eq!(channel.remote_id(), 100);
        assert_eq!(channel.state(), ChannelState::Open);
        assert_eq!(channel.window_size(), 1048576);
    }

    #[test]
    fn test_window_management() {
        let mut channel = SshChannel::new(0, 100, 1000, 32768);

        // Consume window
        assert!(channel.consume_window(500).is_ok());
        assert_eq!(channel.window_size(), 500);

        // Try to consume more than available
        assert!(channel.consume_window(600).is_err());
        assert_eq!(channel.window_size(), 500);

        // Adjust window
        channel.adjust_window(500);
        assert_eq!(channel.window_size(), 1000);
    }

    #[test]
    fn test_channel_close() {
        let mut channel = SshChannel::new(0, 100, 1048576, 32768);
        assert_eq!(channel.state(), ChannelState::Open);

        channel.close();
        assert_eq!(channel.state(), ChannelState::Closed);
    }

    #[test]
    fn test_channel_with_channels() {
        let (channel, _tx) = SshChannel::with_channels(0, 100, 1048576, 32768);
        assert_eq!(channel.local_id(), 0);
        assert_eq!(channel.remote_id(), 100);
        assert_eq!(channel.state(), ChannelState::Opening);
        assert!(channel.rx.is_some());
        assert!(channel.tx.is_some());
    }

    #[tokio::test]
    async fn test_channel_async_communication() {
        let (mut channel, tx) = SshChannel::with_channels(0, 100, 1048576, 32768);

        // Send a message
        tx.send(ChannelMessage::Data(b"test data".to_vec()))
            .unwrap();

        // Receive the message
        let msg = channel.read().await.unwrap();
        assert!(msg.is_some());
        match msg.unwrap() {
            ChannelMessage::Data(data) => {
                assert_eq!(data, b"test data");
            }
            _ => panic!("Expected Data message"),
        }
    }

    #[tokio::test]
    async fn test_channel_legacy_mode_read_returns_none() {
        let mut channel = SshChannel::new(0, 100, 1048576, 32768);
        let result = channel.read().await.unwrap();
        assert!(result.is_none()); // Legacy mode
    }
}
