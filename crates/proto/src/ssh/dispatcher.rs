//! SSH Message Dispatcher.
//!
//! Routes incoming SSH messages to the appropriate channels.

use crate::ssh::channel::ChannelMessage;
use crate::ssh::connection_mgr::SshConnection;
use crate::ssh::message::MessageType;
use fynx_platform::{FynxError, FynxResult};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// Message dispatcher manages routing of SSH messages to channels.
pub struct MessageDispatcher {
    /// Shared connection
    connection: Arc<Mutex<SshConnection>>,
    /// Channel map: channel_id -> message sender
    channels: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<ChannelMessage>>>>,
    /// Global message receiver (for messages without channel ID)
    global_tx: mpsc::UnboundedSender<Vec<u8>>,
    global_rx: Arc<Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
    /// Dispatcher task handle
    task_handle: Option<JoinHandle<()>>,
}

impl MessageDispatcher {
    /// Creates a new message dispatcher.
    pub fn new(connection: Arc<Mutex<SshConnection>>) -> Self {
        let (global_tx, global_rx) = mpsc::unbounded_channel();

        Self {
            connection,
            channels: Arc::new(Mutex::new(HashMap::new())),
            global_tx,
            global_rx: Arc::new(Mutex::new(global_rx)),
            task_handle: None,
        }
    }

    /// Registers a channel with the dispatcher.
    pub async fn register_channel(
        &self,
        channel_id: u32,
        tx: mpsc::UnboundedSender<ChannelMessage>,
    ) {
        let mut channels = self.channels.lock().await;
        channels.insert(channel_id, tx);
        debug!("Registered channel {}", channel_id);
    }

    /// Unregisters a channel from the dispatcher.
    pub async fn unregister_channel(&self, channel_id: u32) {
        let mut channels = self.channels.lock().await;
        channels.remove(&channel_id);
        debug!("Unregistered channel {}", channel_id);
    }

    /// Starts the dispatcher task.
    pub fn start(&mut self) {
        let connection = Arc::clone(&self.connection);
        let channels = Arc::clone(&self.channels);
        let global_tx = self.global_tx.clone();

        let handle = tokio::spawn(async move {
            debug!("Message dispatcher started");

            loop {
                // Receive packet from connection
                let payload = {
                    let mut conn = connection.lock().await;
                    match conn.receive_packet().await {
                        Ok(payload) => payload,
                        Err(e) => {
                            warn!("Failed to receive packet: {}", e);
                            break;
                        }
                    }
                };

                if payload.is_empty() {
                    continue;
                }

                // Parse message type
                let msg_type = payload[0];

                // Route message based on type
                if let Err(e) = Self::route_message(&channels, &global_tx, msg_type, &payload).await
                {
                    warn!("Failed to route message: {}", e);
                }
            }

            debug!("Message dispatcher stopped");
        });

        self.task_handle = Some(handle);
    }

    /// Routes a message to the appropriate channel or global handler.
    async fn route_message(
        channels: &Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<ChannelMessage>>>>,
        global_tx: &mpsc::UnboundedSender<Vec<u8>>,
        msg_type: u8,
        payload: &[u8],
    ) -> FynxResult<()> {
        match MessageType::from_u8(msg_type) {
            // Channel messages
            Some(MessageType::ChannelData) => {
                if payload.len() < 9 {
                    return Err(FynxError::Protocol("Invalid CHANNEL_DATA".to_string()));
                }

                let channel_id =
                    u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
                let data_len =
                    u32::from_be_bytes([payload[5], payload[6], payload[7], payload[8]]) as usize;
                let data = payload[9..9 + data_len].to_vec();

                Self::send_to_channel(channels, channel_id, ChannelMessage::Data(data)).await?;
            }

            Some(MessageType::ChannelExtendedData) => {
                if payload.len() < 13 {
                    return Err(FynxError::Protocol(
                        "Invalid CHANNEL_EXTENDED_DATA".to_string(),
                    ));
                }

                let channel_id =
                    u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
                // Skip data_type (bytes 5-8)
                let data_len =
                    u32::from_be_bytes([payload[9], payload[10], payload[11], payload[12]])
                        as usize;
                let data = payload[13..13 + data_len].to_vec();

                Self::send_to_channel(channels, channel_id, ChannelMessage::ExtendedData(data))
                    .await?;
            }

            Some(MessageType::ChannelEof) => {
                if payload.len() < 5 {
                    return Err(FynxError::Protocol("Invalid CHANNEL_EOF".to_string()));
                }

                let channel_id =
                    u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
                Self::send_to_channel(channels, channel_id, ChannelMessage::Eof).await?;
            }

            Some(MessageType::ChannelClose) => {
                if payload.len() < 5 {
                    return Err(FynxError::Protocol("Invalid CHANNEL_CLOSE".to_string()));
                }

                let channel_id =
                    u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
                Self::send_to_channel(channels, channel_id, ChannelMessage::Close).await?;
            }

            Some(MessageType::ChannelSuccess) => {
                if payload.len() < 5 {
                    return Err(FynxError::Protocol("Invalid CHANNEL_SUCCESS".to_string()));
                }

                let channel_id =
                    u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
                Self::send_to_channel(channels, channel_id, ChannelMessage::Success).await?;
            }

            Some(MessageType::ChannelFailure) => {
                if payload.len() < 5 {
                    return Err(FynxError::Protocol("Invalid CHANNEL_FAILURE".to_string()));
                }

                let channel_id =
                    u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
                Self::send_to_channel(channels, channel_id, ChannelMessage::Failure).await?;
            }

            // Global messages (no channel ID)
            _ => {
                // Send to global handler
                if let Err(e) = global_tx.send(payload.to_vec()) {
                    warn!("Failed to send to global handler: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Sends a message to a specific channel.
    async fn send_to_channel(
        channels: &Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<ChannelMessage>>>>,
        channel_id: u32,
        message: ChannelMessage,
    ) -> FynxResult<()> {
        let channels = channels.lock().await;

        if let Some(tx) = channels.get(&channel_id) {
            tx.send(message).map_err(|_| {
                FynxError::Protocol(format!("Channel {} receiver dropped", channel_id))
            })?;
        } else {
            warn!("Received message for unknown channel {}", channel_id);
        }

        Ok(())
    }

    /// Stops the dispatcher task.
    pub fn stop(&mut self) {
        if let Some(handle) = self.task_handle.take() {
            handle.abort();
        }
    }

    /// Receives a global message (for messages without channel ID).
    pub async fn receive_global(&self) -> Option<Vec<u8>> {
        let mut rx = self.global_rx.lock().await;
        rx.recv().await
    }
}

impl Drop for MessageDispatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_dispatcher_creation() {
        // Can't test without actual connection
        // Would need mock TcpStream
    }
}
