//! SSH Keep-alive implementation.
//!
//! Implements keep-alive heartbeat functionality using SSH_MSG_IGNORE messages
//! to prevent idle connection timeouts.

use crate::ssh::message::MessageType;
use fynx_platform::FynxResult;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// Keep-alive task handle.
///
/// Manages a background task that periodically sends SSH_MSG_IGNORE messages
/// to keep the connection alive.
pub struct KeepaliveTask {
    /// Keep-alive interval
    interval: Duration,
    /// Stop signal
    stop_signal: Arc<AtomicBool>,
    /// Task handle
    task_handle: Option<JoinHandle<()>>,
}

impl KeepaliveTask {
    /// Creates a new keep-alive task (but doesn't start it).
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            stop_signal: Arc::new(AtomicBool::new(false)),
            task_handle: None,
        }
    }

    /// Starts the keep-alive task.
    ///
    /// # Arguments
    ///
    /// * `send_fn` - Async closure that sends a keep-alive message
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut task = KeepaliveTask::new(Duration::from_secs(60));
    /// task.start(|| async {
    ///     client.send_keepalive().await
    /// });
    /// ```
    pub fn start<F, Fut>(&mut self, send_fn: F)
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = FynxResult<()>> + Send + 'static,
    {
        let interval = self.interval;
        let stop_signal = Arc::clone(&self.stop_signal);

        let handle = tokio::spawn(async move {
            debug!("Keep-alive task started with interval: {:?}", interval);

            loop {
                tokio::time::sleep(interval).await;

                if stop_signal.load(Ordering::Relaxed) {
                    debug!("Keep-alive task stopping");
                    break;
                }

                // Send keep-alive message
                match send_fn().await {
                    Ok(()) => {
                        debug!("Keep-alive message sent successfully");
                    }
                    Err(e) => {
                        warn!("Keep-alive failed: {} - stopping task", e);
                        break;
                    }
                }
            }

            debug!("Keep-alive task stopped");
        });

        self.task_handle = Some(handle);
    }

    /// Stops the keep-alive task.
    pub fn stop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);

        if let Some(handle) = self.task_handle.take() {
            handle.abort();
        }
    }

    /// Returns whether the task is running.
    pub fn is_running(&self) -> bool {
        self.task_handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or(false)
    }
}

impl Drop for KeepaliveTask {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Creates an SSH_MSG_IGNORE message for keep-alive.
///
/// The message contains random data to make traffic analysis harder.
///
/// # Format
///
/// ```text
/// byte    SSH_MSG_IGNORE (2)
/// string  data
/// ```
///
/// # Arguments
///
/// * `data_len` - Length of random data (0-256 bytes recommended)
///
/// # Returns
///
/// SSH_MSG_IGNORE message bytes
///
/// # Example
///
/// ```rust
/// use fynx_proto::ssh::session::create_keepalive_message;
///
/// let msg = create_keepalive_message(32);
/// assert_eq!(msg[0], 2); // SSH_MSG_IGNORE
/// ```
pub fn create_keepalive_message(data_len: usize) -> Vec<u8> {
    use rand::Rng;

    let mut msg = Vec::with_capacity(1 + 4 + data_len);

    // Message type: SSH_MSG_IGNORE
    msg.push(MessageType::Ignore as u8);

    // Random data length (4 bytes, big-endian)
    msg.extend_from_slice(&(data_len as u32).to_be_bytes());

    // Random data
    if data_len > 0 {
        let mut rng = rand::thread_rng();
        let random_data: Vec<u8> = (0..data_len).map(|_| rng.gen()).collect();
        msg.extend_from_slice(&random_data);
    }

    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_keepalive_message_format() {
        let msg = create_keepalive_message(0);
        assert_eq!(msg[0], MessageType::Ignore as u8);
        assert_eq!(msg.len(), 1 + 4); // type + length

        // Verify length field is 0
        let data_len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
        assert_eq!(data_len, 0);
    }

    #[test]
    fn test_create_keepalive_message_with_data() {
        let msg = create_keepalive_message(32);
        assert_eq!(msg[0], MessageType::Ignore as u8);
        assert_eq!(msg.len(), 1 + 4 + 32); // type + length + data

        // Verify length field is 32
        let data_len = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
        assert_eq!(data_len, 32);
    }

    #[test]
    fn test_keepalive_task_creation() {
        let task = KeepaliveTask::new(Duration::from_secs(60));
        assert!(!task.is_running());
    }

    #[tokio::test]
    async fn test_keepalive_task_lifecycle() {
        use std::sync::atomic::AtomicU32;

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);

        let mut task = KeepaliveTask::new(Duration::from_millis(100));
        task.start(move || {
            let counter = Arc::clone(&counter_clone);
            async move {
                counter.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        });

        assert!(task.is_running());

        // Wait for a few iterations
        tokio::time::sleep(Duration::from_millis(350)).await;

        // Stop the task
        task.stop();

        // Should have run 3 times (at 100ms, 200ms, 300ms)
        let count = counter.load(Ordering::Relaxed);
        assert!(count >= 3 && count <= 4, "Expected 3-4 calls, got {}", count);

        assert!(!task.is_running());
    }

    #[tokio::test]
    async fn test_keepalive_task_stops_on_error() {
        use std::sync::atomic::AtomicBool;
        use fynx_platform::FynxError;

        let should_fail = Arc::new(AtomicBool::new(false));
        let should_fail_clone = Arc::clone(&should_fail);

        let mut task = KeepaliveTask::new(Duration::from_millis(50));
        task.start(move || {
            let should_fail = Arc::clone(&should_fail_clone);
            async move {
                if should_fail.load(Ordering::Relaxed) {
                    Err(FynxError::Protocol("Simulated error".to_string()))
                } else {
                    Ok(())
                }
            }
        });

        assert!(task.is_running());

        // Wait for first successful iteration
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(task.is_running());

        // Trigger failure
        should_fail.store(true, Ordering::Relaxed);

        // Wait for task to detect error and stop
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Task should have stopped
        assert!(!task.is_running());
    }
}
