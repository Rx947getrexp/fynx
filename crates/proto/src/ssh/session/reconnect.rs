//! SSH Automatic Reconnection.
//!
//! Implements automatic reconnection with exponential backoff to handle
//! network interruptions gracefully.

use fynx_platform::FynxResult;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Reconnection configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconnectConfig {
    /// Whether automatic reconnection is enabled.
    pub enabled: bool,
    /// Maximum number of reconnection attempts.
    pub max_retries: u32,
    /// Initial backoff duration.
    pub initial_backoff: Duration,
    /// Maximum backoff duration.
    pub max_backoff: Duration,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_retries: 3,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
        }
    }
}

impl ReconnectConfig {
    /// Creates a new reconnect configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables automatic reconnection.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Sets the maximum number of retry attempts.
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Sets the initial backoff duration.
    pub fn with_initial_backoff(mut self, duration: Duration) -> Self {
        self.initial_backoff = duration;
        self
    }

    /// Sets the maximum backoff duration.
    pub fn with_max_backoff(mut self, duration: Duration) -> Self {
        self.max_backoff = duration;
        self
    }
}

/// Exponential backoff calculator.
///
/// Calculates backoff delays with exponential growth: 1s, 2s, 4s, 8s, etc.
pub struct ExponentialBackoff {
    config: ReconnectConfig,
    current_attempt: u32,
}

impl ExponentialBackoff {
    /// Creates a new exponential backoff calculator.
    pub fn new(config: ReconnectConfig) -> Self {
        Self {
            config,
            current_attempt: 0,
        }
    }

    /// Calculates the next backoff duration.
    ///
    /// Returns the duration to wait before the next retry attempt.
    /// Uses exponential backoff: initial * 2^attempt, capped at max_backoff.
    pub fn next_backoff(&mut self) -> Duration {
        if self.current_attempt == 0 {
            self.current_attempt += 1;
            self.config.initial_backoff
        } else {
            self.current_attempt += 1;
            let multiplier = 2u32.saturating_pow(self.current_attempt - 1);

            self.config
                .initial_backoff
                .saturating_mul(multiplier)
                .min(self.config.max_backoff)
        }
    }

    /// Returns the current attempt number (0-indexed).
    pub fn attempt(&self) -> u32 {
        self.current_attempt
    }

    /// Resets the backoff calculator.
    pub fn reset(&mut self) {
        self.current_attempt = 0;
    }

    /// Returns whether max retries have been reached.
    pub fn max_retries_reached(&self) -> bool {
        self.current_attempt >= self.config.max_retries
    }
}

/// Reconnection handler.
///
/// Manages the reconnection process with exponential backoff and retry logic.
pub struct ReconnectHandler {
    config: ReconnectConfig,
    backoff: ExponentialBackoff,
}

impl ReconnectHandler {
    /// Creates a new reconnection handler.
    pub fn new(config: ReconnectConfig) -> Self {
        let backoff = ExponentialBackoff::new(config);
        Self { config, backoff }
    }

    /// Attempts to reconnect with exponential backoff.
    ///
    /// Calls the provided `reconnect_fn` up to `max_retries` times,
    /// waiting with exponential backoff between attempts.
    ///
    /// # Arguments
    ///
    /// * `reconnect_fn` - Async function that performs the reconnection
    ///
    /// # Returns
    ///
    /// Ok(()) if reconnection succeeded, Err if all retries failed
    pub async fn reconnect_with_backoff<F, Fut>(&mut self, mut reconnect_fn: F) -> FynxResult<()>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = FynxResult<()>>,
    {
        if !self.config.enabled {
            return Err(fynx_platform::FynxError::Config(
                "Reconnection is disabled".to_string(),
            ));
        }

        self.backoff.reset();

        loop {
            if self.backoff.max_retries_reached() {
                warn!(
                    "Reconnection failed after {} attempts",
                    self.config.max_retries
                );
                return Err(fynx_platform::FynxError::Protocol(format!(
                    "Reconnection failed after {} retries",
                    self.config.max_retries
                )));
            }

            let backoff_duration = self.backoff.next_backoff();
            let attempt = self.backoff.attempt();

            info!(
                "Reconnection attempt {}/{} (backoff: {:?})",
                attempt, self.config.max_retries, backoff_duration
            );

            // Wait before attempting reconnection
            if attempt > 1 {
                debug!("Waiting {:?} before retry", backoff_duration);
                tokio::time::sleep(backoff_duration).await;
            }

            // Attempt reconnection
            match reconnect_fn().await {
                Ok(()) => {
                    info!("Reconnection successful on attempt {}", attempt);
                    return Ok(());
                }
                Err(e) => {
                    warn!("Reconnection attempt {} failed: {}", attempt, e);
                    // Continue to next iteration
                }
            }
        }
    }

    /// Resets the reconnection handler state.
    pub fn reset(&mut self) {
        self.backoff.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reconnect_config_default() {
        let config = ReconnectConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff, Duration::from_secs(1));
        assert_eq!(config.max_backoff, Duration::from_secs(30));
    }

    #[test]
    fn test_reconnect_config_builder() {
        let config = ReconnectConfig::new()
            .with_enabled(true)
            .with_max_retries(5)
            .with_initial_backoff(Duration::from_secs(2))
            .with_max_backoff(Duration::from_secs(60));

        assert!(config.enabled);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_backoff, Duration::from_secs(2));
        assert_eq!(config.max_backoff, Duration::from_secs(60));
    }

    #[test]
    fn test_exponential_backoff() {
        let config = ReconnectConfig {
            enabled: true,
            max_retries: 5,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
        };

        let mut backoff = ExponentialBackoff::new(config);

        // First attempt: 1s
        assert_eq!(backoff.next_backoff(), Duration::from_secs(1));
        assert_eq!(backoff.attempt(), 1);

        // Second attempt: 2s (1 * 2^1)
        assert_eq!(backoff.next_backoff(), Duration::from_secs(2));
        assert_eq!(backoff.attempt(), 2);

        // Third attempt: 4s (1 * 2^2)
        assert_eq!(backoff.next_backoff(), Duration::from_secs(4));
        assert_eq!(backoff.attempt(), 3);

        // Fourth attempt: 8s (1 * 2^3)
        assert_eq!(backoff.next_backoff(), Duration::from_secs(8));
        assert_eq!(backoff.attempt(), 4);

        // Fifth attempt: 16s (1 * 2^4)
        assert_eq!(backoff.next_backoff(), Duration::from_secs(16));
        assert_eq!(backoff.attempt(), 5);
    }

    #[test]
    fn test_exponential_backoff_max_cap() {
        let config = ReconnectConfig {
            enabled: true,
            max_retries: 10,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(10), // Cap at 10s
        };

        let mut backoff = ExponentialBackoff::new(config);

        // Progress through backoffs
        assert_eq!(backoff.next_backoff(), Duration::from_secs(1));
        assert_eq!(backoff.next_backoff(), Duration::from_secs(2));
        assert_eq!(backoff.next_backoff(), Duration::from_secs(4));
        assert_eq!(backoff.next_backoff(), Duration::from_secs(8));

        // Should be capped at 10s (not 16s)
        assert_eq!(backoff.next_backoff(), Duration::from_secs(10));
        assert_eq!(backoff.next_backoff(), Duration::from_secs(10));
    }

    #[test]
    fn test_exponential_backoff_reset() {
        let config = ReconnectConfig::default();
        let mut backoff = ExponentialBackoff::new(config);

        // Make some attempts
        backoff.next_backoff();
        backoff.next_backoff();
        assert_eq!(backoff.attempt(), 2);

        // Reset
        backoff.reset();
        assert_eq!(backoff.attempt(), 0);

        // Should start from beginning again
        assert_eq!(backoff.next_backoff(), Duration::from_secs(1));
    }

    #[test]
    fn test_max_retries_check() {
        let config = ReconnectConfig {
            enabled: true,
            max_retries: 3,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
        };

        let mut backoff = ExponentialBackoff::new(config);

        assert!(!backoff.max_retries_reached());

        backoff.next_backoff(); // attempt 1
        assert!(!backoff.max_retries_reached());

        backoff.next_backoff(); // attempt 2
        assert!(!backoff.max_retries_reached());

        backoff.next_backoff(); // attempt 3
        assert!(backoff.max_retries_reached());
    }

    #[tokio::test]
    async fn test_reconnect_handler_success() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let config = ReconnectConfig {
            enabled: true,
            max_retries: 3,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_secs(1),
        };

        let mut handler = ReconnectHandler::new(config);
        let attempt_counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&attempt_counter);

        let result = handler
            .reconnect_with_backoff(|| {
                let counter = Arc::clone(&counter_clone);
                async move {
                    let attempts = counter.fetch_add(1, Ordering::Relaxed) + 1;
                    if attempts < 2 {
                        // Fail first attempt
                        Err(fynx_platform::FynxError::Protocol(
                            "Simulated failure".to_string(),
                        ))
                    } else {
                        // Succeed on second attempt
                        Ok(())
                    }
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(attempt_counter.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_reconnect_handler_all_retries_fail() {
        let config = ReconnectConfig {
            enabled: true,
            max_retries: 3,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_secs(1),
        };

        let mut handler = ReconnectHandler::new(config);

        let result = handler
            .reconnect_with_backoff(|| async {
                Err(fynx_platform::FynxError::Protocol(
                    "Always fail".to_string(),
                ))
            })
            .await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("failed after 3 retries"));
    }

    #[tokio::test]
    async fn test_reconnect_handler_disabled() {
        let config = ReconnectConfig {
            enabled: false, // Disabled
            max_retries: 3,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
        };

        let mut handler = ReconnectHandler::new(config);

        let result = handler.reconnect_with_backoff(|| async { Ok(()) }).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("disabled"));
    }
}
