//! # Fynx Platform
//!
//! Core platform types, traits, and utilities for the Fynx security ecosystem.
//!
//! This crate provides:
//! - Unified error types (`FynxError`, `FynxResult`)
//! - Core traits (`SecurityModule`, `ProtocolStack`, `Scanner`, `Analyzer`)
//! - Common utilities and configuration
//!
//! # Examples
//!
//! ```
//! use fynx_platform::{FynxError, FynxResult};
//!
//! fn example_function() -> FynxResult<String> {
//!     Ok("Hello, Fynx!".to_string())
//! }
//!
//! # fn main() -> FynxResult<()> {
//! let result = example_function()?;
//! assert_eq!(result, "Hello, Fynx!");
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![forbid(unsafe_code)]

pub mod error;
pub mod traits;

pub use error::{FynxError, FynxResult};
pub use traits::{
    AnalysisResult, Analyzer, Finding, Match, ScanResult, Scanner, SecurityModule, Severity,
};

/// Platform version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
