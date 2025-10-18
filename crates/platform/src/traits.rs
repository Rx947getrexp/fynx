//! Core traits for Fynx security modules

use crate::FynxResult;

/// Security module interface
///
/// All Fynx modules implement this trait to provide unified management.
pub trait SecurityModule: Send + Sync {
    /// Unique module identifier
    fn id(&self) -> &'static str;

    /// Module version
    fn version(&self) -> &'static str;

    /// Module description
    fn description(&self) -> &'static str;

    /// Initialize the module
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails
    fn init(&mut self) -> FynxResult<()> {
        Ok(())
    }

    /// Shutdown the module
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails
    fn shutdown(&mut self) -> FynxResult<()> {
        Ok(())
    }
}

/// Scanner interface for security scanning modules
#[async_trait::async_trait]
pub trait Scanner: SecurityModule {
    /// Scan a target
    ///
    /// # Arguments
    ///
    /// * `target` - Target to scan (IP, domain, file path, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if scanning fails
    async fn scan(&self, target: &str) -> FynxResult<ScanResult>;
}

/// Analyzer interface for security analysis modules
pub trait Analyzer: SecurityModule {
    /// Analyze data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to analyze
    ///
    /// # Errors
    ///
    /// Returns an error if analysis fails
    fn analyze(&self, data: &[u8]) -> FynxResult<AnalysisResult>;
}

/// Scan result
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScanResult {
    /// Target that was scanned
    pub target: String,
    /// Findings from the scan
    pub findings: Vec<Finding>,
}

/// A single finding from a scan
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Finding {
    /// Severity level
    pub severity: Severity,
    /// Description of the finding
    pub description: String,
    /// Additional metadata (optional)
    pub metadata: Option<String>,
}

/// Severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Severity {
    /// Informational
    Info,
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_val = match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        };
        let other_val = match other {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        };
        self_val.cmp(&other_val)
    }
}

/// Analysis result
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AnalysisResult {
    /// Matches found during analysis
    pub matches: Vec<Match>,
}

/// A single match from analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Match {
    /// Offset in the data
    pub offset: usize,
    /// Length of the match
    pub length: usize,
    /// Rule or pattern that matched
    pub rule: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestModule;

    impl SecurityModule for TestModule {
        fn id(&self) -> &'static str {
            "test_module"
        }

        fn version(&self) -> &'static str {
            "0.1.0"
        }

        fn description(&self) -> &'static str {
            "Test security module"
        }
    }

    #[test]
    fn test_security_module() {
        let mut module = TestModule;
        assert_eq!(module.id(), "test_module");
        assert_eq!(module.version(), "0.1.0");
        assert!(module.init().is_ok());
        assert!(module.shutdown().is_ok());
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_scan_result() {
        let result = ScanResult {
            target: "example.com".to_string(),
            findings: vec![Finding {
                severity: Severity::High,
                description: "Test finding".to_string(),
                metadata: None,
            }],
        };

        assert_eq!(result.target, "example.com");
        assert_eq!(result.findings.len(), 1);
    }
}
