//! IPSec Client and Server Configuration
//!
//! Provides configuration structures and builder patterns for IpsecClient and IpsecServer.

use super::{
    child_sa::SaLifetime,
    dpd::DpdConfig,
    ikev2::proposal::{DhTransformId, EncrTransformId, PrfTransformId, Proposal, ProtocolId, Transform, TransformType},
    Error, Result,
};

/// Client configuration for IPSec connections
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Local identity (e.g., "client@example.com")
    pub local_id: String,

    /// Remote identity (e.g., "server@example.com")
    pub remote_id: String,

    /// Pre-shared key for authentication
    pub psk: Vec<u8>,

    /// IKE SA proposals (encryption, PRF, DH)
    pub ike_proposals: Vec<Proposal>,

    /// ESP Child SA proposals (encryption, ESN)
    pub esp_proposals: Vec<Proposal>,

    /// Dead Peer Detection configuration (optional)
    pub dpd_config: Option<DpdConfig>,

    /// SA lifetime configuration
    pub lifetime: SaLifetime,
}

impl ClientConfig {
    /// Create builder for client configuration
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.local_id.is_empty() {
            return Err(Error::InvalidParameter("local_id cannot be empty".into()));
        }
        if self.remote_id.is_empty() {
            return Err(Error::InvalidParameter("remote_id cannot be empty".into()));
        }
        if self.psk.is_empty() {
            return Err(Error::InvalidParameter("PSK cannot be empty".into()));
        }
        if self.ike_proposals.is_empty() {
            return Err(Error::InvalidParameter(
                "At least one IKE proposal required".into(),
            ));
        }
        if self.esp_proposals.is_empty() {
            return Err(Error::InvalidParameter(
                "At least one ESP proposal required".into(),
            ));
        }
        Ok(())
    }
}

/// Server configuration for IPSec connections
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Local identity (e.g., "server@example.com")
    pub local_id: String,

    /// Pre-shared key for authentication
    pub psk: Vec<u8>,

    /// IKE SA proposals (encryption, PRF, DH)
    pub ike_proposals: Vec<Proposal>,

    /// ESP Child SA proposals (encryption, ESN)
    pub esp_proposals: Vec<Proposal>,

    /// Dead Peer Detection configuration (optional)
    pub dpd_config: Option<DpdConfig>,

    /// SA lifetime configuration
    pub lifetime: SaLifetime,
}

impl ServerConfig {
    /// Create builder for server configuration
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.local_id.is_empty() {
            return Err(Error::InvalidParameter("local_id cannot be empty".into()));
        }
        if self.psk.is_empty() {
            return Err(Error::InvalidParameter("PSK cannot be empty".into()));
        }
        if self.ike_proposals.is_empty() {
            return Err(Error::InvalidParameter(
                "At least one IKE proposal required".into(),
            ));
        }
        if self.esp_proposals.is_empty() {
            return Err(Error::InvalidParameter(
                "At least one ESP proposal required".into(),
            ));
        }
        Ok(())
    }
}

/// Builder for ClientConfig
#[derive(Default)]
pub struct ClientBuilder {
    local_id: Option<String>,
    remote_id: Option<String>,
    psk: Option<Vec<u8>>,
    ike_proposals: Option<Vec<Proposal>>,
    esp_proposals: Option<Vec<Proposal>>,
    dpd_config: Option<DpdConfig>,
    lifetime: Option<SaLifetime>,
}

impl ClientBuilder {
    /// Create new client builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set local identity
    pub fn with_local_id(mut self, id: impl Into<String>) -> Self {
        self.local_id = Some(id.into());
        self
    }

    /// Set remote identity
    pub fn with_remote_id(mut self, id: impl Into<String>) -> Self {
        self.remote_id = Some(id.into());
        self
    }

    /// Set pre-shared key
    pub fn with_psk(mut self, psk: impl Into<Vec<u8>>) -> Self {
        self.psk = Some(psk.into());
        self
    }

    /// Set IKE proposals
    pub fn with_ike_proposals(mut self, proposals: Vec<Proposal>) -> Self {
        self.ike_proposals = Some(proposals);
        self
    }

    /// Set ESP proposals
    pub fn with_esp_proposals(mut self, proposals: Vec<Proposal>) -> Self {
        self.esp_proposals = Some(proposals);
        self
    }

    /// Set DPD configuration
    pub fn with_dpd(mut self, config: DpdConfig) -> Self {
        self.dpd_config = Some(config);
        self
    }

    /// Set SA lifetime
    pub fn with_lifetime(mut self, lifetime: SaLifetime) -> Self {
        self.lifetime = Some(lifetime);
        self
    }

    /// Build ClientConfig with validation
    pub fn build(self) -> Result<ClientConfig> {
        let config = ClientConfig {
            local_id: self
                .local_id
                .ok_or_else(|| Error::InvalidParameter("local_id is required".into()))?,
            remote_id: self
                .remote_id
                .ok_or_else(|| Error::InvalidParameter("remote_id is required".into()))?,
            psk: self
                .psk
                .ok_or_else(|| Error::InvalidParameter("psk is required".into()))?,
            ike_proposals: self.ike_proposals.unwrap_or_else(|| {
                vec![
                    // Default: AES-GCM-128, HMAC-SHA256, DH Group 14
                    Proposal::new(1, ProtocolId::Ike)
                        .add_transform(Transform::encr(EncrTransformId::AesGcm128))
                        .add_transform(Transform::prf(PrfTransformId::HmacSha256))
                        .add_transform(Transform::dh(DhTransformId::Group14)),
                ]
            }),
            esp_proposals: self.esp_proposals.unwrap_or_else(|| {
                vec![
                    // Default: AES-GCM-128, No ESN
                    Proposal::new(1, ProtocolId::Esp)
                        .add_transform(Transform::encr(EncrTransformId::AesGcm128))
                        .add_transform(Transform::new(TransformType::Esn, 0)),
                ]
            }),
            dpd_config: self.dpd_config,
            lifetime: self.lifetime.unwrap_or_default(),
        };

        config.validate()?;
        Ok(config)
    }
}

/// Builder for ServerConfig
#[derive(Default)]
pub struct ServerBuilder {
    local_id: Option<String>,
    psk: Option<Vec<u8>>,
    ike_proposals: Option<Vec<Proposal>>,
    esp_proposals: Option<Vec<Proposal>>,
    dpd_config: Option<DpdConfig>,
    lifetime: Option<SaLifetime>,
}

impl ServerBuilder {
    /// Create new server builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set local identity
    pub fn with_local_id(mut self, id: impl Into<String>) -> Self {
        self.local_id = Some(id.into());
        self
    }

    /// Set pre-shared key
    pub fn with_psk(mut self, psk: impl Into<Vec<u8>>) -> Self {
        self.psk = Some(psk.into());
        self
    }

    /// Set IKE proposals
    pub fn with_ike_proposals(mut self, proposals: Vec<Proposal>) -> Self {
        self.ike_proposals = Some(proposals);
        self
    }

    /// Set ESP proposals
    pub fn with_esp_proposals(mut self, proposals: Vec<Proposal>) -> Self {
        self.esp_proposals = Some(proposals);
        self
    }

    /// Set DPD configuration
    pub fn with_dpd(mut self, config: DpdConfig) -> Self {
        self.dpd_config = Some(config);
        self
    }

    /// Set SA lifetime
    pub fn with_lifetime(mut self, lifetime: SaLifetime) -> Self {
        self.lifetime = Some(lifetime);
        self
    }

    /// Build ServerConfig with validation
    pub fn build(self) -> Result<ServerConfig> {
        let config = ServerConfig {
            local_id: self
                .local_id
                .ok_or_else(|| Error::InvalidParameter("local_id is required".into()))?,
            psk: self
                .psk
                .ok_or_else(|| Error::InvalidParameter("psk is required".into()))?,
            ike_proposals: self.ike_proposals.unwrap_or_else(|| {
                vec![
                    // Default: AES-GCM-128, HMAC-SHA256, DH Group 14
                    Proposal::new(1, ProtocolId::Ike)
                        .add_transform(Transform::encr(EncrTransformId::AesGcm128))
                        .add_transform(Transform::prf(PrfTransformId::HmacSha256))
                        .add_transform(Transform::dh(DhTransformId::Group14)),
                ]
            }),
            esp_proposals: self.esp_proposals.unwrap_or_else(|| {
                vec![
                    // Default: AES-GCM-128, No ESN
                    Proposal::new(1, ProtocolId::Esp)
                        .add_transform(Transform::encr(EncrTransformId::AesGcm128))
                        .add_transform(Transform::new(TransformType::Esn, 0)),
                ]
            }),
            dpd_config: self.dpd_config,
            lifetime: self.lifetime.unwrap_or_default(),
        };

        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_client_config_builder() {
        let config = ClientConfig::builder()
            .with_local_id("client@example.com")
            .with_remote_id("server@example.com")
            .with_psk(b"my-secret-key")
            .build()
            .expect("Failed to build client config");

        assert_eq!(config.local_id, "client@example.com");
        assert_eq!(config.remote_id, "server@example.com");
        assert_eq!(config.psk, b"my-secret-key");
        assert_eq!(config.ike_proposals.len(), 1);
        assert_eq!(config.esp_proposals.len(), 1);
    }

    #[test]
    fn test_server_config_builder() {
        let config = ServerConfig::builder()
            .with_local_id("server@example.com")
            .with_psk(b"my-secret-key")
            .build()
            .expect("Failed to build server config");

        assert_eq!(config.local_id, "server@example.com");
        assert_eq!(config.psk, b"my-secret-key");
        assert_eq!(config.ike_proposals.len(), 1);
        assert_eq!(config.esp_proposals.len(), 1);
    }

    #[test]
    fn test_config_validation() {
        // Missing local_id
        let result = ClientConfig::builder()
            .with_remote_id("server@example.com")
            .with_psk(b"secret")
            .build();
        assert!(result.is_err());

        // Missing remote_id
        let result = ClientConfig::builder()
            .with_local_id("client@example.com")
            .with_psk(b"secret")
            .build();
        assert!(result.is_err());

        // Missing PSK
        let result = ClientConfig::builder()
            .with_local_id("client@example.com")
            .with_remote_id("server@example.com")
            .build();
        assert!(result.is_err());

        // Valid config
        let result = ClientConfig::builder()
            .with_local_id("client@example.com")
            .with_remote_id("server@example.com")
            .with_psk(b"secret")
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_custom_proposals() {
        let custom_ike_proposal = Proposal::new(1, ProtocolId::Ike)
            .add_transform(Transform::encr(EncrTransformId::AesGcm256))
            .add_transform(Transform::prf(PrfTransformId::HmacSha512))
            .add_transform(Transform::dh(DhTransformId::Group15));

        let config = ClientConfig::builder()
            .with_local_id("client@example.com")
            .with_remote_id("server@example.com")
            .with_psk(b"secret")
            .with_ike_proposals(vec![custom_ike_proposal])
            .build()
            .expect("Failed to build config");

        assert_eq!(config.ike_proposals.len(), 1);
    }

    #[test]
    fn test_custom_lifetime() {
        let lifetime = SaLifetime {
            soft_time: Duration::from_secs(1800),
            hard_time: Duration::from_secs(3600),
            soft_bytes: Some(100_000_000),
            hard_bytes: Some(200_000_000),
        };

        let config = ClientConfig::builder()
            .with_local_id("client@example.com")
            .with_remote_id("server@example.com")
            .with_psk(b"secret")
            .with_lifetime(lifetime.clone())
            .build()
            .expect("Failed to build config");

        assert_eq!(config.lifetime.soft_time, lifetime.soft_time);
        assert_eq!(config.lifetime.hard_time, lifetime.hard_time);
    }
}
