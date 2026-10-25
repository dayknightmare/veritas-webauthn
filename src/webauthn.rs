use url::Url;
use crate::errors::{VeritasWebAuthnError, VeritasWebAuthnResult};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WebAuthn {
    pub(crate) config: WebAuthnConfig,
}

impl WebAuthn {
    #[must_use]
    #[inline]
    pub fn new(config: WebAuthnConfig) -> Self {
        Self { config }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WebAuthnConfig {
    pub(crate) rp_id: String,
    pub(crate) rp_name: String,
    pub(crate) origins: Vec<Url>,
    pub(crate) timeouts: WebAuthnTimeoutConfig,
}

impl WebAuthnConfig {
    #[must_use]
    #[inline]
    pub fn builder() -> WebAuthnConfigBuilder {
        WebAuthnConfigBuilder::new()
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WebAuthnTimeoutConfig {
    pub(crate) registration: u32,
    pub(crate) authentication: u32,
}

impl WebAuthnTimeoutConfig {
    #[must_use]
    #[inline]
    pub fn builder() -> WebAuthnTimeoutBuilder {
        WebAuthnTimeoutBuilder::new()
    }
}

#[non_exhaustive]
pub struct WebAuthnTimeoutBuilder {
    pub(crate) timeouts: WebAuthnTimeoutConfig,
}

impl Default for WebAuthnTimeoutConfig {
    #[inline]
    fn default() -> Self {
        WebAuthnTimeoutConfig{
            registration: 5 * 60 * 1000,
            authentication: 5 * 60 * 1000,
        }
    }
}

impl Default for WebAuthnTimeoutBuilder {
    #[inline]
    fn default() -> Self {
        WebAuthnTimeoutBuilder::new()
    }
}

impl WebAuthnTimeoutBuilder {
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            timeouts: WebAuthnTimeoutConfig::default(),
        }
    }

    #[must_use]
    #[inline]
    pub fn with_registration(mut self, registration: u32) -> Self {
        self.timeouts.registration = registration;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_authentication(mut self, authentication: u32) -> Self {
        self.timeouts.authentication = authentication;
        self
    }

    #[must_use]
    #[inline]
    pub fn build(self) -> WebAuthnTimeoutConfig {
        self.timeouts
    }
}

#[non_exhaustive]
pub struct WebAuthnConfigBuilder {
    config: WebAuthnConfig,
}

impl Default for WebAuthnConfigBuilder {
    #[inline]
    fn default() -> Self {
        WebAuthnConfigBuilder::new()
    }
}

impl WebAuthnConfigBuilder {
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            config: WebAuthnConfig {
                rp_id: String::new(),
                rp_name: String::new(),
                origins: Vec::new(),
                timeouts: WebAuthnTimeoutConfig::default(),
            },
        }
    }

    #[must_use]
    #[inline]
    pub fn with_rp_id(mut self, rp_id: String) -> Self {
        self.config.rp_id = rp_id;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_rp_name(mut self, rp_name: String) -> Self {
        self.config.rp_name = rp_name;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_origins(mut self, origins: Vec<Url>) -> Self {
        self.config.origins = origins;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_timeouts(mut self, timeouts: WebAuthnTimeoutConfig) -> Self {
        self.config.timeouts.authentication = timeouts.authentication;
        self.config.timeouts.registration = timeouts.registration;
        self
    }

    #[inline]
    pub fn build(self) -> VeritasWebAuthnResult<WebAuthnConfig> {
        if self.config.rp_id.is_empty() {
            return Err(VeritasWebAuthnError::InvalidRpId);
        }

        if self.config.rp_name.is_empty() {
            return Err(VeritasWebAuthnError::InvalidRpName);
        }

        if self.config.origins.is_empty() {
            return Err(VeritasWebAuthnError::InvalidOrigin);
        }

        if self.config.timeouts.authentication > 24 * 60 * 60 * 1000 || self.config.timeouts.authentication < 1000 {
            return Err(VeritasWebAuthnError::InvalidTimeout);
        }

        if self.config.timeouts.registration > 24 * 60 * 60 * 1000 || self.config.timeouts.registration < 1000 {
            return Err(VeritasWebAuthnError::InvalidTimeout);
        }

        Ok(self.config)
    }
}