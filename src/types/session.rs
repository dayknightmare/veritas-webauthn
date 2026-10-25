use crate::errors::{VeritasWebAuthnError, VeritasWebAuthnResult};
use crate::types::base64_encoded_url::Base64EncodedUrl;
use crate::types::protocol::authenticator::UserVerificationRequirement;
use crate::types::protocol::credential::CredentialParameter;
use crate::types::protocol::extension::AuthenticationExtensions;
use crate::types::protocol::webauthn::Mediation;
use serde::{Deserialize, Serialize};

pub(crate) const MIN_CHALLENGE_LEN: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WebAuthnSession {
    pub challenge: Base64EncodedUrl,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "userVerification")]
    pub user_verification: UserVerificationRequirement,
    pub extensions: Option<AuthenticationExtensions>,
    pub parameters: Vec<CredentialParameter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediation: Option<Mediation>,
    #[serde(rename = "expiresAt")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "issuedAt")]
    pub issued_at: chrono::DateTime<chrono::Utc>,
}

impl WebAuthnSession {
    #[must_use]
    #[inline]
    pub fn builder() -> WebAuthnSessionBuilder {
        WebAuthnSessionBuilder::new()
    }

    #[must_use]
    #[inline]
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }
}

#[non_exhaustive]
pub struct WebAuthnSessionBuilder {
    session: WebAuthnSession,
}

impl Default for WebAuthnSessionBuilder {
    #[inline]
    fn default() -> Self {
        WebAuthnSessionBuilder::new()
    }
}

impl WebAuthnSessionBuilder {
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        let now = chrono::Utc::now();

        WebAuthnSessionBuilder {
            session: WebAuthnSession {
                challenge: Base64EncodedUrl::new(Vec::new()),
                rp_id: String::new(),
                user_id: String::new(),
                user_verification: UserVerificationRequirement::Required,
                extensions: None,
                parameters: Vec::new(),
                mediation: None,
                expires_at: now,
                issued_at: now,
            },
        }
    }

    #[must_use]
    #[inline]
    pub fn with_challenge(mut self, challenge: Base64EncodedUrl) -> Self {
        self.session.challenge = challenge;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_rp_id(mut self, rp_id: String) -> Self {
        self.session.rp_id = rp_id;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_user_id(mut self, user_id: String) -> Self {
        self.session.user_id = user_id;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_user_verification(mut self, user_verification: UserVerificationRequirement) -> Self {
        self.session.user_verification = user_verification;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_extensions(mut self, extensions: AuthenticationExtensions) -> Self {
        self.session.extensions = Some(extensions);
        self
    }

    #[must_use]
    #[inline]
    pub fn with_parameters(mut self, parameters: Vec<CredentialParameter>) -> Self {
        self.session.parameters = parameters;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_mediation(mut self, mediation: Option<Mediation>) -> Self {
        self.session.mediation = mediation;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_issued_at(mut self, issued_at: chrono::DateTime<chrono::Utc>) -> Self {
        self.session.issued_at = issued_at;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_expires_at(mut self, expires_at: chrono::DateTime<chrono::Utc>) -> Self {
        self.session.expires_at = expires_at;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_timeout(mut self, timeout: u32) -> Self {
        self.session.expires_at = self.session.issued_at + chrono::Duration::milliseconds(timeout as i64);
        self
    }

    #[inline]
    pub fn build(self) -> VeritasWebAuthnResult<WebAuthnSession> {
        if self.session.challenge.len() < MIN_CHALLENGE_LEN {
            return Err(VeritasWebAuthnError::InvalidChallenge);
        }

        if self.session.rp_id.is_empty() {
            return Err(VeritasWebAuthnError::InvalidRpId);
        }

        if self.session.user_id.is_empty() {
            return Err(VeritasWebAuthnError::InvalidUserId);
        }

        if self.session.parameters.is_empty() {
            return Err(VeritasWebAuthnError::InvalidCredentialParameters);
        }

        if self.session.expires_at <= self.session.issued_at {
            return Err(VeritasWebAuthnError::InvalidTimeout);
        }

        Ok(self.session)
    }
}
