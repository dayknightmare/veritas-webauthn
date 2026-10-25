use crate::types::base64_encoded_url::Base64EncodedUrl;
use crate::types::protocol::attestation::{AttestationFormat, ConveyancePreference};
use crate::types::protocol::authenticator::{AuthenticatorAttachment, ResidentKeyRequirement, UserVerificationRequirement};
use crate::types::protocol::credential::{CredentialDescriptor, CredentialParameter};
use crate::types::protocol::extension::AuthenticationExtensions;
use crate::types::protocol::public_key::PublicKeyCredentialHint;
use crate::types::protocol::webauthn::Mediation;
use crate::types::user::{WebAuthnUser};
use crate::types::session::MIN_CHALLENGE_LEN;
use crate::errors::{VeritasWebAuthnError, VeritasWebAuthnResult};
use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RegistrationBeginResponse {
    pub response: PublicKeyCredentialRegistrationBeginResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediation: Option<Mediation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PublicKeyCredentialRegistrationBeginResponse {
    pub challenge: Base64EncodedUrl,
    pub rp: RelyingPartyRegistrationBeginResponse,
    pub user: WebAuthnUser,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,

    #[serde(rename = "pubKeyCredParams")]
    pub(crate) parameters: Vec<CredentialParameter>,

    #[serde(rename = "excludeCredentials")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) excluded_credentials: Option<Vec<CredentialDescriptor>>,

    #[serde(rename = "authenticatorSelection")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) authenticator_selection: Option<AuthenticatorSelectionRegistrationBeginResponse>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hits: Option<Vec<PublicKeyCredentialHint>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) attestation: Option<ConveyancePreference>,

    #[serde(rename = "attestationFormat")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) attestation_fmt: Option<Vec<AttestationFormat>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) extensions: Option<AuthenticationExtensions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RelyingPartyRegistrationBeginResponse {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuthenticatorSelectionRegistrationBeginResponse {
    #[serde(rename = "authenticatorAttachment")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,

    #[serde(rename = "requireResidentKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,

    #[serde(rename = "residentKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<ResidentKeyRequirement>,

    #[serde(rename = "userVerification")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
}

impl RegistrationBeginResponse {
    #[must_use]
    #[inline]
    pub fn builder() -> RegistrationBeginResponseBuilder {
        RegistrationBeginResponseBuilder::new()
    }
}

pub struct RegistrationBeginResponseBuilder {
    options: RegistrationBeginResponse,
}

impl Default for RegistrationBeginResponseBuilder {
    #[inline]
    fn default() -> Self {
        RegistrationBeginResponseBuilder::new()
    }
}

impl RegistrationBeginResponseBuilder {
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        RegistrationBeginResponseBuilder {
            options: RegistrationBeginResponse {
                response: PublicKeyCredentialRegistrationBeginResponse {
                    challenge: Base64EncodedUrl::new(Vec::new()),
                    rp: RelyingPartyRegistrationBeginResponse {
                        id: String::new(),
                        name: String::new(),
                    },
                    user: WebAuthnUser {
                        id: String::new(),
                        name: String::new(),
                        display_name: String::new(),
                    },
                    timeout: None,
                    parameters: Vec::new(),
                    excluded_credentials: None,
                    authenticator_selection: None,
                    hits: None,
                    attestation: None,
                    attestation_fmt: None,
                    extensions: None,
                },
                mediation: None,
            },
        }
    }

    #[must_use]
    #[inline]
    pub fn with_challenge(mut self, challenge: Base64EncodedUrl) -> Self {
        self.options.response.challenge = challenge;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_rp_id(mut self, rp_id: String) -> Self {
        self.options.response.rp.id = rp_id;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_rp_name(mut self, rp_name: String) -> Self {
        self.options.response.rp.name = rp_name;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_user(mut self, user: WebAuthnUser) -> Self {
        self.options.response.user = user;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_timeout(mut self, timeout: u32) -> Self {
        self.options.response.timeout = Some(timeout);
        self
    }

    #[must_use]
    #[inline]
    pub fn with_parameters(mut self, parameters: Vec<CredentialParameter>) -> Self {
        self.options.response.parameters = parameters;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_excluded_credentials(mut self, credentials: Option<Vec<CredentialDescriptor>>) -> Self {
        self.options.response.excluded_credentials = credentials;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_authenticator_selection(mut self, selection: AuthenticatorSelectionRegistrationBeginResponse) -> Self {
        self.options.response.authenticator_selection = Some(selection);
        self
    }

    #[must_use]
    #[inline]
    pub fn with_hints(mut self, hints: Option<Vec<PublicKeyCredentialHint>>) -> Self {
        self.options.response.hits = hints;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_attestation(mut self, attestation: Option<ConveyancePreference>) -> Self {
        self.options.response.attestation = attestation;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_attestation_fmt(mut self, attestation_fmt: Option<Vec<AttestationFormat>>) -> Self {
        self.options.response.attestation_fmt = attestation_fmt;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_extensions(mut self, extensions: Option<AuthenticationExtensions>) -> Self {
        self.options.response.extensions = extensions;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_mediation(mut self, mediation: Option<Mediation>) -> Self {
        self.options.mediation = mediation;
        self
    }

    #[inline]
    pub fn build(self) -> VeritasWebAuthnResult<RegistrationBeginResponse> {
        if self.options.response.challenge.len() < MIN_CHALLENGE_LEN {
            return Err(VeritasWebAuthnError::InvalidChallenge);
        }

        if self.options.response.rp.id.is_empty() {
            return Err(VeritasWebAuthnError::InvalidRpId);
        }

        if self.options.response.rp.name.is_empty() {
            return Err(VeritasWebAuthnError::InvalidRpName);
        }

        if self.options.response.user.id.is_empty() {
            return Err(VeritasWebAuthnError::InvalidUserId);
        }

        if self.options.response.parameters.is_empty() {
            return Err(VeritasWebAuthnError::InvalidCredentialParameters);
        }

        Ok(self.options)
    }
}
