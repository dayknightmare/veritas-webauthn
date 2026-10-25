use crate::types::base64_encoded_url::Base64EncodedUrl;
use crate::types::protocol::attestation::AttestationFormat;
use crate::types::protocol::authenticator::AuthenticatorAttachment;
use crate::types::protocol::transport::Transport;
use crate::types::protocol::attestation::MAX_CREDENTIAL_ID_LENGTH;
use crate::types::protocol::authenticator_data::AuthenticatorData;
use crate::errors::{VeritasWebAuthnError, VeritasWebAuthnResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Credential {
    pub id: Base64EncodedUrl,
    #[serde(rename = "publicKey")]
    pub public_key: Base64EncodedUrl,
    // #[serde(rename = "attestationType")]
    // pub attestation_type: String, // TODO
    #[serde(rename = "attestationFormat")]
    pub attestation_format: AttestationFormat,
    pub transport: Vec<Transport>,
    pub flags: CredentialFlags,
    pub authenticator: Authenticator,
    pub attestation: Attestation,
    // pub extensions: asdsd //TODO
}

#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CredentialFlags {
    pub user_present: bool,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub raw: u8,
}

#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Authenticator {
    pub aaguid: Base64EncodedUrl,
    #[serde(rename = "signCount")]
    pub sign_count: u32,
    #[serde(rename = "cloneWarning")]
    pub clone_warning: bool,
    pub attachment: AuthenticatorAttachment
}

#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Attestation {
    pub client_data_json: Base64EncodedUrl,
    pub client_data_hash: Base64EncodedUrl,
    pub authenticator_data: Base64EncodedUrl,
    pub public_key_algorithm: i32,
}

const AAGUID_LENGTH: usize = 16;

impl From<&AuthenticatorData> for CredentialFlags {
    #[inline]
    fn from(auth_data: &AuthenticatorData) -> Self {
        CredentialFlags {
            user_present: auth_data.has_user_presence(),
            user_verified: auth_data.has_user_verified(),
            backup_eligible: auth_data.has_backup_eligibility(),
            backup_state: auth_data.has_backup_state(),
            raw: auth_data.flags,
        }
    }
}

impl Credential {
    #[must_use]
    #[inline]
    pub fn builder() -> CredentialBuilder {
        CredentialBuilder::new()
    }
}

pub struct CredentialBuilder {
    id: Base64EncodedUrl,
    public_key: Base64EncodedUrl,
    attestation_format: AttestationFormat,
    transport: Vec<Transport>,
    flags: CredentialFlags,
    authenticator: Option<Authenticator>,
    attestation: Option<Attestation>,
}

impl Default for CredentialBuilder {
    #[inline]
    fn default() -> Self {
        CredentialBuilder::new()
    }
}

impl CredentialBuilder {
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        CredentialBuilder {
            id: Base64EncodedUrl::new(Vec::new()),
            public_key: Base64EncodedUrl::new(Vec::new()),
            attestation_format: AttestationFormat::None,
            transport: Vec::new(),
            flags: CredentialFlags {
                user_present: false,
                user_verified: false,
                backup_eligible: false,
                backup_state: false,
                raw: 0,
            },
            authenticator: None,
            attestation: None,
        }
    }

    #[must_use]
    #[inline]
    pub fn with_id(mut self, id: Base64EncodedUrl) -> Self {
        self.id = id;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_public_key(mut self, public_key: Base64EncodedUrl) -> Self {
        self.public_key = public_key;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_attestation_format(mut self, attestation_format: AttestationFormat) -> Self {
        self.attestation_format = attestation_format;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_transport(mut self, transport: Vec<Transport>) -> Self {
        self.transport = transport;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_flags(mut self, flags: CredentialFlags) -> Self {
        self.flags = flags;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_authenticator(mut self, authenticator: Authenticator) -> Self {
        self.authenticator = Some(authenticator);
        self
    }

    #[must_use]
    #[inline]
    pub fn with_attestation(mut self, attestation: Attestation) -> Self {
        self.attestation = Some(attestation);
        self
    }

    #[inline]
    pub fn build(self) -> VeritasWebAuthnResult<Credential> {
        if self.id.is_empty() || self.id.len() > MAX_CREDENTIAL_ID_LENGTH {
            return Err(VeritasWebAuthnError::InvalidCredentialId);
        }

        if self.public_key.is_empty() {
            return Err(VeritasWebAuthnError::InvalidCredentialPublicKey);
        }

        if self.flags.backup_state && !self.flags.backup_eligible {
            return Err(VeritasWebAuthnError::InvalidBackupState);
        }

        let authenticator = self.authenticator.ok_or(VeritasWebAuthnError::InvalidAuthenticator)?;

        if authenticator.aaguid.len() != AAGUID_LENGTH {
            return Err(VeritasWebAuthnError::InvalidAaguid);
        }

        let attestation = self.attestation.ok_or(VeritasWebAuthnError::InvalidAttestationObject)?;

        Ok(Credential {
            id: self.id,
            public_key: self.public_key,
            attestation_format: self.attestation_format,
            transport: self.transport,
            flags: self.flags,
            authenticator,
            attestation,
        })
    }
}
