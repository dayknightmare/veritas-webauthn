use crate::types::base64_encoded_url::Base64EncodedUrl;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct AuthenticatorData {
    #[serde(rename = "rpIdHash")]
    pub rp_id_hash: Base64EncodedUrl,

    pub flags: u8,
    pub sign_count: u32,

    #[serde(rename = "att_data")]
    pub attested_credential_data: AttestedCredentialData,

    #[serde(rename = "ext")]
    pub extensions: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct AttestedCredentialData {
    pub aaguid: Base64EncodedUrl,
    pub credential_id: Base64EncodedUrl,
    pub credential_public_key: Base64EncodedUrl,
}

impl AuthenticatorData {
    #[must_use]
    #[inline]
    pub fn has_user_presence(&self) -> bool {
        self.flags & 0x01 != 0
    }

    #[must_use]
    #[inline]
    pub fn has_user_verified(&self) -> bool {
        self.flags & 0x04 != 0
    }

    #[must_use]
    #[inline]
    pub fn has_backup_eligibility(&self) -> bool {
        self.flags & 0x08 != 0
    }

    #[must_use]
    #[inline]
    pub fn has_backup_state(&self) -> bool {
        self.flags & 0x10 != 0
    }

    #[must_use]
    #[inline]
    pub fn has_attested_credential_data(&self) -> bool {
        self.flags & 0x40 != 0
    }

    #[must_use]
    #[inline]
    pub fn has_extensions(&self) -> bool {
        self.flags & 0x80 != 0
    }
}