use crate::errors::{VeritasWebAuthnError, VeritasWebAuthnResult};
use crate::types::protocol::webauthn::{CeremonyType, TokenBinding};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct ClientDataJSON {
    #[serde(rename = "type")]
    pub kind: CeremonyType,
    pub challenge: String,
    pub origin: String,
    #[serde(rename = "topOrigin")]
    pub top_origin: Option<String>,
    #[serde(rename = "crossOrigin")]
    pub cross_origin: Option<bool>,
    #[serde(rename = "tokenBinding")]
    pub token_binding: Option<TokenBinding>,
}

impl TryFrom<String> for ClientDataJSON {
    type Error = VeritasWebAuthnError;

    #[inline]
    fn try_from(value: String) -> VeritasWebAuthnResult<Self> {
        serde_json::from_str(&value).map_err(|_| VeritasWebAuthnError::InvalidClientDataJson)
    }
}