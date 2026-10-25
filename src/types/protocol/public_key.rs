use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
pub enum PublicKeyCredentialHint {
    #[serde(rename = "security-key")]
    SecurityKey,
    #[serde(rename = "client-device")]
    ClientDevice,
    #[serde(rename = "hybrid")]
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
pub enum CredentialParameterType {
    #[serde(rename = "public-key")]
    PublicKey,
}