use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Mediation {
    #[serde(rename = "silent")]
    Silent,
    #[serde(rename = "optional")]
    Optional,
    #[serde(rename = "conditional")]
    Conditional,
    #[serde(rename = "required")]
    Required,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CeremonyType {
    #[serde(rename = "webauthn.create")]
    Create,
    #[serde(rename = "webauthn.get")]
    Get,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub enum TokenBindingStatus {
    #[serde(rename = "present")]
    Present,
    #[serde(rename = "supported")]
    Supported,
    #[serde(rename = "sct")]
    SCT,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct TokenBinding {
    pub status: Option<TokenBindingStatus>,
    pub id: Option<String>,
}