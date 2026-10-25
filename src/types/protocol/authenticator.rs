use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthenticatorAttachment {
    #[serde(rename = "platform")]
    Platform,
    #[serde(rename = "cross-platform")]
    CrossPlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResidentKeyRequirement {
    #[serde(rename = "required")]
    Required,
    #[serde(rename = "preferred")]
    Preferred,
    #[serde(rename = "discouraged")]
    Discouraged,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
pub enum UserVerificationRequirement {
    #[serde(rename = "required")]
    Required,
    #[serde(rename = "preferred")]
    Preferred,
    #[serde(rename = "discouraged")]
    Discouraged,
}