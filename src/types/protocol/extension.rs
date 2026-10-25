use crate::types::base64_encoded_url::Base64EncodedUrl;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuthenticationExtensions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appid: Option<String>,

    #[serde(rename = "appidExclude")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appid_exclude: Option<String>,

    #[serde(rename = "credProps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,

    pub prf: Option<PRF>,
    #[serde(rename = "remoteClientDataJSON")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_client_data_json: Option<String>,

    #[serde(rename = "enforceCredentialProtectionPolicy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforce_credential_protection_policy: Option<bool>,

    #[serde(rename = "hmacCreateSecret")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_create_secret: Option<bool>,

    #[serde(rename = "getCredBlob")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_cred_blob: Option<bool>,

    #[serde(rename = "minPinLength")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<bool>,

    #[serde(rename = "largeBlob")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<LargeBlob>,

    #[serde(rename = "credentialProtectionPolicy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_protection_policy: Option<CredentialProtectionPolicy>,

    #[serde(rename = "credBlob")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_blob: Option<Base64EncodedUrl>,

    #[serde(rename = "hmacGetSecret")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_get_secret: Option<HMACGetSecret>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
pub enum LargeBlobValues {
    #[serde(rename = "required")]
    Required,
    #[serde(rename = "preferred")]
    Preferred,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LargeBlob {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support: Option<LargeBlobValues>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub read: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub write: Option<Base64EncodedUrl>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PRFValues {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<Base64EncodedUrl>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub second: Option<Base64EncodedUrl>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PRF {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eval: Option<PRFValues>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub eval_by_credential: Option<HashMap<String, PRFValues>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
pub enum CredentialProtectionPolicy {
    #[serde(rename = "userVerificationRequired")]
    UserVerificationRequired,
    #[serde(rename = "userVerificationOptional")]
    UserVerificationOptional,
    #[serde(rename = "userVerificationOptionalWithCredentialIDList")]
    UserVerificationOptionalWithCredentialIDList,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HMACGetSecret {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt1: Option<Base64EncodedUrl>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt2: Option<Base64EncodedUrl>,
}