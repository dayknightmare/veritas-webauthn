use crate::types::cose::algorithm::WebauthAlgorithm;
use crate::types::base64_encoded_url::Base64EncodedUrl;
use crate::types::protocol::attestation::AttestationObject;
use crate::types::protocol::authenticator::AuthenticatorAttachment;
use crate::types::protocol::client_data_json::ClientDataJSON;
use crate::types::protocol::extension::{HMACGetSecret, LargeBlob, PRF};
use crate::types::protocol::transport::Transport;
use crate::errors::VeritasWebAuthnError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RegistrationFinishRequest {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(rename = "rawId")]
    pub raw_id: Base64EncodedUrl,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: AuthenticatorAttachment,
    #[serde(rename = "clientExtensionResults")]
    pub client_extension_results: Option<AuthenticationExtensionsClientOutputsRegistrationFinishRequest>,
    pub response: ResponseRegistrationFinishRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuthenticationExtensionsClientOutputsRegistrationFinishRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appid: Option<String>,

    #[serde(rename = "appidExclude")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appid_exclude: Option<String>,

    #[serde(rename = "credProps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<CredProps>,

    pub prf: Option<PRF>,

    #[serde(rename = "remoteClientDataJSON")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_client_data_json: Option<String>,

    #[serde(rename = "hmacCreateSecret")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_create_secret: Option<bool>,

    #[serde(rename = "largeBlob")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<LargeBlob>,

    #[serde(rename = "hmacGetSecret")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_get_secret: Option<HMACGetSecret>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CredProps {
    pub rk: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ResponseRegistrationFinishRequest {
    pub transports: Option<Vec<Transport>>,

    #[serde(rename = "authenticatorData")]
    pub authenticator_data: Option<Base64EncodedUrl>,

    #[serde(rename = "publicKey")]
    pub public_key: Option<Base64EncodedUrl>,

    #[serde(rename = "publicKeyAlgorithm")]
    pub public_key_algorithm: Option<WebauthAlgorithm>,

    #[serde(rename = "attestationObject")]
    pub attestation_object: Base64EncodedUrl,

    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Base64EncodedUrl,
}

#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct RegistrationFinishRequestParsed {
    pub id: String,
    pub kind: String,
    pub raw_id: Base64EncodedUrl,
    pub authenticator_attachment: AuthenticatorAttachment,
    pub client_extension_results: Option<AuthenticationExtensionsClientOutputsRegistrationFinishRequest>,
    pub response: ResponseRegistrationFinishRequestParsed,
}

#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct ResponseRegistrationFinishRequestParsed {
    pub client_data: ClientDataJSON,
    pub raw_client_data_json: Base64EncodedUrl,
    pub attestation_object: AttestationObject,
    pub transports: Vec<Transport>,
}

impl TryFrom<RegistrationFinishRequest> for RegistrationFinishRequestParsed {
    type Error = VeritasWebAuthnError;

    #[inline]
    fn try_from(response: RegistrationFinishRequest) -> Result<Self, Self::Error> {
        let client_data_json = ClientDataJSON::try_from(response.response.client_data_json.to_string())?;
        let attestation_object = AttestationObject::try_from(response.response.attestation_object)?;

        Ok(RegistrationFinishRequestParsed {
            id: response.id,
            kind: response.kind,
            raw_id: response.raw_id,
            authenticator_attachment: response.authenticator_attachment,
            client_extension_results: response.client_extension_results,
            response: ResponseRegistrationFinishRequestParsed {
                client_data: client_data_json,
                attestation_object,
                raw_client_data_json: response.response.client_data_json,
                transports: response.response.transports.unwrap_or_default(),
            },
        })
    }
}