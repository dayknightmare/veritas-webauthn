use crate::types::base64_encoded_url::Base64EncodedUrl;
use crate::types::protocol::authenticator_data::{AttestedCredentialData, AuthenticatorData};
use crate::errors::{VeritasWebAuthnError, VeritasWebAuthnResult};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

const MIN_AUTH_DATA_LENGTH: usize = 37;
const MIN_ATTESTED_AUTH_LENGTH: usize = 55;
pub(crate) const MAX_CREDENTIAL_ID_LENGTH: usize = 1023;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
pub enum AttestationFormat {
    #[serde(rename = "packed")]
    Packed,
    #[serde(rename = "tpm")]
    TPM,
    #[serde(rename = "android-key")]
    AndroidKey,
    #[serde(rename = "android-safetynet")]
    AndroidSafetyNet,
    #[serde(rename = "fido-u2f")]
    FIDOU2F,
    #[serde(rename = "apple")]
    Apple,
    #[serde(rename = "compound")]
    Compound,
    #[serde(rename = "none")]
    None,
}

impl From<String> for AttestationFormat {
    #[inline]
    fn from(value: String) -> Self {
        match value.as_str() {
            "packed" => AttestationFormat::Packed,
            "tpm" => AttestationFormat::TPM,
            "android-key" => AttestationFormat::AndroidKey,
            "android-safetynet" => AttestationFormat::AndroidSafetyNet,
            "fido-u2f" => AttestationFormat::FIDOU2F,
            "apple" => AttestationFormat::Apple,
            "compound" => AttestationFormat::Compound,
            _ => AttestationFormat::None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConveyancePreference {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "indirect")]
    Indirect,
    #[serde(rename = "direct")]
    Direct,
    #[serde(rename = "enterprise")]
    Enterprise
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AttestationObject {
    pub fmt: String,
    pub att_stmt: serde_json::Value,
    pub auth_data: Vec<u8>,
    pub auth_data_parsed: Option<AuthenticatorData>,
    pub(crate) _ep_att: Option<bool>,
    pub(crate) _large_blob_key: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[non_exhaustive]
pub(crate) struct AuthenticatorDataCborRaw {
    pub(crate) rp_id_hash: [u8; 32],
    pub(crate) counter: u32,
    pub(crate) flags: u8,
    pub(crate) attested_credential_data: AttestedCredentialDataCborRaw,
    pub(crate) extensions: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[non_exhaustive]
pub(crate) struct AttestedCredentialDataCborRaw {
    pub(crate) aaguid: [u8; 16],
    pub(crate) credential_id: Vec<u8>,
    pub(crate) credential_pk: Vec<u8>,
}

impl TryFrom<Base64EncodedUrl> for AttestationObject {
    type Error = VeritasWebAuthnError;

    #[inline]
    fn try_from(value: Base64EncodedUrl) -> Result<Self, Self::Error> {
        let mut obj = AttestationObject::from_bytes(value.to_vec()).map_err(|_| VeritasWebAuthnError::InvalidAttestationObject)?;
        let auth_data = obj.parse_auth_data()?;

        obj.auth_data_parsed = Some(AuthenticatorData{
            rp_id_hash: Base64EncodedUrl::new(auth_data.rp_id_hash.to_vec()),
            flags: auth_data.flags,
            sign_count: auth_data.counter,
            attested_credential_data: AttestedCredentialData{
                aaguid: Base64EncodedUrl::new(auth_data.attested_credential_data.aaguid.to_vec()),
                credential_id: Base64EncodedUrl::new(auth_data.attested_credential_data.credential_id.to_vec()),
                credential_public_key: Base64EncodedUrl::new(auth_data.attested_credential_data.credential_pk.to_vec()),
            },
            extensions: auth_data.extensions,
        });
        Ok(obj)
    }
}

impl AttestationObject {

    #[inline]
    pub fn from_bytes(data: Vec<u8>) -> VeritasWebAuthnResult<Self> {
        let result: Self = cbor2::from_slice(&data).map_err(|_| VeritasWebAuthnError::InvalidAttestationObject)?;
        Ok(result)
    }

    #[inline]
    fn parse_auth_data(&self) -> VeritasWebAuthnResult<AuthenticatorDataCborRaw> {
        let data = self.auth_data.clone().to_vec();

        if data.len() < MIN_AUTH_DATA_LENGTH {
            return Err(VeritasWebAuthnError::AuthDataTooShort);
        }

        let rp_id_hash = data[..32].try_into().map_err(|_| VeritasWebAuthnError::AuthDataTooShort)?;
        let counter = u32::from_be_bytes(data[33..37].try_into().map_err(|_| VeritasWebAuthnError::AuthDataTooShort)?);
        let (attested, extension_data, flags) = self.collect_flags(&data)?;
        let mut rest = data.len() - MIN_AUTH_DATA_LENGTH;

        let mut result = AuthenticatorDataCborRaw{
            rp_id_hash,
            counter,
            flags,
            attested_credential_data: AttestedCredentialDataCborRaw{
                aaguid: [0; 16],
                credential_id: vec![],
                credential_pk: vec![],
            },
            extensions: None,
        };

        if attested {
            let (new_rest, attested_credential_data) = self.parse_attested_credential_data(rest, &data)?;
            rest = new_rest;
            if let Some(attested_credential_data) = attested_credential_data {
                result.attested_credential_data = attested_credential_data;
            }
        } else if !extension_data && data.len() != 37 {
            return Err(VeritasWebAuthnError::InvalidCredentialFlags);
        }

        if extension_data {
            if rest == 0 {
                return Err(VeritasWebAuthnError::AuthDataInvalidLength);
            }

            result.extensions = Some(data[data.len() - rest..].to_vec());
        }

        if rest > 0 {
            return Err(VeritasWebAuthnError::AuthDataInvalidLength);
        }

        Ok(result)
    }

    #[inline]
    fn collect_flags(&self, data: &[u8]) -> VeritasWebAuthnResult<(bool, bool, u8)> {
        let flags = data[32];

        let attested = (flags & 0x40) != 0;         // flag 64
        let extension_data = (flags & 0x80) != 0;   // flag 128

        Ok((attested, extension_data, flags))
    }

    #[inline]
    fn parse_attested_credential_data(&self, mut rest: usize, data: &[u8]) -> VeritasWebAuthnResult<(usize, Option<AttestedCredentialDataCborRaw>)> {
        if rest < MIN_ATTESTED_AUTH_LENGTH {
            return Err(VeritasWebAuthnError::AuthDataTooShort);
        }

        let aaguid = data[37..53].try_into().map_err(|_| VeritasWebAuthnError::AuthDataAaguidMismatch)?;
        let idlen = u16::from_be_bytes(data[53..55].try_into().map_err(|_| VeritasWebAuthnError::AuthDataIdLengthMismatch)?);

        if idlen > MAX_CREDENTIAL_ID_LENGTH as u16 {
            return Err(VeritasWebAuthnError::AuthDataInvalidLength);
        }

        if data.len() < 55 + idlen as usize {
            return Err(VeritasWebAuthnError::AuthDataTooShort);
        }

        let id = <&[u8] as Into<Vec<u8>>>::into(&data[55..55 + idlen as usize]);
        let pk = &data[55 + idlen as usize..];

        let (key_size, _) = self.cbor_parser(pk).map_err(|_| VeritasWebAuthnError::AuthDataInvalidLength)?;

        rest -= 16 + 2 + idlen as usize + key_size;

        Ok((rest, Some(AttestedCredentialDataCborRaw{
            aaguid,
            credential_id: id,
            credential_pk: pk.to_vec(),
        })))
    }

    #[inline]
    fn cbor_parser(&self, i: &[u8]) -> VeritasWebAuthnResult<(usize, cbor2::Value)> {
        let mut cursor = Cursor::new(i);

        match cbor2::from_reader::<cbor2::Value, _>(&mut cursor) {
            Ok(value) => Ok((cursor.position() as usize, value)),
            Err(_) => Err(VeritasWebAuthnError::AuthDataInvalidLength),
        }
    }
}
