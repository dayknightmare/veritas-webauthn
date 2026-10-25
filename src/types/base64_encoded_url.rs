use core::fmt;
use std::fmt::{Display, Formatter};
use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::errors::{VeritasWebAuthnError, VeritasWebAuthnResult};

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub struct Base64EncodedUrl(Vec<u8>);

impl Base64EncodedUrl {
    #[must_use]
    #[inline]
    pub fn new(base64_encoded_url: Vec<u8>) -> Base64EncodedUrl {
        Base64EncodedUrl(base64_encoded_url)
    }

    #[must_use]
    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    #[inline]
    pub fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.as_slice())
    }

    #[inline]
    pub fn from_string(s: String) -> VeritasWebAuthnResult<Base64EncodedUrl> {
        match URL_SAFE_NO_PAD.decode(s.as_bytes()) {
            Ok(e) => Ok(Base64EncodedUrl(e)),
            Err(_) => Err(VeritasWebAuthnError::InvalidBase64EncodedUrl),
        }
    }
}

impl Display for Base64EncodedUrl {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", String::from_utf8(self.0.clone()).unwrap_or_else(|_| String::new()))
    }
}

impl AsRef<[u8]> for Base64EncodedUrl {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for Base64EncodedUrl {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = URL_SAFE_NO_PAD.encode(self);
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for Base64EncodedUrl {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {
        let decoded = String::deserialize(deserializer)?;
        let decoded = URL_SAFE_NO_PAD.decode(decoded.as_bytes()).map_err(serde::de::Error::custom)?;
        Ok(Base64EncodedUrl(decoded))
    }
}