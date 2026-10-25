use crate::errors::VeritasWebAuthnError;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, Copy)]
#[repr(i32)]
#[non_exhaustive]
pub enum WebauthAlgorithm {
    AlgES256 = -7,
    AlgEdDSA = -8,
    AlgES384 = -35,
    AlgES512 = -36,
    AlgPS256 = -37,
    AlgPS384 = -38,
    AlgPS512 = -39,
    AlgRS256 = -257,
    AlgRS384 = -258,
    AlgRS512 = -259,
}

impl WebauthAlgorithm {
    pub const ALL: [WebauthAlgorithm; 10] = [
        WebauthAlgorithm::AlgES256,
        WebauthAlgorithm::AlgEdDSA,
        WebauthAlgorithm::AlgES384,
        WebauthAlgorithm::AlgES512,
        WebauthAlgorithm::AlgPS256,
        WebauthAlgorithm::AlgPS384,
        WebauthAlgorithm::AlgPS512,
        WebauthAlgorithm::AlgRS256,
        WebauthAlgorithm::AlgRS384,
        WebauthAlgorithm::AlgRS512,
    ];
    
    #[inline]
    pub fn iter() -> impl Iterator<Item = WebauthAlgorithm> {
        Self::ALL.iter().copied()
    }

    #[must_use]
    #[inline]
    pub fn to_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for WebauthAlgorithm {
    type Error = VeritasWebAuthnError;

    #[inline]
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            -7 => Ok(WebauthAlgorithm::AlgES256),
            -8 => Ok(WebauthAlgorithm::AlgEdDSA),
            -35 => Ok(WebauthAlgorithm::AlgES384),
            -36 => Ok(WebauthAlgorithm::AlgES512),
            -37 => Ok(WebauthAlgorithm::AlgPS256),
            -38 => Ok(WebauthAlgorithm::AlgPS384),
            -39 => Ok(WebauthAlgorithm::AlgPS512),
            -257 => Ok(WebauthAlgorithm::AlgRS256),
            -258 => Ok(WebauthAlgorithm::AlgRS384),
            -259 => Ok(WebauthAlgorithm::AlgRS512),
            _ => Err(VeritasWebAuthnError::InvalidAlgorithm),
        }
    }
}

impl Serialize for WebauthAlgorithm {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i32(*self as i32)
    }
}

impl<'de> Deserialize<'de> for WebauthAlgorithm {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    
    where
        D: serde::Deserializer<'de>,
    {
        let value = i32::deserialize(deserializer)?;
        WebauthAlgorithm::try_from(value)
            .map_err(|_| serde::de::Error::custom("Invalid WebauthAlgorithm"))
    }
}