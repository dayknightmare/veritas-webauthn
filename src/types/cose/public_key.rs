use crate::types::cose::algorithm::WebauthAlgorithm;
use crate::types::protocol::credential::CredentialParameter;
use crate::errors::{VeritasWebAuthnError, VeritasWebAuthnResult};
use cbor2::Cbor;

const MIN_RSA_MODULUS_LEN: usize = 256;
const MAX_RSA_MODULUS_LEN: usize = 1024;
const MAX_RSA_EXPONENT_LEN: usize = 8;

#[derive(Debug, Clone, Cbor)]
#[non_exhaustive]
pub struct PublicKeyData {
    #[cbor(key = 1)]
    pub key_type: i64,
    #[cbor(key = 3)]
    pub algorithm: i64,
    pub(crate) _data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Cbor)]
#[non_exhaustive]
struct EC2PublicKeyData {
    #[cbor(key = 1)]
    pub key_type: i64,
    #[cbor(key = 3)]
    pub algorithm: i64,
    #[cbor(key = -1)]
    pub curve: i64,
    #[cbor(key = -2)]
    pub x: Vec<u8>,
    #[cbor(key = -3)]
    pub y: Vec<u8>,
}

#[derive(Debug, Clone, Cbor)]
#[non_exhaustive]
struct RSAPublicKeyData {
    #[cbor(key = 1)]
    pub key_type: i64,
    #[cbor(key = 3)]
    pub algorithm: i64,
    #[cbor(key = -1)]
    pub modulus: Vec<u8>,
    #[cbor(key = -2)]
    pub exponent: Vec<u8>,
}

#[derive(Debug, Clone, Cbor)]
#[non_exhaustive]
struct OKPublicKeyData {
    #[cbor(key = 1)]
    pub key_type: i64,
    #[cbor(key = 3)]
    pub algorithm: i64,
    #[cbor(key = -1)]
    pub curve: i64,
    #[cbor(key = -2)]
    pub x: Vec<u8>,
}

#[non_exhaustive]
enum CoseKeyType {
    Octet = 1,
    Elliptic = 2,
    Rsa = 3,
    Akp = 4
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
enum CoseEllipticCurve {
    P256 = 1,
    P384 = 2,
    P521 = 3,
}

impl TryFrom<i64> for CoseEllipticCurve {
    type Error = VeritasWebAuthnError;

    #[inline]
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CoseEllipticCurve::P256),
            2 => Ok(CoseEllipticCurve::P384),
            3 => Ok(CoseEllipticCurve::P521),
            _ => Err(VeritasWebAuthnError::InvalidPublicKey),
        }
    }
}

impl TryFrom<i64> for CoseKeyType {
    type Error = VeritasWebAuthnError;

    #[inline]
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CoseKeyType::Octet),
            2 => Ok(CoseKeyType::Elliptic),
            3 => Ok(CoseKeyType::Rsa),
            4 => Ok(CoseKeyType::Akp),
            _ => Err(VeritasWebAuthnError::InvalidPublicKey),
        }
    }
}

impl TryFrom<Vec<u8>> for PublicKeyData {
    type Error = VeritasWebAuthnError;

    #[inline]
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let mut pk: PublicKeyData = cbor2::from_slice(&value).map_err(|_| VeritasWebAuthnError::InvalidPublicKey)?;
        pk._data = Some(value);

        Ok(pk)
    }
}

impl PublicKeyData {
    #[must_use]
    #[inline]
    pub fn is_public_key_allowed(&self, valid: Vec<CredentialParameter>) -> bool {
        let mut found = false;

        for alg in valid {
            if self.algorithm == alg.alg.to_i32() as i64 {
                found = true;
                break;
            }
        }

        found
    }

    #[inline]
    pub fn verify_key_type(&self) -> VeritasWebAuthnResult<()> {
        let value = self._data.clone().ok_or(VeritasWebAuthnError::InvalidPublicKey)?;
        let key = CoseKeyType::try_from(self.key_type)?;

        match key {
            CoseKeyType::Octet => self.parse_octet_key(value),
            CoseKeyType::Elliptic => self.parse_elliptic_key(value),
            CoseKeyType::Rsa => self.parse_rsa_key(value),
            _ => Err(VeritasWebAuthnError::UnsupportedPublicKey),
        }
    }

    #[inline]
    fn parse_octet_key(&self, value: Vec<u8>) -> VeritasWebAuthnResult<()> {
        let pk: OKPublicKeyData = cbor2::from_slice(&value).map_err(|_| VeritasWebAuthnError::InvalidPublicKey)?;
        let alg = WebauthAlgorithm::try_from(pk.algorithm as i32)?;

        match alg {
            WebauthAlgorithm::AlgEdDSA => {
                if pk.curve != 6 || pk.x.len() != 32 {
                    return Err(VeritasWebAuthnError::InvalidPublicKey);
                }

                Ok(())
            },
            _ => Err(VeritasWebAuthnError::UnsupportedPublicKey),
        }
    }

    #[inline]
    fn parse_elliptic_key(&self, value: Vec<u8>) -> VeritasWebAuthnResult<()> {
        let pk: EC2PublicKeyData = cbor2::from_slice(&value)
            .map_err(|_| VeritasWebAuthnError::InvalidPublicKey)?;
        let alg = WebauthAlgorithm::try_from(pk.algorithm as i32)?;
        let curve = CoseEllipticCurve::try_from(pk.curve)?;

        let (expected_curve, coordinate_len) = match alg {
            WebauthAlgorithm::AlgES256 => (CoseEllipticCurve::P256, 32),
            WebauthAlgorithm::AlgES384 => (CoseEllipticCurve::P384, 48),
            WebauthAlgorithm::AlgES512 => (CoseEllipticCurve::P521, 66),
            _ => return Err(VeritasWebAuthnError::UnsupportedPublicKey),
        };

        if curve != expected_curve || pk.x.len() != coordinate_len || pk.y.len() != coordinate_len {
            return Err(VeritasWebAuthnError::InvalidPublicKey);
        }

        Ok(())
    }

    #[inline]
    fn parse_rsa_key(&self, value: Vec<u8>) -> VeritasWebAuthnResult<()> {
        let pk: RSAPublicKeyData = cbor2::from_slice(&value).map_err(|_| VeritasWebAuthnError::InvalidPublicKey)?;
        let alg = WebauthAlgorithm::try_from(pk.algorithm as i32)?;

        match alg {
            WebauthAlgorithm::AlgRS256
            | WebauthAlgorithm::AlgRS384
            | WebauthAlgorithm::AlgRS512
            | WebauthAlgorithm::AlgPS256
            | WebauthAlgorithm::AlgPS384
            | WebauthAlgorithm::AlgPS512 => {},
            _ => return Err(VeritasWebAuthnError::UnsupportedPublicKey),
        }

        if pk.modulus.len() < MIN_RSA_MODULUS_LEN || pk.modulus.len() > MAX_RSA_MODULUS_LEN {
            return Err(VeritasWebAuthnError::InvalidPublicKey);
        }

        if pk.modulus[0] & 0x80 == 0 {
            return Err(VeritasWebAuthnError::InvalidPublicKey);
        }

        if pk.exponent.is_empty() || pk.exponent.len() > MAX_RSA_EXPONENT_LEN || pk.exponent[0] == 0 {
            return Err(VeritasWebAuthnError::InvalidPublicKey);
        }

        let least_significant = pk.exponent[pk.exponent.len() - 1];

        if least_significant & 1 == 0 || (pk.exponent.len() == 1 && least_significant < 3) {
            return Err(VeritasWebAuthnError::InvalidPublicKey);
        }

        Ok(())
    }
}