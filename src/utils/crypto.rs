use sha2::{Digest, Sha256};

#[must_use]
#[inline]
pub fn sha256_encrypt(value: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(value);

    hasher.finalize().to_vec()
}

