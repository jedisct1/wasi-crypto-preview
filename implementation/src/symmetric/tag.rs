use super::*;

use zeroize::Zeroize;

#[derive(Debug, Clone, Eq)]
pub struct SymmetricTag {
    alg: SymmetricAlgorithm,
    raw: Vec<u8>,
}

impl PartialEq for SymmetricTag {
    fn eq(&self, other: &Self) -> bool {
        self.alg == other.alg
            && ring::constant_time::verify_slices_are_equal(&self.raw, &other.raw).is_ok()
    }
}

impl Drop for SymmetricTag {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

impl SymmetricTag {
    pub fn new(alg: SymmetricAlgorithm, raw: Vec<u8>) -> Self {
        SymmetricTag { alg, raw }
    }

    pub fn verify(&self, other_raw: &[u8]) -> Result<(), CryptoError> {
        ring::constant_time::verify_slices_are_equal(&self.raw, other_raw)
            .map_err(|_| CryptoError::InvalidTag)
    }
}

impl AsRef<[u8]> for SymmetricTag {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}
