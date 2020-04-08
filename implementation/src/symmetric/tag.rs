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

    pub fn verify(&self, expected_raw: &[u8]) -> Result<(), CryptoError> {
        ring::constant_time::verify_slices_are_equal(&self.raw, expected_raw)
            .map_err(|_| CryptoError::InvalidTag)
    }
}

impl AsRef<[u8]> for SymmetricTag {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl CryptoCtx {
    pub fn symmetric_tag_export(
        &self,
        symmetric_tag_handle: Handle,
    ) -> Result<Vec<u8>, CryptoError> {
        let symmetric_tag = self.handles.symmetric_tag.get(symmetric_tag_handle)?;
        let raw = symmetric_tag.as_ref().to_vec();
        Ok(raw)
    }

    pub fn symmetric_tag_verify(
        &self,
        symmetric_tag_handle: Handle,
        expected_raw: &[u8],
    ) -> Result<(), CryptoError> {
        let symmetric_tag = self.handles.symmetric_tag.get(symmetric_tag_handle)?;
        symmetric_tag.verify(expected_raw)
    }

    pub fn symmetric_tag_close(&self, symmetric_tag_handle: Handle) -> Result<(), CryptoError> {
        self.handles.symmetric_tag.close(symmetric_tag_handle)
    }
}
