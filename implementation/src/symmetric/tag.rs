use super::*;
use crate::array_output::*;
use crate::types as guest_types;
use crate::{CryptoCtx, WasiCryptoCtx};

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
    ) -> Result<Handle, CryptoError> {
        let symmetric_tag = self.handles.symmetric_tag.get(symmetric_tag_handle)?;
        let array_output_handle =
            ArrayOutput::register(&self.handles, symmetric_tag.as_ref().to_vec())?;
        Ok(array_output_handle)
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

impl WasiCryptoCtx {
    pub fn symmetric_tag_export(
        &self,
        symmetric_tag_handle: guest_types::SymmetricTag,
    ) -> Result<guest_types::ArrayOutput, CryptoError> {
        Ok(self
            .ctx
            .symmetric_tag_export(symmetric_tag_handle.into())?
            .into())
    }

    pub fn symmetric_tag_verify(
        &self,
        symmetric_tag_handle: guest_types::SymmetricTag,
        expected_raw_ptr: &wiggle::GuestPtr<'_, u8>,
        expected_raw_len: guest_types::Size,
    ) -> Result<(), CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
        let expected_raw: &[u8] = unsafe {
            &*expected_raw_ptr
                .as_array(expected_raw_len as _)
                .as_raw(&mut guest_borrow)?
        };
        Ok(self
            .ctx
            .symmetric_tag_verify(symmetric_tag_handle.into(), expected_raw)?
            .into())
    }

    pub fn symmetric_tag_close(
        &self,
        symmetric_tag_handle: guest_types::SymmetricTag,
    ) -> Result<(), CryptoError> {
        Ok(self
            .ctx
            .symmetric_tag_close(symmetric_tag_handle.into())?
            .into())
    }
}
