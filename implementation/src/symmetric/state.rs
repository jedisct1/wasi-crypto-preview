use super::*;
use crate::types as guest_types;
use crate::{CryptoCtx, WasiCryptoCtx};

use std::convert::TryFrom;

pub trait SymmetricAlgorithmStateLike {
    fn alg(&self) -> SymmetricAlgorithm;

    fn absorb(&mut self, _data: &[u8]) -> Result<(), CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }

    fn squeeze(&mut self, _out: &mut [u8]) -> Result<(), CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }

    fn squeeze_key(&mut self, _len: usize) -> Result<Vec<u8>, CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }

    fn squeeze_tag(&mut self) -> Result<SymmetricTag, CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }

    fn max_tag_len(&mut self) -> Result<usize, CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }

    fn encrypt(&mut self, _out: &mut [u8], _data: &[u8]) -> Result<usize, CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }

    fn encrypt_detached(
        &mut self,
        _out: &mut [u8],
        _data: &[u8],
    ) -> Result<SymmetricTag, CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }

    fn decrypt(&mut self, _out: &mut [u8], _data: &[u8]) -> Result<usize, CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }

    fn decrypt_detached(
        &mut self,
        _out: &mut [u8],
        _data: &[u8],
        _raw_tag: &[u8],
    ) -> Result<usize, CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }

    fn ratchet(&mut self) -> Result<Vec<u8>, CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }
}

#[derive(Clone, Debug)]
pub enum SymmetricState {
    HmacSha2(HmacSha2SymmetricState),
    Sha2(Sha2SymmetricState),
    AesGcm(AesGcmSymmetricState),
}

impl SymmetricState {
    pub fn alg(self) -> SymmetricAlgorithm {
        match self {
            SymmetricState::HmacSha2(op) => op.alg,
            SymmetricState::Sha2(op) => op.alg,
            SymmetricState::AesGcm(op) => op.alg,
        }
    }

    fn open(
        alg_str: &str,
        key: Option<SymmetricKey>,
        options: Option<SymmetricOptions>,
    ) -> Result<SymmetricState, CryptoError> {
        let alg = SymmetricAlgorithm::try_from(alg_str)?;
        if let Some(ref key) = key {
            ensure!(key.alg() == alg, CryptoError::InvalidKey);
        }
        let symmetric_state = match alg {
            SymmetricAlgorithm::HmacSha256 | SymmetricAlgorithm::HmacSha512 => {
                SymmetricState::HmacSha2(HmacSha2SymmetricState::new(alg, key, options)?)
            }
            SymmetricAlgorithm::Sha256
            | SymmetricAlgorithm::Sha512
            | SymmetricAlgorithm::Sha512_256 => {
                SymmetricState::Sha2(Sha2SymmetricState::new(alg, None, options)?)
            }
            SymmetricAlgorithm::Aes128Gcm | SymmetricAlgorithm::Aes256Gcm => {
                SymmetricState::AesGcm(AesGcmSymmetricState::new(alg, key, options)?)
            }
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        };
        Ok(symmetric_state)
    }

    fn absorb(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            SymmetricState::Sha2(state) => state.absorb(data)?,
            SymmetricState::HmacSha2(state) => state.absorb(data)?,
            SymmetricState::AesGcm(state) => state.absorb(data)?,
        };
        Ok(())
    }

    fn squeeze(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        let out = match self {
            SymmetricState::Sha2(state) => state.squeeze(out)?,
            SymmetricState::HmacSha2(state) => state.squeeze(out)?,
            SymmetricState::AesGcm(state) => state.squeeze(out)?,
        };
        Ok(out)
    }

    fn squeeze_tag(&mut self) -> Result<SymmetricTag, CryptoError> {
        let tag = match self {
            SymmetricState::Sha2(state) => state.squeeze_tag()?,
            SymmetricState::HmacSha2(state) => state.squeeze_tag()?,
            SymmetricState::AesGcm(state) => state.squeeze_tag()?,
        };
        Ok(tag)
    }

    fn max_tag_len(&mut self) -> Result<usize, CryptoError> {
        let tag = match self {
            SymmetricState::Sha2(state) => state.max_tag_len()?,
            SymmetricState::HmacSha2(state) => state.max_tag_len()?,
            SymmetricState::AesGcm(state) => state.max_tag_len()?,
        };
        Ok(tag)
    }

    fn encrypt(&mut self, out: &mut [u8], data: &[u8]) -> Result<usize, CryptoError> {
        ensure!(
            out.len() >= data.len() + self.max_tag_len()?,
            CryptoError::Overflow
        );
        let out = match self {
            SymmetricState::Sha2(state) => state.encrypt(out, data)?,
            SymmetricState::HmacSha2(state) => state.encrypt(out, data)?,
            SymmetricState::AesGcm(state) => state.encrypt(out, data)?,
        };
        Ok(out)
    }

    fn encrypt_detached(
        &mut self,
        out: &mut [u8],
        data: &[u8],
    ) -> Result<SymmetricTag, CryptoError> {
        ensure!(out.len() >= data.len(), CryptoError::Overflow);
        let symmetric_tag = match self {
            SymmetricState::Sha2(state) => state.encrypt_detached(out, data)?,
            SymmetricState::HmacSha2(state) => state.encrypt_detached(out, data)?,
            SymmetricState::AesGcm(state) => state.encrypt_detached(out, data)?,
        };
        Ok(symmetric_tag)
    }

    fn decrypt(&mut self, out: &mut [u8], data: &[u8]) -> Result<usize, CryptoError> {
        ensure!(
            out.len()
                >= data
                    .len()
                    .checked_sub(self.max_tag_len()?)
                    .ok_or(CryptoError::Overflow)?,
            CryptoError::Overflow
        );
        let out_len = match self {
            SymmetricState::Sha2(state) => state.decrypt(out, data)?,
            SymmetricState::HmacSha2(state) => state.decrypt(out, data)?,
            SymmetricState::AesGcm(state) => state.decrypt(out, data)?,
        };
        Ok(out_len)
    }

    fn decrypt_detached(
        &mut self,
        out: &mut [u8],
        data: &[u8],
        raw_tag: &[u8],
    ) -> Result<usize, CryptoError> {
        ensure!(out.len() >= data.len(), CryptoError::Overflow);
        let out = match self {
            SymmetricState::Sha2(state) => state.decrypt_detached(out, data, raw_tag)?,
            SymmetricState::HmacSha2(state) => state.decrypt_detached(out, data, raw_tag)?,
            SymmetricState::AesGcm(state) => state.decrypt_detached(out, data, raw_tag)?,
        };
        Ok(out)
    }
}

impl CryptoCtx {
    pub fn symmetric_state_open(
        &self,
        alg_str: &str,
        key_handle: Option<Handle>,
        options_handle: Option<Handle>,
    ) -> Result<Handle, CryptoError> {
        let key = match key_handle {
            None => None,
            Some(symmetric_key_handle) => {
                Some(self.handles.symmetric_key.get(symmetric_key_handle)?)
            }
        };
        let options = match options_handle {
            None => None,
            Some(options_handle) => {
                Some(self.handles.options.get(options_handle)?.into_symmetric()?)
            }
        };
        let symmetric_state = SymmetricState::open(alg_str, key, options)?;
        let handle = self.handles.symmetric_state.register(symmetric_state)?;
        Ok(handle)
    }

    pub fn symmetric_state_close(&self, state_handle: Handle) -> Result<(), CryptoError> {
        self.handles.symmetric_state.close(state_handle)
    }

    pub fn symmetric_state_absorb(
        &self,
        state_handle: Handle,
        data: &[u8],
    ) -> Result<(), CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        symmetric_state.absorb(data)
    }

    pub fn symmetric_state_squeeze(
        &self,
        state_handle: Handle,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        symmetric_state.squeeze(out)
    }

    pub fn symmetric_state_squeeze_tag(&self, state_handle: Handle) -> Result<Handle, CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        let tag = symmetric_state.squeeze_tag()?;
        let handle = self.handles.symmetric_tag.register(tag)?;
        Ok(handle)
    }

    pub fn symmetric_state_max_tag_len(&self, state_handle: Handle) -> Result<usize, CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        let max_tag_len = symmetric_state.max_tag_len()?;
        Ok(max_tag_len)
    }

    pub fn symmetric_state_encrypt(
        &self,
        state_handle: Handle,
        out: &mut [u8],
        data: &[u8],
    ) -> Result<usize, CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        symmetric_state.encrypt(out, data)
    }

    pub fn symmetric_state_encrypt_detached(
        &self,
        state_handle: Handle,
        out: &mut [u8],
        data: &[u8],
    ) -> Result<SymmetricTag, CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        symmetric_state.encrypt_detached(out, data)
    }

    pub fn symmetric_state_decrypt(
        &self,
        state_handle: Handle,
        out: &mut [u8],
        data: &[u8],
    ) -> Result<usize, CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        symmetric_state.decrypt(out, data)
    }

    pub fn symmetric_state_decrypt_detached(
        &self,
        state_handle: Handle,
        out: &mut [u8],
        data: &[u8],
        raw_tag: &[u8],
    ) -> Result<usize, CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        symmetric_state.decrypt_detached(out, data, raw_tag)
    }
}

impl WasiCryptoCtx {
    pub fn symmetric_state_open(
        &self,
        alg_str: &wiggle::GuestPtr<'_, str>,
        key_handle: &guest_types::OptSymmetricKey,
        options_handle: &guest_types::OptOptions,
    ) -> Result<guest_types::SymmetricState, CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
        let alg_str: &str = unsafe { &*alg_str.as_raw(&mut guest_borrow)? };
        let key_handle = match *key_handle {
            guest_types::OptSymmetricKey::Some(key_handle) => Some(key_handle),
            guest_types::OptSymmetricKey::None => None,
        };
        let options_handle = match *options_handle {
            guest_types::OptOptions::Some(options_handle) => Some(options_handle),
            guest_types::OptOptions::None => None,
        };
        Ok(self
            .ctx
            .symmetric_state_open(
                alg_str,
                key_handle.map(Into::into),
                options_handle.map(Into::into),
            )?
            .into())
    }
}
