use super::*;

pub trait SymmetricAlgorithmStateLike {
    fn alg(&self) -> SymmetricAlgorithm;

    fn absorb(&mut self, _data: &[u8]) -> Result<(), CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }

    fn squeeze(&mut self, _len: usize) -> Result<Vec<u8>, CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }

    fn squeeze_tag(&mut self) -> Result<SymmetricTag, CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }

    fn encrypt(&mut self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }

    fn encrypt_detached(&mut self, _data: &[u8]) -> Result<(Vec<u8>, SymmetricTag), CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }

    fn decrypt(&mut self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }

    fn decrypt_detached(&mut self, _data: &[u8], _raw_tag: &[u8]) -> Result<Vec<u8>, CryptoError> {
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
                SymmetricState::AesGcm(AesGcmSymmetricState::new(alg, None, options)?)
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

    fn squeeze(&mut self, len: usize) -> Result<Vec<u8>, CryptoError> {
        let out = match self {
            SymmetricState::Sha2(state) => state.squeeze(len)?,
            SymmetricState::HmacSha2(state) => state.squeeze(len)?,
            SymmetricState::AesGcm(state) => state.squeeze(len)?,
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

    fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let out = match self {
            SymmetricState::Sha2(state) => state.encrypt(data)?,
            SymmetricState::HmacSha2(state) => state.encrypt(data)?,
            SymmetricState::AesGcm(state) => state.encrypt(data)?,
        };
        Ok(out)
    }

    fn encrypt_detached(&mut self, data: &[u8]) -> Result<(Vec<u8>, SymmetricTag), CryptoError> {
        let (out, symmetric_tag) = match self {
            SymmetricState::Sha2(state) => state.encrypt_detached(data)?,
            SymmetricState::HmacSha2(state) => state.encrypt_detached(data)?,
            SymmetricState::AesGcm(state) => state.encrypt_detached(data)?,
        };
        Ok((out, symmetric_tag))
    }

    fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let out = match self {
            SymmetricState::Sha2(state) => state.decrypt(data)?,
            SymmetricState::HmacSha2(state) => state.decrypt(data)?,
            SymmetricState::AesGcm(state) => state.decrypt(data)?,
        };
        Ok(out)
    }

    fn decrypt_detached(&mut self, data: &[u8], raw_tag: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let out = match self {
            SymmetricState::Sha2(state) => state.decrypt_detached(data, raw_tag)?,
            SymmetricState::HmacSha2(state) => state.decrypt_detached(data, raw_tag)?,
            SymmetricState::AesGcm(state) => state.decrypt_detached(data, raw_tag)?,
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
        len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        symmetric_state.squeeze(len)
    }

    pub fn symmetric_state_squeeze_tag(&self, state_handle: Handle) -> Result<Handle, CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        let tag = symmetric_state.squeeze_tag()?;
        let handle = self.handles.symmetric_tag.register(tag)?;
        Ok(handle)
    }

    pub fn symmetric_encrypt(
        &mut self,
        state_handle: Handle,
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        symmetric_state.encrypt(data)
    }

    pub fn symmetric_encrypt_detached(
        &mut self,
        state_handle: Handle,
        data: &[u8],
    ) -> Result<(Vec<u8>, SymmetricTag), CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        symmetric_state.encrypt_detached(data)
    }

    pub fn symmetric_decrypt(
        &mut self,
        state_handle: Handle,
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        symmetric_state.decrypt(data)
    }

    pub fn symmetric_decrypt_detached(
        &mut self,
        state_handle: Handle,
        data: &[u8],
        raw_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        symmetric_state.decrypt_detached(data, raw_tag)
    }
}
