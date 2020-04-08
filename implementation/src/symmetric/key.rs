use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SymmetricKey {
    HmacSha2(HmacSha2SymmetricKey),
    AesGcm(AesGcmSymmetricKey),
}

impl SymmetricKey {
    pub fn alg(&self) -> SymmetricAlgorithm {
        match self {
            SymmetricKey::HmacSha2(key) => key.alg(),
            SymmetricKey::AesGcm(key) => key.alg(),
        }
    }

    fn generate(
        alg_str: &str,
        options: Option<SymmetricOptions>,
    ) -> Result<SymmetricKey, CryptoError> {
        let alg = SymmetricAlgorithm::try_from(alg_str)?;
        let key = match alg {
            SymmetricAlgorithm::HmacSha256 | SymmetricAlgorithm::HmacSha512 => {
                SymmetricKey::HmacSha2(HmacSha2SymmetricKey::generate(alg, options)?)
            }
            SymmetricAlgorithm::Aes128Gcm | SymmetricAlgorithm::Aes256Gcm => {
                SymmetricKey::AesGcm(AesGcmSymmetricKey::generate(alg, options)?)
            }
            _ => bail!(CryptoError::KeyNotSupported),
        };
        Ok(key)
    }

    fn import(alg_str: &str, raw: &[u8]) -> Result<SymmetricKey, CryptoError> {
        let alg = SymmetricAlgorithm::try_from(alg_str)?;
        let key = match alg {
            SymmetricAlgorithm::HmacSha256 | SymmetricAlgorithm::HmacSha512 => {
                SymmetricKey::HmacSha2(HmacSha2SymmetricKey::import(alg, raw)?)
            }
            SymmetricAlgorithm::Aes128Gcm | SymmetricAlgorithm::Aes256Gcm => {
                SymmetricKey::AesGcm(AesGcmSymmetricKey::import(alg, raw)?)
            }
            _ => bail!(CryptoError::KeyNotSupported),
        };
        Ok(key)
    }

    pub fn as_raw(&self) -> Result<Vec<u8>, CryptoError> {
        let raw = match self {
            SymmetricKey::HmacSha2(key) => key.as_raw()?.to_vec(),
            SymmetricKey::AesGcm(key) => key.as_raw()?.to_vec(),
        };
        Ok(raw)
    }
}

impl CryptoCtx {
    pub fn symmetric_key_generate(
        &self,
        alg_str: &str,
        options_handle: Option<Handle>,
    ) -> Result<Handle, CryptoError> {
        let options = match options_handle {
            None => None,
            Some(options_handle) => {
                Some(self.handles.options.get(options_handle)?.into_symmetric()?)
            }
        };
        let key = SymmetricKey::generate(alg_str, options)?;
        let handle = self.handles.symmetric_key.register(key)?;
        Ok(handle)
    }

    pub fn symmetric_key_import(&self, alg_str: &str, raw: &[u8]) -> Result<Handle, CryptoError> {
        let key = SymmetricKey::import(alg_str, raw)?;
        let handle = self.handles.symmetric_key.register(key)?;
        Ok(handle)
    }

    pub fn symmetric_key_close(&self, symmetric_key_handle: Handle) -> Result<(), CryptoError> {
        self.handles.symmetric_key.close(symmetric_key_handle)
    }
}
