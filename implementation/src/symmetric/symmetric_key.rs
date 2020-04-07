use super::*;
use crate::version::Version;
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SymmetricKey {
    HmacSha2(HmacSha2SymmetricKey),
}

impl SymmetricKey {
    fn generate(handles: &HandleManagers, alg_str: &str) -> Result<Handle, CryptoError> {
        let alg = SymmetricAlgorithm::try_from(alg_str)?;
        let handle = match alg {
            SymmetricAlgorithm::HmacSha256 | SymmetricAlgorithm::HmacSha512 => {
                HmacSha2SymmetricKey::generate(handles, alg)?
            }
            _ => bail!(CryptoError::KeyNotSupported),
        };
        Ok(handle)
    }

    fn import(handles: &HandleManagers, alg_str: &str, raw: &[u8]) -> Result<Handle, CryptoError> {
        let alg = SymmetricAlgorithm::try_from(alg_str)?;
        let handle = match alg {
            SymmetricAlgorithm::HmacSha256 | SymmetricAlgorithm::HmacSha512 => {
                HmacSha2SymmetricKey::import(handles, alg, raw)?
            }
            _ => bail!(CryptoError::KeyNotSupported),
        };
        Ok(handle)
    }

    pub fn as_raw(&self) -> Result<Vec<u8>, CryptoError> {
        let raw = match self {
            SymmetricKey::HmacSha2(key) => key.as_raw()?.to_vec(),
        };
        Ok(raw)
    }
}
