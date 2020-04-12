use super::state::*;
use super::*;

use ::xoodyak::*;
use parking_lot::Mutex;
use ring::rand::SecureRandom;
use std::sync::Arc;
use zeroize::Zeroize;

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct XoodyakSymmetricState {
    pub alg: SymmetricAlgorithm,
    options: Option<SymmetricOptions>,
    #[derivative(Debug = "ignore")]
    state: Arc<Mutex<Box<dyn Xoodyak + Sync + Send>>>,
}

#[derive(Clone, Debug, Eq)]
pub struct XoodyakSymmetricKey {
    alg: SymmetricAlgorithm,
    raw: Vec<u8>,
}

impl PartialEq for XoodyakSymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.alg == other.alg
            && ring::constant_time::verify_slices_are_equal(&self.raw, &other.raw).is_ok()
    }
}

impl Drop for XoodyakSymmetricKey {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

impl SymmetricKeyLike for XoodyakSymmetricKey {
    fn alg(&self) -> SymmetricAlgorithm {
        self.alg
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_raw(&self) -> Result<&[u8], CryptoError> {
        Ok(&self.raw)
    }
}

impl XoodyakSymmetricKey {
    fn new(alg: SymmetricAlgorithm, raw: &[u8]) -> Result<Self, CryptoError> {
        Ok(XoodyakSymmetricKey {
            alg,
            raw: raw.to_vec(),
        })
    }
}

pub struct XoodyakSymmetricKeyBuilder {
    alg: SymmetricAlgorithm,
}

impl XoodyakSymmetricKeyBuilder {
    pub fn new(alg: SymmetricAlgorithm) -> Box<dyn SymmetricKeyBuilder> {
        Box::new(Self { alg })
    }
}

impl SymmetricKeyBuilder for XoodyakSymmetricKeyBuilder {
    fn generate(&self, _options: Option<SymmetricOptions>) -> Result<SymmetricKey, CryptoError> {
        let key_len = match self.alg {
            SymmetricAlgorithm::Xoodyak128 => 128,
            SymmetricAlgorithm::Xoodyak256 => 256,
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        };
        let rng = ring::rand::SystemRandom::new();
        let mut raw = vec![0u8; key_len];
        rng.fill(&mut raw).map_err(|_| CryptoError::RNGError)?;
        self.import(&raw)
    }

    fn import(&self, raw: &[u8]) -> Result<SymmetricKey, CryptoError> {
        let key = XoodyakSymmetricKey::new(self.alg, raw)?;
        Ok(SymmetricKey::new(Box::new(key)))
    }
}

impl XoodyakSymmetricState {
    pub fn new(
        alg: SymmetricAlgorithm,
        key: Option<SymmetricKey>,
        options: Option<SymmetricOptions>,
    ) -> Result<Self, CryptoError> {
        let key = match key {
            None => None,
            Some(key) => {
                let key = key.inner();
                let key = key
                    .as_any()
                    .downcast_ref::<XoodyakSymmetricKey>()
                    .ok_or(CryptoError::InvalidKey)?
                    .clone();
                Some(key)
            }
        };
        unimplemented!();
    }
}

impl SymmetricStateLike for XoodyakSymmetricState {
    fn alg(&self) -> SymmetricAlgorithm {
        self.alg
    }

    fn options_get(&self, name: &str) -> Result<Vec<u8>, CryptoError> {
        self.options
            .as_ref()
            .ok_or(CryptoError::OptionNotSet)?
            .get(name)
    }

    fn options_get_u64(&self, name: &str) -> Result<u64, CryptoError> {
        self.options
            .as_ref()
            .ok_or(CryptoError::OptionNotSet)?
            .get_u64(name)
    }
}
