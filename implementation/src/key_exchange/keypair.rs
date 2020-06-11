use super::*;

use crate::asymmetric_common::*;
use parking_lot::{Mutex, MutexGuard};
use std::sync::Arc;

#[derive(Clone)]
pub struct KxKeyPair {
    inner: Arc<Mutex<Box<dyn KxKeyPairLike>>>,
}

pub trait KxKeyPairBuilder {
    fn generate(&self, options: Option<KxOptions>) -> Result<KxKeyPair, CryptoError>;
}

impl KxKeyPair {
    pub fn new(kx_keypair_like: Box<dyn KxKeyPairLike>) -> Self {
        KxKeyPair {
            inner: Arc::new(Mutex::new(kx_keypair_like)),
        }
    }

    pub fn inner(&self) -> MutexGuard<Box<dyn KxKeyPairLike>> {
        self.inner.lock()
    }

    pub fn locked<T, U>(&self, mut f: T) -> U
    where
        T: FnMut(MutexGuard<Box<dyn KxKeyPairLike>>) -> U,
    {
        f(self.inner())
    }

    pub fn alg(&self) -> KxAlgorithm {
        self.inner().alg()
    }

    pub fn builder(alg_str: &str) -> Result<Box<dyn KxKeyPairBuilder>, CryptoError> {
        let alg = KxAlgorithm::try_from(alg_str)?;
        let builder = match alg {
            KxAlgorithm::X25519 => unimplemented!(),
            _ => bail!(CryptoError::InvalidOperation),
        };
        Ok(builder)
    }

    fn generate(alg_str: &str, options: Option<KxOptions>) -> Result<KxKeyPair, CryptoError> {
        let builder = Self::builder(alg_str)?;
        builder.generate(options)
    }

    pub(crate) fn export(&self, _encoding: KeyPairEncoding) -> Result<Vec<u8>, CryptoError> {
        unimplemented!()
    }

    pub(crate) fn public_key(&self) -> Result<KxPublicKey, CryptoError> {
        unimplemented!()
    }
}

pub trait KxKeyPairLike: Sync + Send {
    fn as_any(&self) -> &dyn Any;
    fn alg(&self) -> KxAlgorithm;
    fn as_raw(&self) -> Result<&[u8], CryptoError>;
}
