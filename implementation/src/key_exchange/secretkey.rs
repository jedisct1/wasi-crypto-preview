use super::*;

use crate::asymmetric_common::*;
use parking_lot::{Mutex, MutexGuard};
use std::sync::Arc;

pub trait KxSecretKeyBuilder {
    fn from_raw(&self, raw: &[u8]) -> Result<KxSecretKey, CryptoError>;
}

#[derive(Clone)]
pub struct KxSecretKey {
    inner: Arc<Mutex<Box<dyn KxSecretKeyLike>>>,
}

impl KxSecretKey {
    pub fn new(kx_secretkey_like: Box<dyn KxSecretKeyLike>) -> Self {
        KxSecretKey {
            inner: Arc::new(Mutex::new(kx_secretkey_like)),
        }
    }

    pub fn inner(&self) -> MutexGuard<Box<dyn KxSecretKeyLike>> {
        self.inner.lock()
    }

    pub fn locked<T, U>(&self, mut f: T) -> U
    where
        T: FnMut(MutexGuard<Box<dyn KxSecretKeyLike>>) -> U,
    {
        f(self.inner())
    }

    pub fn alg(&self) -> KxAlgorithm {
        self.inner().alg()
    }

    pub(crate) fn export(&self, encoding: SecretKeyEncoding) -> Result<Vec<u8>, CryptoError> {
        match encoding {
            SecretKeyEncoding::Raw => Ok(self.inner().as_raw()?.to_vec()),
            _ => bail!(CryptoError::UnsupportedEncoding),
        }
    }

    pub(crate) fn publickey(&self) -> Result<KxPublicKey, CryptoError> {
        Ok(self.inner().into_publickey()?)
    }
}

pub trait KxSecretKeyLike: Sync + Send {
    fn as_any(&self) -> &dyn Any;
    fn alg(&self) -> KxAlgorithm;
    fn as_raw(&self) -> Result<&[u8], CryptoError>;
    fn into_publickey(&self) -> Result<KxPublicKey, CryptoError>;
}
