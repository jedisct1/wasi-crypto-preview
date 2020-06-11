use super::*;

use crate::asymmetric_common::*;
use parking_lot::{Mutex, MutexGuard};
use std::sync::Arc;

#[derive(Clone)]
pub struct KxPublicKey {
    inner: Arc<Mutex<Box<dyn KxPublicKeyLike>>>,
}

impl KxPublicKey {
    pub fn new(kx_publickey_like: Box<dyn KxPublicKeyLike>) -> Self {
        KxPublicKey {
            inner: Arc::new(Mutex::new(kx_publickey_like)),
        }
    }

    pub fn inner(&self) -> MutexGuard<Box<dyn KxPublicKeyLike>> {
        self.inner.lock()
    }

    pub fn locked<T, U>(&self, mut f: T) -> U
    where
        T: FnMut(MutexGuard<Box<dyn KxPublicKeyLike>>) -> U,
    {
        f(self.inner())
    }

    pub fn alg(&self) -> KxAlgorithm {
        self.inner().alg()
    }

    pub(crate) fn export(&self, _encoding: PublicKeyEncoding) -> Result<Vec<u8>, CryptoError> {
        unimplemented!()
    }

    pub(crate) fn verify(&self) -> Result<(), CryptoError> {
        unimplemented!()
    }

    pub(crate) fn from_secretkey(sk: KxSecretKey) -> Result<KxPublicKey, CryptoError> {
        unimplemented!()
    }
}

pub trait KxPublicKeyLike: Sync + Send {
    fn as_any(&self) -> &dyn Any;
    fn alg(&self) -> KxAlgorithm;
    fn as_raw(&self) -> Result<&[u8], CryptoError>;
}
