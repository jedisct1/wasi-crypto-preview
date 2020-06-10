use super::*;

use parking_lot::Mutex;
use std::sync::Arc;

#[derive(Clone)]
pub struct KxKeyPair {
    inner: Arc<Mutex<Box<dyn KxKeyPairLike>>>,
}

pub trait KxKeyPairLike: Sync + Send {
    fn as_any(&self) -> &dyn Any;
    fn alg(&self) -> KxAlgorithm;
}

pub trait KxKeyPairBuilder {
    fn generate(&self, options: Option<KxOptions>) -> Result<KxKeyPair, CryptoError>;
}
