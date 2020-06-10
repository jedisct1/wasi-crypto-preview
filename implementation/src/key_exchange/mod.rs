mod secretkey;

use std::any::Any;
use std::convert::TryFrom;

use crate::error::*;
use parking_lot::Mutex;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct KxOptionsInner {
    context: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct KxOptions {
    inner: Arc<Mutex<KxOptionsInner>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KxAlgorithm {
    X25519,
}

impl TryFrom<&str> for KxAlgorithm {
    type Error = CryptoError;

    fn try_from(alg_str: &str) -> Result<Self, CryptoError> {
        match alg_str.to_uppercase().as_str() {
            "X25519" => Ok(KxAlgorithm::X25519),
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        }
    }
}
