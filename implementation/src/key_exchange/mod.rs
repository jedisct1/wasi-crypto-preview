mod keypair;
mod publickey;
mod secretkey;
mod x25519;

use std::any::Any;
use std::convert::TryFrom;

use self::x25519::*;
use crate::error::*;
use crate::options::*;
use parking_lot::Mutex;
use std::sync::Arc;

pub use keypair::*;
pub use publickey::*;
pub use secretkey::*;

#[derive(Debug, Default)]
pub struct KxOptionsInner {
    context: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Default)]
pub struct KxOptions {
    inner: Arc<Mutex<KxOptionsInner>>,
}

impl OptionsLike for KxOptions {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn set(&mut self, _name: &str, _value: &[u8]) -> Result<(), CryptoError> {
        bail!(CryptoError::UnsupportedOption)
    }

    fn set_u64(&mut self, _name: &str, _value: u64) -> Result<(), CryptoError> {
        bail!(CryptoError::UnsupportedOption)
    }
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
