use std::any::Any;

use super::error::*;

pub trait Options {
    fn as_any(&self) -> &dyn Any;
    fn set(&mut self, name: &str, value: &str) -> Result<(), CryptoError>;
    fn set_u64(&mut self, name: &str, value: u64) -> Result<(), CryptoError>;
}
