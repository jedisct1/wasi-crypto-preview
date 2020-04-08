use std::any::Any;

use super::error::*;

pub trait OptionsLike: Send + Sized {
    fn as_any(&self) -> &dyn Any;
    fn set(&mut self, name: &str, value: &[u8]) -> Result<(), CryptoError>;
    fn set_u64(&mut self, name: &str, value: u64) -> Result<(), CryptoError>;
}
