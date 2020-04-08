use std::any::Any;

use super::CryptoCtx;
use crate::error::*;
use crate::handles::*;
use crate::signatures::SignatureOptions;
use crate::symmetric::SymmetricOptions;

pub trait OptionsLike: Send + Sized {
    fn as_any(&self) -> &dyn Any;
    fn set(&mut self, name: &str, value: &[u8]) -> Result<(), CryptoError>;
    fn set_u64(&mut self, name: &str, value: u64) -> Result<(), CryptoError>;
}

#[derive(Clone, Debug)]
pub enum Options {
    Signatures(SignatureOptions),
    Symmetric(SymmetricOptions),
}

impl Options {
    pub fn into_signatures(self) -> Result<SignatureOptions, CryptoError> {
        match self {
            Options::Signatures(options) => Ok(options),
            _ => bail!(CryptoError::InvalidHandle),
        }
    }

    pub fn into_symmetric(self) -> Result<SymmetricOptions, CryptoError> {
        match self {
            Options::Symmetric(options) => Ok(options),
            _ => bail!(CryptoError::InvalidHandle),
        }
    }

    pub fn set(&mut self, name: &str, value: &[u8]) -> Result<(), CryptoError> {
        match self {
            Options::Signatures(options) => options.set(name, value),
            Options::Symmetric(options) => options.set(name, value),
        }
    }

    pub fn set_u64(&mut self, name: &str, value: u64) -> Result<(), CryptoError> {
        match self {
            Options::Signatures(options) => options.set_u64(name, value),
            Options::Symmetric(options) => options.set_u64(name, value),
        }
    }
}

pub enum OptionsType {
    Signatures,
    Symmetric,
}

impl CryptoCtx {
    pub fn options_open(&self, options_type: OptionsType) -> Result<Handle, CryptoError> {
        let options = match options_type {
            OptionsType::Signatures => Options::Signatures(SignatureOptions::default()),
            OptionsType::Symmetric => Options::Symmetric(SymmetricOptions::default()),
        };
        let handle = self.handles.options.register(options)?;
        Ok(handle)
    }

    pub fn options_close(&self, options_handle: Handle) -> Result<(), CryptoError> {
        self.handles.options.close(options_handle)
    }

    pub fn options_set(
        &mut self,
        options_handle: Handle,
        name: &str,
        value: &[u8],
    ) -> Result<(), CryptoError> {
        let mut options = self.handles.options.get(options_handle)?;
        options.set(name, value)
    }

    pub fn options_set_u64(
        &mut self,
        options_handle: Handle,
        name: &str,
        value: u64,
    ) -> Result<(), CryptoError> {
        let mut options = self.handles.options.get(options_handle)?;
        options.set_u64(name, value)
    }
}
