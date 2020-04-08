use std::any::Any;

use super::{CryptoCtx, WasiCryptoCtx};
use crate::error::*;
use crate::handles::*;
use crate::signatures::SignatureOptions;
use crate::symmetric::SymmetricOptions;
use crate::types as guest_types;

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

impl From<guest_types::OptionsType> for OptionsType {
    fn from(options_type: guest_types::OptionsType) -> Self {
        match options_type {
            guest_types::OptionsType::Signatures => OptionsType::Signatures,
            guest_types::OptionsType::Symmetric => OptionsType::Symmetric,
        }
    }
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
        &self,
        options_handle: Handle,
        name: &str,
        value: &[u8],
    ) -> Result<(), CryptoError> {
        let mut options = self.handles.options.get(options_handle)?;
        options.set(name, value)
    }

    pub fn options_set_u64(
        &self,
        options_handle: Handle,
        name: &str,
        value: u64,
    ) -> Result<(), CryptoError> {
        let mut options = self.handles.options.get(options_handle)?;
        options.set_u64(name, value)
    }
}

impl WasiCryptoCtx {
    pub fn options_open(
        &self,
        options_type: guest_types::OptionsType,
    ) -> Result<guest_types::Options, CryptoError> {
        Ok(self.ctx.options_open(options_type.into())?.into())
    }

    pub fn options_close(&self, options_handle: guest_types::Options) -> Result<(), CryptoError> {
        Ok(self.ctx.options_close(options_handle.into())?.into())
    }

    pub fn options_set(
        &self,
        options_handle: guest_types::Options,
        name_str: &wiggle::GuestPtr<'_, str>,
        value_ptr: &wiggle::GuestPtr<'_, u8>,
        value_len: guest_types::Size,
    ) -> Result<(), CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
        let name_str: &str = unsafe { &*name_str.as_raw(&mut guest_borrow)? };
        let value: &[u8] = unsafe {
            &*value_ptr
                .as_array(value_len as _)
                .as_raw(&mut guest_borrow)?
        };
        Ok(self
            .ctx
            .options_set(options_handle.into(), name_str, value)?
            .into())
    }

    pub fn options_set_u64(
        &self,
        options_handle: guest_types::Options,
        name_str: &wiggle::GuestPtr<'_, str>,
        value: u64,
    ) -> Result<(), CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
        let name_str: &str = unsafe { &*name_str.as_raw(&mut guest_borrow)? };
        Ok(self
            .ctx
            .options_set_u64(options_handle.into(), name_str, value)?
            .into())
    }
}
