mod hmac_sha2;
mod sha2;
mod symmetric_key;
mod tag;

use crate::error::*;
use crate::handles::*;
use crate::options::*;
use crate::types as guest_types;
use crate::{CryptoCtx, HandleManagers, WasiCryptoCtx};
use hmac_sha2::*;
use sha2::*;
use std::any::Any;
use std::convert::TryFrom;

pub use symmetric_key::SymmetricKey;
pub use tag::SymmetricTag;

#[derive(Clone, Debug, Default)]
pub struct SymmetricOptions {
    context: Option<String>,
    salt: Option<String>,
    memory_limit: Option<u64>,
    ops_limit: Option<u64>,
    parallelism: Option<u64>,
}

impl OptionsLike for SymmetricOptions {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn set(&mut self, name: &str, value: &str) -> Result<(), CryptoError> {
        let option = match name.to_lowercase().as_str() {
            "context" => &mut self.context,
            "salt" => &mut self.salt,
            _ => bail!(CryptoError::UnsupportedOption),
        };
        *option = Some(value.to_string());
        Ok(())
    }

    fn set_u64(&mut self, name: &str, value: u64) -> Result<(), CryptoError> {
        let option = match name.to_lowercase().as_str() {
            "memory_limit" => &mut self.memory_limit,
            "ops_limit" => &mut self.ops_limit,
            "parallelism" => &mut self.parallelism,
            _ => bail!(CryptoError::UnsupportedOption),
        };
        *option = Some(value);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymmetricAlgorithm {
    None,
    HmacSha256,
    HmacSha512,
    Sha256,
    Sha512,
    Sha512_256,
}

impl TryFrom<&str> for SymmetricAlgorithm {
    type Error = CryptoError;

    fn try_from(alg_str: &str) -> Result<Self, CryptoError> {
        match alg_str {
            "HMAC/SHA-256" => Ok(SymmetricAlgorithm::HmacSha256),
            "HMAC/SHA-512" => Ok(SymmetricAlgorithm::HmacSha512),
            "SHA-256" => Ok(SymmetricAlgorithm::Sha256),
            "SHA-512" => Ok(SymmetricAlgorithm::Sha512),
            "SHA-512/256" => Ok(SymmetricAlgorithm::Sha512_256),
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        }
    }
}

#[derive(Clone, Debug)]
pub enum SymmetricState {
    HmacSha2(HmacSha2SymmetricState),
    Sha2(Sha2SymmetricState),
}

impl SymmetricState {
    pub fn alg(self) -> SymmetricAlgorithm {
        match self {
            SymmetricState::HmacSha2(op) => op.alg,
            SymmetricState::Sha2(op) => op.alg,
        }
    }

    fn open(
        alg_str: &str,
        key: Option<SymmetricKey>,
        options: Option<SymmetricOptions>,
    ) -> Result<SymmetricState, CryptoError> {
        let alg = SymmetricAlgorithm::try_from(alg_str)?;
        let symmetric_state = match alg {
            SymmetricAlgorithm::HmacSha256 | SymmetricAlgorithm::HmacSha512 => {
                SymmetricState::HmacSha2(HmacSha2SymmetricState::new(alg, key, options)?)
            }
            SymmetricAlgorithm::Sha256
            | SymmetricAlgorithm::Sha512
            | SymmetricAlgorithm::Sha512_256 => {
                SymmetricState::Sha2(Sha2SymmetricState::new(alg, None, options)?)
            }
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        };
        Ok(symmetric_state)
    }

    fn absorb(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            SymmetricState::Sha2(state) => state.absorb(data)?,
            SymmetricState::HmacSha2(state) => state.absorb(data)?,
        };
        Ok(())
    }

    fn squeeze(&mut self, len: usize) -> Result<Vec<u8>, CryptoError> {
        let out = match self {
            SymmetricState::Sha2(state) => state.squeeze(len)?,
            SymmetricState::HmacSha2(state) => state.squeeze(len)?,
        };
        Ok(out)
    }

    fn squeeze_tag(&mut self) -> Result<SymmetricTag, CryptoError> {
        let tag = match self {
            SymmetricState::Sha2(state) => state.squeeze_tag()?,
            SymmetricState::HmacSha2(state) => state.squeeze_tag()?,
        };
        Ok(tag)
    }
}

impl CryptoCtx {
    pub fn symmetric_state_open(
        &self,
        alg_str: &str,
        key_handle: Option<Handle>,
        options_handle: Option<Handle>,
    ) -> Result<Handle, CryptoError> {
        let key = match key_handle {
            None => None,
            Some(symmetric_key_handle) => {
                Some(self.handles.symmetric_key.get(symmetric_key_handle)?)
            }
        };
        let options = match options_handle {
            None => None,
            Some(options_handle) => Some(self.handles.symmetric_options.get(options_handle)?),
        };
        let symmetric_state = SymmetricState::open(alg_str, key, options)?;
        let handle = self.handles.symmetric_state.register(symmetric_state)?;
        Ok(handle)
    }

    pub fn symmetric_state_close(&self, state_handle: Handle) -> Result<(), CryptoError> {
        self.handles.symmetric_state.close(state_handle)
    }

    pub fn symmetric_state_absorb(
        &self,
        state_handle: Handle,
        data: &[u8],
    ) -> Result<(), CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        symmetric_state.absorb(data)
    }

    pub fn symmetric_state_squeeze(
        &self,
        state_handle: Handle,
        len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        symmetric_state.squeeze(len)
    }

    pub fn symmetric_state_squeeze_tag(&self, state_handle: Handle) -> Result<Handle, CryptoError> {
        let mut symmetric_state = self.handles.symmetric_state.get(state_handle)?;
        let tag = symmetric_state.squeeze_tag()?;
        let handle = self.handles.symmetric_tag.register(tag)?;
        Ok(handle)
    }
}

#[test]
fn test_hmac() {
    use crate::CryptoCtx;

    let ctx = CryptoCtx::new();

    let key_handle = ctx.symmetric_key_generate("HMAC/SHA-512", None).unwrap();
    let state_handle = ctx
        .symmetric_state_open("HMAC/SHA-512", Some(key_handle), None)
        .unwrap();
    ctx.symmetric_state_absorb(state_handle, b"data").unwrap();
    ctx.symmetric_state_absorb(state_handle, b"more_data")
        .unwrap();
    let tag = ctx.symmetric_state_squeeze_tag(state_handle).unwrap();
    ctx.symmetric_state_close(state_handle).unwrap();
}
