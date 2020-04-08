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
        key: Option<&SymmetricKey>,
        options: &SymmetricOptions,
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
}

impl CryptoCtx {
    pub fn symmetric_state_open(
        &self,
        alg_str: &str,
        key: Option<&SymmetricKey>,
        options: SymmetricOptions,
    ) -> Result<Handle, CryptoError> {
        let symmetric_state = SymmetricState::open(alg_str, key, &options)?;
        let handle = self.handles.symmetric_state.register(symmetric_state)?;
        Ok(handle)
    }

    pub fn symmetric_state_close(&self, state_handle: Handle) -> Result<(), CryptoError> {
        self.handles.symmetric_state.close(state_handle)
    }

    fn absorb(&self, state_handle: Handle, data: &[u8]) -> Result<(), CryptoError> {
        let state = self.handles.symmetric_state.get(state_handle)?;
        match state {
            SymmetricState::Sha2(mut state) => state.absorb(data)?,
            SymmetricState::HmacSha2(mut state) => state.absorb(data)?,
        };
        Ok(())
    }
}
