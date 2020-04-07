mod hmac_sha2;
mod sha2;
mod symmetric_key;

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
pub enum SymmetricOp {
    HmacSha2(HmacSha2SymmetricOp),
    Sha2(Sha2SymmetricOp),
}

impl SymmetricOp {
    pub fn alg(self) -> SymmetricAlgorithm {
        match self {
            SymmetricOp::HmacSha2(op) => op.alg,
            SymmetricOp::Sha2(op) => op.alg,
        }
    }

    fn open(
        handles: &HandleManagers,
        alg_str: &str,
        key: Option<&SymmetricKey>,
        options: &SymmetricOptions,
    ) -> Result<Handle, CryptoError> {
        let alg = SymmetricAlgorithm::try_from(alg_str)?;
        let symmetric_op = match alg {
            SymmetricAlgorithm::HmacSha256 => {
                SymmetricOp::HmacSha2(HmacSha2SymmetricOp::new(alg, key, options)?)
            }
            SymmetricAlgorithm::HmacSha512 => {
                SymmetricOp::HmacSha2(HmacSha2SymmetricOp::new(alg, key, options)?)
            }
            SymmetricAlgorithm::Sha256 => {
                SymmetricOp::Sha2(Sha2SymmetricOp::new(alg, None, options)?)
            }
            SymmetricAlgorithm::Sha512 => {
                SymmetricOp::Sha2(Sha2SymmetricOp::new(alg, None, options)?)
            }
            SymmetricAlgorithm::Sha512_256 => {
                SymmetricOp::Sha2(Sha2SymmetricOp::new(alg, None, options)?)
            }
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        };
        let handle = handles.symmetric_op.register(symmetric_op)?;
        Ok(handle)
    }
}

impl CryptoCtx {
    pub fn symmetric_op_open(
        &self,
        alg_str: &str,
        key: Option<&SymmetricKey>,
        options: SymmetricOptions,
    ) -> Result<Handle, CryptoError> {
        SymmetricOp::open(&self.handles, alg_str, key, &options)
    }

    pub fn symmetric_op_close(&self, handle: Handle) -> Result<(), CryptoError> {
        self.handles.symmetric_op.close(handle)
    }
}
