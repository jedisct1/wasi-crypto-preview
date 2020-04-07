use super::ecdsa::*;
use super::eddsa::*;
use super::rsa::*;
use super::signature::*;
use crate::error::*;
use crate::handles::*;
use crate::types as guest_types;
use crate::{CryptoCtx, HandleManagers, WasiCryptoCtx};

use std::convert::TryFrom;

#[derive(Clone, Copy, Debug)]
pub enum SignatureOp {
    Ecdsa(EcdsaSignatureOp),
    Eddsa(EddsaSignatureOp),
    Rsa(RsaSignatureOp),
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    Ed25519,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_3072_8192_SHA384,
}

impl TryFrom<&str> for SignatureAlgorithm {
    type Error = CryptoError;

    fn try_from(alg_str: &str) -> Result<Self, CryptoError> {
        match alg_str {
            "ECDSA_P256_SHA256" => Ok(SignatureAlgorithm::ECDSA_P256_SHA256),
            "ECDSA_P384_SHA384" => Ok(SignatureAlgorithm::ECDSA_P384_SHA384),
            "Ed25519" => Ok(SignatureAlgorithm::Ed25519),
            "RSA_PKCS1_2048_8192_SHA256" => Ok(SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256),
            "RSA_PKCS1_2048_8192_SHA384" => Ok(SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384),
            "RSA_PKCS1_2048_8192_SHA512" => Ok(SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512),
            "RSA_PKCS1_3072_8192_SHA384" => Ok(SignatureAlgorithm::RSA_PKCS1_3072_8192_SHA384),
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        }
    }
}

impl SignatureOp {
    pub fn alg(self) -> SignatureAlgorithm {
        match self {
            SignatureOp::Ecdsa(op) => op.alg,
            SignatureOp::Eddsa(op) => op.alg,
            SignatureOp::Rsa(op) => op.alg,
        }
    }

    fn open(handles: &HandleManagers, alg_str: &str) -> Result<Handle, CryptoError> {
        let alg = SignatureAlgorithm::try_from(alg_str)?;
        let signature_op = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 => SignatureOp::Ecdsa(EcdsaSignatureOp::new(alg)),
            SignatureAlgorithm::ECDSA_P384_SHA384 => SignatureOp::Ecdsa(EcdsaSignatureOp::new(alg)),
            SignatureAlgorithm::Ed25519 => SignatureOp::Eddsa(EddsaSignatureOp::new(alg)),
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256
            | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384
            | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512
            | SignatureAlgorithm::RSA_PKCS1_3072_8192_SHA384 => {
                SignatureOp::Rsa(RsaSignatureOp::new(alg))
            }
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        };
        let handle = handles.signature_op.register(signature_op)?;
        Ok(handle)
    }
}

impl CryptoCtx {
    pub fn signature_op_open(&self, alg_str: &str) -> Result<Handle, CryptoError> {
        SignatureOp::open(&self.handles, alg_str)
    }

    pub fn signature_op_close(&self, handle: Handle) -> Result<(), CryptoError> {
        self.handles.signature_op.close(handle)
    }
}

impl WasiCryptoCtx {
    pub fn signature_op_open(
        &self,
        alg_str: &wiggle::GuestPtr<'_, str>,
    ) -> Result<guest_types::SignatureOp, CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
        let alg_str: &str = unsafe { &*alg_str.as_raw(&mut guest_borrow)? };
        Ok(self.ctx.signature_op_open(alg_str)?.into())
    }

    pub fn signature_op_close(
        &self,
        op_handle: guest_types::SignatureOp,
    ) -> Result<(), CryptoError> {
        self.ctx.signature_op_close(op_handle.into())
    }
}
