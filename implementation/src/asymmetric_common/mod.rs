use crate::array_output::*;
use crate::error::*;
use crate::handles::*;
use crate::signatures::*;
use crate::version::Version;
use crate::CryptoCtx;

use std::convert::TryFrom;

mod keypair;
mod managed_keypair;
mod publickey;
mod wasi_glue;

pub use self::keypair::{KeyPair, KeyPairEncoding};
pub use self::publickey::{PublicKey, PublicKeyEncoding};

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AsymmetricAlgorithm {
    Signature(SignatureAlgorithm),
}

impl TryFrom<&str> for AsymmetricAlgorithm {
    type Error = CryptoError;

    fn try_from(alg_str: &str) -> Result<Self, CryptoError> {
        match alg_str {
            "ECDSA_P256_SHA256" => Ok(AsymmetricAlgorithm::Signature(
                SignatureAlgorithm::ECDSA_P256_SHA256,
            )),
            "ECDSA_P384_SHA384" => Ok(AsymmetricAlgorithm::Signature(
                SignatureAlgorithm::ECDSA_P384_SHA384,
            )),
            "Ed25519" => Ok(AsymmetricAlgorithm::Signature(SignatureAlgorithm::Ed25519)),
            "RSA_PKCS1_2048_8192_SHA256" => Ok(AsymmetricAlgorithm::Signature(
                SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256,
            )),
            "RSA_PKCS1_2048_8192_SHA384" => Ok(AsymmetricAlgorithm::Signature(
                SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384,
            )),
            "RSA_PKCS1_2048_8192_SHA512" => Ok(AsymmetricAlgorithm::Signature(
                SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512,
            )),
            "RSA_PKCS1_3072_8192_SHA384" => Ok(AsymmetricAlgorithm::Signature(
                SignatureAlgorithm::RSA_PKCS1_3072_8192_SHA384,
            )),
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        }
    }
}
