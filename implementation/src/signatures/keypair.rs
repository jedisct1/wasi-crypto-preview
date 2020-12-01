use super::ecdsa::*;
use super::eddsa::*;
use super::publickey::*;
use super::rsa::*;
use super::*;
use crate::asymmetric_common::*;
use crate::error::*;

#[derive(Clone)]
pub enum SignatureKeyPair {
    Ecdsa(EcdsaSignatureKeyPair),
    Eddsa(EddsaSignatureKeyPair),
    Rsa(RsaSignatureKeyPair),
}

impl SignatureKeyPair {
    pub(crate) fn export(&self, encoding: KeyPairEncoding) -> Result<Vec<u8>, CryptoError> {
        let encoded = match self {
            SignatureKeyPair::Ecdsa(kp) => kp.export(encoding)?,
            SignatureKeyPair::Eddsa(kp) => kp.export(encoding)?,
            SignatureKeyPair::Rsa(kp) => kp.export(encoding)?,
        };
        Ok(encoded)
    }

    pub(crate) fn generate(
        alg: SignatureAlgorithm,
        options: Option<SignatureOptions>,
    ) -> Result<SignatureKeyPair, CryptoError> {
        let kp = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 | SignatureAlgorithm::ECDSA_K256_SHA256 => {
                SignatureKeyPair::Ecdsa(EcdsaSignatureKeyPair::generate(alg, options)?)
            }
            SignatureAlgorithm::Ed25519 => {
                SignatureKeyPair::Eddsa(EddsaSignatureKeyPair::generate(alg, options)?)
            }
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256
            | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384
            | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512
            | SignatureAlgorithm::RSA_PKCS1_3072_8192_SHA384 => {
                SignatureKeyPair::Rsa(RsaSignatureKeyPair::generate(alg, options)?)
            }
        };
        Ok(kp)
    }

    pub(crate) fn import(
        alg: SignatureAlgorithm,
        encoded: &[u8],
        encoding: KeyPairEncoding,
    ) -> Result<SignatureKeyPair, CryptoError> {
        let kp = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 | SignatureAlgorithm::ECDSA_K256_SHA256 => {
                SignatureKeyPair::Ecdsa(EcdsaSignatureKeyPair::import(alg, encoded, encoding)?)
            }
            SignatureAlgorithm::Ed25519 => {
                SignatureKeyPair::Eddsa(EddsaSignatureKeyPair::import(alg, encoded, encoding)?)
            }
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256
            | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384
            | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512
            | SignatureAlgorithm::RSA_PKCS1_3072_8192_SHA384 => {
                SignatureKeyPair::Rsa(RsaSignatureKeyPair::import(alg, encoded, encoding)?)
            }
        };
        Ok(kp)
    }

    pub(crate) fn public_key(&self) -> Result<SignaturePublicKey, CryptoError> {
        let pk = match self {
            SignatureKeyPair::Ecdsa(kp) => SignaturePublicKey::Ecdsa(kp.public_key()?),
            SignatureKeyPair::Eddsa(kp) => SignaturePublicKey::Eddsa(kp.public_key()?),
            SignatureKeyPair::Rsa(kp) => SignaturePublicKey::Rsa(kp.public_key()?),
        };
        Ok(pk)
    }

    pub(crate) fn secret_key(&self) -> Result<SignatureSecretKey, CryptoError> {
        bail!(CryptoError::NotImplemented)
    }
}
