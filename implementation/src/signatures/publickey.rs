use super::ecdsa::*;
use super::eddsa::*;
use super::rsa::*;
use super::*;
use crate::asymmetric_common::*;
use crate::error::*;
#[derive(Clone, Debug)]
pub enum SignaturePublicKey {
    Ecdsa(EcdsaSignaturePublicKey),
    Eddsa(EddsaSignaturePublicKey),
    Rsa(RsaSignaturePublicKey),
}

impl SignaturePublicKey {
    pub fn alg(&self) -> SignatureAlgorithm {
        match self {
            SignaturePublicKey::Ecdsa(x) => x.alg,
            SignaturePublicKey::Eddsa(x) => x.alg,
            SignaturePublicKey::Rsa(x) => x.alg,
        }
    }

    pub(crate) fn import(
        alg: SignatureAlgorithm,
        encoded: &[u8],
        encoding: PublicKeyEncoding,
    ) -> Result<SignaturePublicKey, CryptoError> {
        let pk = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 | SignatureAlgorithm::ECDSA_K256_SHA256 => {
                SignaturePublicKey::Ecdsa(EcdsaSignaturePublicKey::import(alg, encoded, encoding)?)
            }
            SignatureAlgorithm::Ed25519 => {
                SignaturePublicKey::Eddsa(EddsaSignaturePublicKey::import(alg, encoded, encoding)?)
            }
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256
            | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384
            | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512
            | SignatureAlgorithm::RSA_PKCS1_3072_8192_SHA384 => {
                SignaturePublicKey::Rsa(RsaSignaturePublicKey::import(alg, encoded, encoding)?)
            }
        };
        Ok(pk)
    }

    pub(crate) fn export(&self, encoding: PublicKeyEncoding) -> Result<Vec<u8>, CryptoError> {
        let raw_pk = match self {
            SignaturePublicKey::Ecdsa(pk) => pk.export(encoding)?,
            SignaturePublicKey::Eddsa(pk) => pk.export(encoding)?,
            SignaturePublicKey::Rsa(pk) => pk.export(encoding)?,
        };
        Ok(raw_pk)
    }

    pub(crate) fn verify(_pk: SignaturePublicKey) -> Result<(), CryptoError> {
        bail!(CryptoError::NotImplemented)
    }
}
