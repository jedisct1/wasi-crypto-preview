use ed25519_dalek::Signer as _;
use std::sync::Arc;

use super::*;
use crate::asymmetric_common::*;
use crate::error::*;
use crate::rand::SecureRandom;

#[derive(Debug, Clone)]
pub struct EddsaSignatureSecretKey {
    pub alg: SignatureAlgorithm,
}

#[derive(Debug)]
pub struct EddsaSignatureKeyPair {
    pub alg: SignatureAlgorithm,
    pub dalek_kp: ed25519_dalek::Keypair,
}

impl Clone for EddsaSignatureKeyPair {
    fn clone(&self) -> Self {
        let dalek_kp = ed25519_dalek::Keypair::from_bytes(&self.dalek_kp.to_bytes()).unwrap();
        EddsaSignatureKeyPair {
            alg: self.alg,
            dalek_kp,
        }
    }
}

impl EddsaSignatureKeyPair {
    pub fn from_pkcs8(alg: SignatureAlgorithm, _pkcs8: &[u8]) -> Result<Self, CryptoError> {
        ensure!(
            alg == SignatureAlgorithm::Ed25519,
            CryptoError::UnsupportedAlgorithm
        );
        bail!(CryptoError::NotImplemented)
    }

    pub fn as_pkcs8(&self) -> Result<&[u8], CryptoError> {
        bail!(CryptoError::NotImplemented)
    }

    pub fn generate(
        alg: SignatureAlgorithm,
        _options: Option<SignatureOptions>,
    ) -> Result<Self, CryptoError> {
        let mut rng = SecureRandom::new();
        let dalek_kp = ed25519_dalek::Keypair::generate(&mut rng);
        Ok(EddsaSignatureKeyPair { alg, dalek_kp })
    }

    pub fn import(
        alg: SignatureAlgorithm,
        encoded: &[u8],
        encoding: KeyPairEncoding,
    ) -> Result<Self, CryptoError> {
        match encoding {
            KeyPairEncoding::Pkcs8 => {}
            _ => bail!(CryptoError::UnsupportedEncoding),
        };
        let kp = EddsaSignatureKeyPair::from_pkcs8(alg, encoded)?;
        Ok(kp)
    }

    pub fn raw_public_key(&self) -> &[u8] {
        self.dalek_kp.public.as_bytes()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EddsaSignature(pub Vec<u8>);

impl EddsaSignature {
    pub fn new(encoded: Vec<u8>) -> Self {
        EddsaSignature(encoded)
    }
}

impl SignatureLike for EddsaSignature {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug)]
pub struct EddsaSignatureState {
    pub kp: EddsaSignatureKeyPair,
    pub input: Vec<u8>,
}

impl EddsaSignatureState {
    pub fn new(kp: EddsaSignatureKeyPair) -> Self {
        EddsaSignatureState { kp, input: vec![] }
    }
}

impl SignatureStateLike for EddsaSignatureState {
    fn update(&mut self, input: &[u8]) -> Result<(), CryptoError> {
        self.input.extend_from_slice(input);
        Ok(())
    }

    fn sign(&mut self) -> Result<Signature, CryptoError> {
        let signature_u8 = Vec::from(self.kp.dalek_kp.sign(&self.input).to_bytes());
        let signature = EddsaSignature(signature_u8);
        Ok(Signature::new(Box::new(signature)))
    }
}

#[derive(Debug)]
pub struct EddsaSignatureVerificationState {
    pub pk: EddsaSignaturePublicKey,
    pub input: Vec<u8>,
}

impl EddsaSignatureVerificationState {
    pub fn new(pk: EddsaSignaturePublicKey) -> Self {
        EddsaSignatureVerificationState { pk, input: vec![] }
    }
}

impl SignatureVerificationStateLike for EddsaSignatureVerificationState {
    fn update(&mut self, input: &[u8]) -> Result<(), CryptoError> {
        self.input.extend_from_slice(input);
        Ok(())
    }

    fn verify(&self, signature: &Signature) -> Result<(), CryptoError> {
        let signature = signature.inner();
        let signature = signature
            .as_any()
            .downcast_ref::<EddsaSignature>()
            .ok_or(CryptoError::InvalidSignature)?;
        let mut signature_u8 = [0u8; 64];
        ensure!(
            signature.as_ref().len() == signature_u8.len(),
            CryptoError::InvalidSignature
        );
        signature_u8.copy_from_slice(signature.as_ref());
        let dalek_signature = ed25519_dalek::Signature::new(signature_u8);
        let dalek_pk = ed25519_dalek::PublicKey::from_bytes(self.pk.as_raw()?)
            .map_err(|_| CryptoError::InvalidKey)?;
        dalek_pk
            .verify_strict(self.input.as_ref(), &dalek_signature)
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct EddsaSignaturePublicKey {
    pub alg: SignatureAlgorithm,
    pub raw: Vec<u8>,
}

impl EddsaSignaturePublicKey {
    pub fn from_raw(alg: SignatureAlgorithm, raw: &[u8]) -> Result<Self, CryptoError> {
        let pk = EddsaSignaturePublicKey {
            alg,
            raw: raw.to_vec(),
        };
        Ok(pk)
    }

    pub fn as_raw(&self) -> Result<&[u8], CryptoError> {
        Ok(&self.raw)
    }
}
