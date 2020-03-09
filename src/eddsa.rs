use parking_lot::Mutex;
use std::sync::Arc;
use zeroize::Zeroize;

use super::error::*;
use super::handles::*;
use super::signature::*;
use super::signature_keypair::*;
use super::WASI_CRYPTO_CTX;

#[derive(Clone, Copy, Debug)]
pub struct EdDSASignatureOp {
    pub alg: SignatureAlgorithm,
}

impl EdDSASignatureOp {
    pub fn new(alg: SignatureAlgorithm) -> Self {
        EdDSASignatureOp { alg }
    }
}

#[derive(Clone, Debug)]
pub struct EdDSASignatureKeyPair {
    pub alg: SignatureAlgorithm,
    pub pkcs8: Vec<u8>,
    pub ring_kp: Arc<ring::signature::Ed25519KeyPair>,
}

impl EdDSASignatureKeyPair {
    pub fn from_pkcs8(alg: SignatureAlgorithm, pkcs8: &[u8]) -> Result<Self, Error> {
        let ring_kp = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| anyhow!("Invalid key pair"))?;
        let kp = EdDSASignatureKeyPair {
            alg,
            pkcs8: pkcs8.to_vec(),
            ring_kp: Arc::new(ring_kp),
        };
        Ok(kp)
    }

    pub fn as_pkcs8(&self) -> Result<&[u8], Error> {
        Ok(&self.pkcs8)
    }

    pub fn generate(alg: SignatureAlgorithm) -> Result<Self, Error> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| anyhow!("RNG error"))?;
        Self::from_pkcs8(alg, pkcs8.as_ref())
    }
}

impl Drop for EdDSASignatureKeyPair {
    fn drop(&mut self) {
        self.pkcs8.zeroize();
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EdDSASignatureKeyPairBuilder {
    pub alg: SignatureAlgorithm,
}

impl EdDSASignatureKeyPairBuilder {
    pub fn new(alg: SignatureAlgorithm) -> Self {
        EdDSASignatureKeyPairBuilder { alg }
    }

    pub fn generate(&self) -> Result<Handle, Error> {
        let kp = EdDSASignatureKeyPair::generate(self.alg)?;
        let handle = WASI_CRYPTO_CTX
            .signature_keypair_manager
            .register(SignatureKeyPair::EdDSA(kp))?;
        Ok(handle)
    }

    pub fn import(&self, encoded: &[u8], encoding: KeyPairEncoding) -> Result<Handle, Error> {
        match encoding {
            KeyPairEncoding::PKCS8 => {}
            _ => bail!("Unsupported"),
        };
        let kp = EdDSASignatureKeyPair::from_pkcs8(self.alg, encoded)?;
        let handle = WASI_CRYPTO_CTX
            .signature_keypair_manager
            .register(SignatureKeyPair::EdDSA(kp))?;
        Ok(handle)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdDSASignature(pub Vec<u8>);

impl AsRef<[u8]> for EdDSASignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug)]
pub struct EdDSASignatureState {
    pub kp: EdDSASignatureKeyPair,
    pub input: Mutex<Vec<u8>>,
}

impl EdDSASignatureState {
    pub fn new(kp: EdDSASignatureKeyPair) -> Self {
        EdDSASignatureState {
            kp,
            input: Mutex::new(vec![]),
        }
    }

    pub fn update(&self, input: &[u8]) -> Result<(), Error> {
        self.input.lock().extend_from_slice(input);
        Ok(())
    }

    pub fn sign(&self) -> Result<EdDSASignature, Error> {
        let input = self.input.lock();
        let signature_u8 = self.kp.ring_kp.sign(&input).as_ref().to_vec();
        let signature = EdDSASignature(signature_u8);
        Ok(signature)
    }
}

#[derive(Clone, Debug)]
pub struct EdDSASignaturePublicKey {
    pub alg: SignatureAlgorithm,
    pub raw: Vec<u8>,
}

impl EdDSASignaturePublicKey {
    pub fn from_raw(alg: SignatureAlgorithm, raw: &[u8]) -> Result<Self, Error> {
        let pk = EdDSASignaturePublicKey {
            alg,
            raw: raw.to_vec(),
        };
        Ok(pk)
    }
}
