#[macro_use]
extern crate lazy_static;

use anyhow::{anyhow, bail, ensure, Error};
use parking_lot::Mutex;
use ring::signature::KeyPair as _;
use std::collections::HashMap;
use std::mem;
use zeroize::Zeroize;

pub type Handle = u32;

struct HandlesManager<HandleType: Clone + Sync> {
    last_handle: Handle,
    map: HashMap<Handle, HandleType>,
    type_id: u8,
}

lazy_static! {
    static ref SIGNATURE_OP_MANAGER: Mutex<HandlesManager<SignatureOp>> =
        Mutex::new(HandlesManager::new(0x00));
}

impl<HandleType: Clone + Sync> HandlesManager<HandleType> {
    pub fn new(type_id: u8) -> Self {
        HandlesManager {
            last_handle: (type_id as Handle) << (mem::size_of::<Handle>() * 8 - 8),
            map: HashMap::new(),
            type_id,
        }
    }

    pub fn close(&mut self, handle: Handle) -> Result<(), Error> {
        self.map
            .remove(&handle)
            .ok_or(anyhow!("Handle was already closed"))?;
        Ok(())
    }

    fn next_handle(&self, handle: Handle) -> Handle {
        (handle.wrapping_add(1) & ((1 as Handle) << (mem::size_of::<Handle>() * 8 - 8) - 1))
            | (self.type_id as Handle)
    }

    pub fn register(&mut self, op: HandleType) -> Result<Handle, Error> {
        let mut handle = self.next_handle(self.last_handle);
        loop {
            if !self.map.contains_key(&handle) {
                break;
            }
            ensure!(handle != self.last_handle, "No more handles");
            handle = self.next_handle(self.last_handle);
        }
        self.last_handle = handle;
        ensure!(self.map.insert(handle, op).is_none(), "Collision");
        Ok(handle)
    }

    pub fn get(&mut self, handle: Handle) -> Result<&HandleType, Error> {
        let op = self
            .map
            .get(&handle)
            .ok_or(anyhow!("Unregistered handle"))?;
        Ok(op)
    }
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
#[derive(Clone, Debug)]
struct ECDSASignatureOp {
    alg: SignatureAlgorithm,
}

impl ECDSASignatureOp {
    fn new(alg: SignatureAlgorithm) -> Self {
        ECDSASignatureOp { alg }
    }
}

#[derive(Clone, Debug)]
struct EdDSASignatureOp {
    alg: SignatureAlgorithm,
}

impl EdDSASignatureOp {
    fn new(alg: SignatureAlgorithm) -> Self {
        EdDSASignatureOp { alg }
    }
}

#[derive(Clone, Debug)]
struct RSASignatureOp {
    alg: SignatureAlgorithm,
}

impl RSASignatureOp {
    fn new(alg: SignatureAlgorithm) -> Self {
        RSASignatureOp { alg }
    }
}

#[derive(Clone, Debug)]
enum SignatureOp {
    ECDSA(ECDSASignatureOp),
    EdDSA(EdDSASignatureOp),
    RSA(RSASignatureOp),
}

impl SignatureOp {
    pub fn pop(&mut self) {
        //
    }
}

pub fn signature_open(alg_str: &str) -> Result<Handle, Error> {
    let signature_op = match alg_str {
        "ECDSA_P256_SHA256" => {
            SignatureOp::ECDSA(ECDSASignatureOp::new(SignatureAlgorithm::ECDSA_P256_SHA256))
        }
        "ECDSA_P384_SHA384" => {
            SignatureOp::ECDSA(ECDSASignatureOp::new(SignatureAlgorithm::ECDSA_P384_SHA384))
        }
        "Ed25519" => SignatureOp::EdDSA(EdDSASignatureOp::new(SignatureAlgorithm::Ed25519)),
        "RSA_PKCS1_2048_8192_SHA256" => SignatureOp::RSA(RSASignatureOp::new(
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256,
        )),
        "RSA_PKCS1_2048_8192_SHA384" => SignatureOp::RSA(RSASignatureOp::new(
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384,
        )),
        "RSA_PKCS1_2048_8192_SHA512" => SignatureOp::RSA(RSASignatureOp::new(
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512,
        )),
        "RSA_PKCS1_3072_8192_SHA384" => SignatureOp::RSA(RSASignatureOp::new(
            SignatureAlgorithm::RSA_PKCS1_3072_8192_SHA384,
        )),
        _ => bail!("Unsupported algorithm"),
    };
    let handle = SIGNATURE_OP_MANAGER.lock().register(signature_op)?;
    Ok(handle)
}

pub fn signature_close(handle: Handle) -> Result<(), Error> {
    SIGNATURE_OP_MANAGER.lock().close(handle)
}

#[derive(Debug)]
pub struct ECDSAKeyPair {
    alg: SignatureAlgorithm,
    pkcs8: Vec<u8>,
    ring_kp: ring::signature::EcdsaKeyPair,
}

impl Drop for ECDSAKeyPair {
    fn drop(&mut self) {
        self.pkcs8.zeroize();
    }
}

impl ECDSAKeyPair {
    fn ring_alg_from_alg(
        alg: SignatureAlgorithm,
    ) -> Result<&'static ring::signature::EcdsaSigningAlgorithm, Error> {
        let ring_alg = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 => {
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING
            }
            SignatureAlgorithm::ECDSA_P384_SHA384 => {
                &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING
            }
            _ => bail!("Unsupported signature system"),
        };
        Ok(ring_alg)
    }

    pub fn from_pkcs8(alg: SignatureAlgorithm, pkcs8: &[u8]) -> Result<Self, Error> {
        let ring_alg = Self::ring_alg_from_alg(alg)?;
        let ring_kp = ring::signature::EcdsaKeyPair::from_pkcs8(ring_alg, pkcs8)
            .map_err(|_| anyhow!("Invalid key pair"))?;
        let kp = ECDSAKeyPair {
            alg,
            pkcs8: pkcs8.to_vec(),
            ring_kp,
        };
        Ok(kp)
    }

    pub fn as_pkcs8(&self) -> Result<&[u8], Error> {
        Ok(&self.pkcs8)
    }

    pub fn generate(alg: SignatureAlgorithm) -> Result<Self, Error> {
        let ring_alg = Self::ring_alg_from_alg(alg)?;
        let mut rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(ring_alg, &mut rng).unwrap();
        Self::from_pkcs8(alg, pkcs8.as_ref())
    }
}

pub fn signature_keypair_builder_open(op_handle: Handle) -> Result<(), Error> {
    let mut signature_op = SIGNATURE_OP_MANAGER.lock();
    let mut signature_op = signature_op.get(op_handle)?;
    signature_op.pop();
    Ok(())
}

#[derive(Debug)]
enum KeyPair {
    ECDSA(ECDSAKeyPair),
}

fn main() {
    let handle = signature_open("ECDSA_P256_SHA256").unwrap();
    println!("Hello, world!");
}
