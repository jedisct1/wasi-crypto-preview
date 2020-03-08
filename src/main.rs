#[macro_use]
extern crate lazy_static;

use anyhow::{anyhow, bail, ensure, Error};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::Zeroize;

pub type Handle = u32;

struct HandlesManagerInner<HandleType: Clone + Sync> {
    last_handle: Handle,
    map: HashMap<Handle, HandleType>,
    type_id: u8,
}

struct HandlesManager<HandleType: Clone + Sync> {
    inner: Mutex<HandlesManagerInner<HandleType>>,
}

impl<HandleType: Clone + Sync> HandlesManager<HandleType> {
    fn new(handle_type: u8) -> Self {
        HandlesManager {
            inner: Mutex::new(HandlesManagerInner::new(handle_type)),
        }
    }

    pub fn close(&self, handle: Handle) -> Result<(), Error> {
        self.inner.lock().close(handle)
    }

    pub fn register(&self, op: HandleType) -> Result<Handle, Error> {
        self.inner.lock().register(op)
    }

    pub fn get(&self, handle: Handle) -> Result<HandleType, Error> {
        self.inner.lock().get(handle).map(|x| x.clone())
    }
}

// These maps should be stored in a WASI context
lazy_static! {
    static ref SIGNATURE_OP_MANAGER: HandlesManager<SignatureOp> = HandlesManager::new(0x00);
    static ref SIGNATURE_KEYPAIR_BUILDER_MANAGER: HandlesManager<SignatureKeyPairBuilder> =
        HandlesManager::new(0x01);
    static ref SIGNATURE_KEYPAIR_MANAGER: HandlesManager<SignatureKeyPair> =
        HandlesManager::new(0x02);
    static ref SIGNATURE_STATE_MANAGER: HandlesManager<ExclusiveSignatureState> =
        HandlesManager::new(0x03);
    static ref SIGNATURE_MANAGER: HandlesManager<Signature> = HandlesManager::new(0x04);
}

impl<HandleType: Clone + Sync> HandlesManagerInner<HandleType> {
    pub fn new(type_id: u8) -> Self {
        HandlesManagerInner {
            last_handle: (type_id as Handle).rotate_right(8),
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
        ((handle.wrapping_add(1) << 8) | (self.type_id as Handle)).rotate_right(8)
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
#[derive(Clone, Copy, Debug)]
struct ECDSASignatureOp {
    alg: SignatureAlgorithm,
}

impl ECDSASignatureOp {
    fn new(alg: SignatureAlgorithm) -> Self {
        ECDSASignatureOp { alg }
    }
}

#[derive(Clone, Copy, Debug)]
struct EdDSASignatureOp {
    alg: SignatureAlgorithm,
}

impl EdDSASignatureOp {
    fn new(alg: SignatureAlgorithm) -> Self {
        EdDSASignatureOp { alg }
    }
}

#[derive(Clone, Copy, Debug)]
struct RSASignatureOp {
    alg: SignatureAlgorithm,
}

impl RSASignatureOp {
    fn new(alg: SignatureAlgorithm) -> Self {
        RSASignatureOp { alg }
    }
}

#[derive(Clone, Copy, Debug)]
enum SignatureOp {
    ECDSA(ECDSASignatureOp),
    EdDSA(EdDSASignatureOp),
    RSA(RSASignatureOp),
}

impl SignatureOp {
    fn alg(&self) -> SignatureAlgorithm {
        match self {
            SignatureOp::ECDSA(op) => op.alg,
            SignatureOp::EdDSA(op) => op.alg,
            SignatureOp::RSA(op) => op.alg,
        }
    }
}

pub fn signature_op_open(alg_str: &str) -> Result<Handle, Error> {
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
    let handle = SIGNATURE_OP_MANAGER.register(signature_op)?;
    Ok(handle)
}

pub fn signature_op_close(handle: Handle) -> Result<(), Error> {
    SIGNATURE_OP_MANAGER.close(handle)
}

pub fn signature_keypair_builder_close(handle: Handle) -> Result<(), Error> {
    SIGNATURE_KEYPAIR_BUILDER_MANAGER.close(handle)
}

pub fn signature_keypair_close(handle: Handle) -> Result<(), Error> {
    SIGNATURE_KEYPAIR_MANAGER.close(handle)
}

pub fn signature_state_close(handle: Handle) -> Result<(), Error> {
    SIGNATURE_STATE_MANAGER.close(handle)
}

pub fn signature_close(handle: Handle) -> Result<(), Error> {
    SIGNATURE_MANAGER.close(handle)
}

#[derive(Debug, Clone)]
pub struct ECDSASignatureKeyPair {
    alg: SignatureAlgorithm,
    pkcs8: Vec<u8>,
    ring_kp: Arc<ring::signature::EcdsaKeyPair>,
}

impl Drop for ECDSASignatureKeyPair {
    fn drop(&mut self) {
        self.pkcs8.zeroize();
    }
}

impl ECDSASignatureKeyPair {
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
        let kp = ECDSASignatureKeyPair {
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
        let ring_alg = Self::ring_alg_from_alg(alg)?;
        let mut rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(ring_alg, &mut rng)
            .map_err(|_| anyhow!("RNG error"))?;
        Self::from_pkcs8(alg, pkcs8.as_ref())
    }
}

#[derive(Clone, Debug)]
struct EdDSASignatureKeyPair {
    alg: SignatureAlgorithm,
    pkcs8: Vec<u8>,
    ring_kp: Arc<ring::signature::Ed25519KeyPair>,
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
        let mut rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&mut rng)
            .map_err(|_| anyhow!("RNG error"))?;
        Self::from_pkcs8(alg, pkcs8.as_ref())
    }
}

impl Drop for EdDSASignatureKeyPair {
    fn drop(&mut self) {
        self.pkcs8.zeroize();
    }
}

#[derive(Clone, Debug)]
struct RSASignatureKeyPair {
    alg: SignatureAlgorithm,
    pkcs8: Vec<u8>,
    ring_kp: Arc<ring::signature::RsaKeyPair>,
}

impl RSASignatureKeyPair {
    pub fn from_pkcs8(alg: SignatureAlgorithm, pkcs8: &[u8]) -> Result<Self, Error> {
        let ring_kp = ring::signature::RsaKeyPair::from_pkcs8(pkcs8)
            .map_err(|_| anyhow!("Invalid key pair"))?;
        let kp = RSASignatureKeyPair {
            alg,
            pkcs8: pkcs8.to_vec(),
            ring_kp: Arc::new(ring_kp),
        };
        Ok(kp)
    }

    pub fn as_pkcs8(&self) -> Result<&[u8], Error> {
        Ok(&self.pkcs8)
    }

    #[allow(dead_code)]
    pub fn generate(_alg: SignatureAlgorithm) -> Result<Self, Error> {
        bail!("Unimplemented")
    }
}

pub enum KeyPairEncoding {
    Raw = 1,
    PKCS8 = 2,
}

#[derive(Clone, Copy, Debug)]
struct ECDSASignatureKeyPairBuilder {
    alg: SignatureAlgorithm,
}

#[derive(Clone, Copy, Debug)]
struct EdDSASignatureKeyPairBuilder {
    alg: SignatureAlgorithm,
}

#[derive(Clone, Copy, Debug)]
struct RSASignatureKeyPairBuilder {
    alg: SignatureAlgorithm,
}

impl ECDSASignatureKeyPairBuilder {
    fn new(alg: SignatureAlgorithm) -> Self {
        ECDSASignatureKeyPairBuilder { alg }
    }

    fn generate(&self) -> Result<Handle, Error> {
        let kp = ECDSASignatureKeyPair::generate(self.alg)?;
        let handle = SIGNATURE_KEYPAIR_MANAGER.register(SignatureKeyPair::ECDSA(kp))?;
        Ok(handle)
    }

    fn import(&self, encoded: &[u8], encoding: KeyPairEncoding) -> Result<Handle, Error> {
        match encoding {
            KeyPairEncoding::PKCS8 => {}
            _ => bail!("Unsupported"),
        };
        let kp = ECDSASignatureKeyPair::from_pkcs8(self.alg, encoded)?;
        let handle = SIGNATURE_KEYPAIR_MANAGER.register(SignatureKeyPair::ECDSA(kp))?;
        Ok(handle)
    }
}

impl EdDSASignatureKeyPairBuilder {
    fn new(alg: SignatureAlgorithm) -> Self {
        EdDSASignatureKeyPairBuilder { alg }
    }

    fn generate(&self) -> Result<Handle, Error> {
        let kp = EdDSASignatureKeyPair::generate(self.alg)?;
        let handle = SIGNATURE_KEYPAIR_MANAGER.register(SignatureKeyPair::EdDSA(kp))?;
        Ok(handle)
    }

    fn import(&self, encoded: &[u8], encoding: KeyPairEncoding) -> Result<Handle, Error> {
        match encoding {
            KeyPairEncoding::PKCS8 => {}
            _ => bail!("Unsupported"),
        };
        let kp = ECDSASignatureKeyPair::from_pkcs8(self.alg, encoded)?;
        let handle = SIGNATURE_KEYPAIR_MANAGER.register(SignatureKeyPair::ECDSA(kp))?;
        Ok(handle)
    }
}

impl RSASignatureKeyPairBuilder {
    fn new(alg: SignatureAlgorithm) -> Self {
        RSASignatureKeyPairBuilder { alg }
    }

    fn generate(&self) -> Result<Handle, Error> {
        bail!("Unimplemented")
    }

    fn import(&self, encoded: &[u8], encoding: KeyPairEncoding) -> Result<Handle, Error> {
        match encoding {
            KeyPairEncoding::PKCS8 => {}
            _ => bail!("Unsupported"),
        };
        let kp = RSASignatureKeyPair::from_pkcs8(self.alg, encoded)?;
        let handle = SIGNATURE_KEYPAIR_MANAGER.register(SignatureKeyPair::RSA(kp))?;
        Ok(handle)
    }
}

#[derive(Clone, Copy, Debug)]
enum SignatureKeyPairBuilder {
    ECDSA(ECDSASignatureKeyPairBuilder),
    EdDSA(EdDSASignatureKeyPairBuilder),
    RSA(RSASignatureKeyPairBuilder),
}

#[derive(Clone, Debug)]
enum SignatureKeyPair {
    ECDSA(ECDSASignatureKeyPair),
    EdDSA(EdDSASignatureKeyPair),
    RSA(RSASignatureKeyPair),
}

impl SignatureKeyPair {
    fn export(&self, encoding: KeyPairEncoding) -> Result<Vec<u8>, Error> {
        let encoded = match encoding {
            KeyPairEncoding::PKCS8 => match self {
                SignatureKeyPair::ECDSA(kp) => kp.as_pkcs8()?.to_vec(),
                SignatureKeyPair::EdDSA(kp) => kp.as_pkcs8()?.to_vec(),
                SignatureKeyPair::RSA(kp) => kp.as_pkcs8()?.to_vec(),
            },
            _ => bail!("Unimplemented"),
        };
        Ok(encoded)
    }
}

pub fn signature_keypair_builder_open(op_handle: Handle) -> Result<Handle, Error> {
    let signature_op = SIGNATURE_OP_MANAGER.get(op_handle)?;
    let kp_builder = match signature_op {
        SignatureOp::ECDSA(_) => {
            SignatureKeyPairBuilder::ECDSA(ECDSASignatureKeyPairBuilder::new(signature_op.alg()))
        }
        SignatureOp::EdDSA(_) => {
            SignatureKeyPairBuilder::EdDSA(EdDSASignatureKeyPairBuilder::new(signature_op.alg()))
        }
        SignatureOp::RSA(_) => {
            SignatureKeyPairBuilder::RSA(RSASignatureKeyPairBuilder::new(signature_op.alg()))
        }
    };
    let handle = SIGNATURE_KEYPAIR_BUILDER_MANAGER.register(kp_builder)?;
    Ok(handle)
}

pub fn signature_keypair_generate(kp_builder_handle: Handle) -> Result<Handle, Error> {
    let kp_builder = SIGNATURE_KEYPAIR_BUILDER_MANAGER.get(kp_builder_handle)?;
    let handle = match kp_builder {
        SignatureKeyPairBuilder::ECDSA(kp_builder) => kp_builder.generate()?,
        SignatureKeyPairBuilder::EdDSA(kp_builder) => kp_builder.generate()?,
        SignatureKeyPairBuilder::RSA(kp_builder) => kp_builder.generate()?,
    };
    Ok(handle)
}

pub fn signature_keypair_import(
    kp_builder_handle: Handle,
    encoded: &[u8],
    encoding: KeyPairEncoding,
) -> Result<Handle, Error> {
    let kp_builder = SIGNATURE_KEYPAIR_BUILDER_MANAGER.get(kp_builder_handle)?;
    let handle = match kp_builder {
        SignatureKeyPairBuilder::ECDSA(kp_builder) => kp_builder.import(encoded, encoding)?,
        SignatureKeyPairBuilder::EdDSA(kp_builder) => kp_builder.import(encoded, encoding)?,
        SignatureKeyPairBuilder::RSA(kp_builder) => kp_builder.import(encoded, encoding)?,
    };
    Ok(handle)
}

pub fn signature_keypair_export(
    kp_handle: Handle,
    encoding: KeyPairEncoding,
) -> Result<Vec<u8>, Error> {
    let kp = SIGNATURE_KEYPAIR_MANAGER.get(kp_handle)?;
    let encoded = kp.export(encoding)?;
    Ok(encoded)
}

#[derive(Debug)]
struct ECDSASignatureState {
    kp: ECDSASignatureKeyPair,
    input: Mutex<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ECDSASignature(Vec<u8>);

impl AsRef<[u8]> for ECDSASignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ECDSASignatureState {
    fn new(kp: ECDSASignatureKeyPair) -> Self {
        ECDSASignatureState {
            kp,
            input: Mutex::new(vec![]),
        }
    }

    fn update(&self, input: &[u8]) -> Result<(), Error> {
        self.input.lock().extend_from_slice(input);
        Ok(())
    }

    fn sign(&self) -> Result<ECDSASignature, Error> {
        let mut rng = ring::rand::SystemRandom::new();
        let input = self.input.lock();
        let signature_u8 = self
            .kp
            .ring_kp
            .sign(&mut rng, &input)
            .map_err(|_| anyhow!("Unable to sign"))?
            .as_ref()
            .to_vec();
        let signature = ECDSASignature(signature_u8);
        Ok(signature)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EdDSASignature(Vec<u8>);

impl AsRef<[u8]> for EdDSASignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug)]
struct EdDSASignatureState {
    kp: EdDSASignatureKeyPair,
    input: Mutex<Vec<u8>>,
}

impl EdDSASignatureState {
    fn new(kp: EdDSASignatureKeyPair) -> Self {
        EdDSASignatureState {
            kp,
            input: Mutex::new(vec![]),
        }
    }

    fn update(&self, input: &[u8]) -> Result<(), Error> {
        self.input.lock().extend_from_slice(input);
        Ok(())
    }

    fn sign(&self) -> Result<EdDSASignature, Error> {
        let input = self.input.lock();
        let signature_u8 = self.kp.ring_kp.sign(&input).as_ref().to_vec();
        let signature = EdDSASignature(signature_u8);
        Ok(signature)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RSASignature(Vec<u8>);

impl AsRef<[u8]> for RSASignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug)]
struct RSASignatureState {
    kp: RSASignatureKeyPair,
    input: Mutex<Vec<u8>>,
}

impl RSASignatureState {
    fn new(kp: RSASignatureKeyPair) -> Self {
        RSASignatureState {
            kp,
            input: Mutex::new(vec![]),
        }
    }

    fn update(&self, input: &[u8]) -> Result<(), Error> {
        self.input.lock().extend_from_slice(input);
        Ok(())
    }

    fn sign(&self) -> Result<RSASignature, Error> {
        let mut rng = ring::rand::SystemRandom::new();
        let input = self.input.lock();
        let mut signature_u8 = vec![];
        let padding_alg = match self.kp.alg {
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256 => &ring::signature::RSA_PKCS1_SHA256,
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384 => &ring::signature::RSA_PKCS1_SHA384,
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512 => &ring::signature::RSA_PKCS1_SHA512,
            SignatureAlgorithm::RSA_PKCS1_3072_8192_SHA384 => &ring::signature::RSA_PKCS1_SHA384,
            _ => bail!("Unexpected configuration"),
        };
        self.kp
            .ring_kp
            .sign(padding_alg, &mut rng, &input, &mut signature_u8)
            .map_err(|_| anyhow!("Unable to sign"))?;
        let signature = RSASignature(signature_u8);
        Ok(signature)
    }
}

#[derive(Clone, Debug)]
enum Signature {
    ECDSA(ECDSASignature),
    EdDSA(EdDSASignature),
    RSA(RSASignature),
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Signature::ECDSA(signature) => signature.as_ref(),
            Signature::EdDSA(signature) => signature.as_ref(),
            Signature::RSA(signature) => signature.as_ref(),
        }
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        ring::constant_time::verify_slices_are_equal(self.as_ref(), other.as_ref()).is_ok()
    }
}

impl Eq for Signature {}

#[derive(Debug)]
enum SignatureState {
    ECDSA(ECDSASignatureState),
    EdDSA(EdDSASignatureState),
    RSA(RSASignatureState),
}

#[derive(Debug, Clone)]
struct ExclusiveSignatureState {
    state: Arc<SignatureState>,
}

impl ExclusiveSignatureState {
    pub fn new(signature_state: SignatureState) -> Self {
        ExclusiveSignatureState {
            state: Arc::new(signature_state),
        }
    }

    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        match self.state.as_ref() {
            SignatureState::ECDSA(state) => state.update(input),
            SignatureState::EdDSA(state) => state.update(input),
            SignatureState::RSA(state) => state.update(input),
        }
    }

    pub fn sign(&mut self) -> Result<Signature, Error> {
        let signature = match self.state.as_ref() {
            SignatureState::ECDSA(state) => Signature::ECDSA(state.sign()?),
            SignatureState::EdDSA(state) => Signature::EdDSA(state.sign()?),
            SignatureState::RSA(state) => Signature::RSA(state.sign()?),
        };
        Ok(signature)
    }
}

pub fn signature_state_open(kp_handle: Handle) -> Result<Handle, Error> {
    let kp = SIGNATURE_KEYPAIR_MANAGER.get(kp_handle)?;
    let signature_state = match kp {
        SignatureKeyPair::ECDSA(kp) => {
            ExclusiveSignatureState::new(SignatureState::ECDSA(ECDSASignatureState::new(kp)))
        }
        SignatureKeyPair::EdDSA(kp) => {
            ExclusiveSignatureState::new(SignatureState::EdDSA(EdDSASignatureState::new(kp)))
        }
        SignatureKeyPair::RSA(kp) => {
            ExclusiveSignatureState::new(SignatureState::RSA(RSASignatureState::new(kp)))
        }
    };
    let handle = SIGNATURE_STATE_MANAGER.register(signature_state)?;
    Ok(handle)
}

pub fn signature_state_update(state_handle: Handle, input: &[u8]) -> Result<(), Error> {
    let mut state = SIGNATURE_STATE_MANAGER.get(state_handle)?;
    state.update(input)
}

pub fn signature_state_sign(state_handle: Handle) -> Result<Handle, Error> {
    let mut state = SIGNATURE_STATE_MANAGER.get(state_handle)?;
    let signature = state.sign()?;
    let handle = SIGNATURE_MANAGER.register(signature)?;
    Ok(handle)
}

pub enum SignatureEncoding {
    Raw = 1,
    Hex = 2,
    Base64Original = 3,
    Base64OriginalNoPadding = 4,
    Base64URLSafe = 5,
    Base64URLSafeNoPadding = 6,
}

pub fn signature_export(
    signature_handle: Handle,
    encoding: SignatureEncoding,
) -> Result<Vec<u8>, Error> {
    match encoding {
        SignatureEncoding::Raw => {}
        _ => bail!("Unimplemented"),
    }
    let signature = SIGNATURE_MANAGER.get(signature_handle)?;
    Ok(signature.as_ref().to_vec())
}

fn main() {
    //    let op_handle = signature_open("ECDSA_P256_SHA256").unwrap();
    //let op_handle = signature_open("Ed25519").unwrap();
    let op_handle = signature_op_open("ECDSA_P384_SHA384").unwrap();
    let kp_builder = signature_keypair_builder_open(op_handle).unwrap();
    dbg!(op_handle);
    dbg!(kp_builder);
    let kp = signature_keypair_generate(kp_builder).unwrap();
    dbg!(kp);
    println!("Hello, world!");
    let encoded = signature_keypair_export(kp, KeyPairEncoding::PKCS8).unwrap();
    dbg!(encoded.len());
    let state = signature_state_open(kp).unwrap();
    dbg!(state);

    signature_state_update(state, b"test").unwrap();
    let sig_handle = signature_state_sign(state).unwrap();
    dbg!(sig_handle);
    let sig_handle2 = signature_state_sign(state).unwrap();
    dbg!(sig_handle2);

    let sig = signature_export(sig_handle, SignatureEncoding::Raw).unwrap();
    dbg!(&sig);
    let sig2 = signature_export(sig_handle, SignatureEncoding::Raw).unwrap();
    dbg!(&sig2);

    signature_op_close(op_handle).unwrap();
    signature_keypair_builder_close(kp_builder).unwrap();
    signature_keypair_close(kp).unwrap();
    signature_state_close(state).unwrap();
    signature_close(sig_handle).unwrap();
}
