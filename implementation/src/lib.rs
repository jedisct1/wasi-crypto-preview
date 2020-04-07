#[macro_use]
extern crate derivative;

mod array_output;
mod error;
mod handles;
mod options;
mod signatures;
mod symmetric;
mod version;

use array_output::*;
use handles::*;
use signatures::*;
use symmetric::*;

pub use error::CryptoError;
pub use handles::Handle;
pub use signatures::{KeyPairEncoding, PublicKeyEncoding, SignatureEncoding};
pub use version::Version;

#[allow(unused)]
static REBUILD_IF_WITX_FILE_IS_UPDATED: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../witx/wasi_ephemeral_crypto.witx"
));

wiggle::from_witx!({
    witx: ["../witx/wasi_ephemeral_crypto.witx"],
    ctx: WasiCryptoCtx
});

pub struct HandleManagers {
    pub signature_op: HandlesManager<SignatureOp>,
    pub signature_keypair_builder: HandlesManager<SignatureKeyPairBuilder>,
    pub signature_keypair: HandlesManager<SignatureKeyPair>,
    pub signature_state: HandlesManager<ExclusiveSignatureState>,
    pub signature: HandlesManager<Signature>,
    pub signature_publickey: HandlesManager<SignaturePublicKey>,
    pub signature_verification_state: HandlesManager<ExclusiveSignatureVerificationState>,
    pub array_output: HandlesManager<ArrayOutput>,
    pub symmetric_op: HandlesManager<SymmetricOp>,
    pub symmetric_key: HandlesManager<SymmetricKey>,
}

pub struct CryptoCtx {
    pub(crate) handles: HandleManagers,
}

pub struct WasiCryptoCtx {
    ctx: CryptoCtx,
}

impl CryptoCtx {
    pub fn new() -> Self {
        CryptoCtx {
            handles: HandleManagers {
                array_output: HandlesManager::new(0x00),
                signature_op: HandlesManager::new(0x01),
                signature_keypair_builder: HandlesManager::new(0x02),
                signature_keypair: HandlesManager::new(0x03),
                signature_state: HandlesManager::new(0x04),
                signature: HandlesManager::new(0x05),
                signature_publickey: HandlesManager::new(0x06),
                signature_verification_state: HandlesManager::new(0x07),
                symmetric_op: HandlesManager::new(0x08),
                symmetric_key: HandlesManager::new(0x09),
            },
        }
    }
}

impl WasiCryptoCtx {
    pub fn new() -> Self {
        WasiCryptoCtx {
            ctx: CryptoCtx::new(),
        }
    }
}
