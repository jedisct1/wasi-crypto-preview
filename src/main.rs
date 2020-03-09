#[macro_use]
extern crate lazy_static;

mod ecdsa;
mod eddsa;
mod error;
mod handles;
mod rsa;
mod signature;
mod signature_keypair;
mod signature_op;

use error::*;
use handles::*;
use signature::*;
use signature_keypair::*;
use signature_op::*;

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

fn main() {
    let op_handle = signature_op_open("ECDSA_P256_SHA256").unwrap();
    //let op_handle = signature_op_open("Ed25519").unwrap();
    //    let op_handle = signature_op_open("ECDSA_P384_SHA384").unwrap();
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

    dbg!(sig.len());

    signature_op_close(op_handle).unwrap();
    signature_keypair_builder_close(kp_builder).unwrap();
    signature_keypair_close(kp).unwrap();
    signature_state_close(state).unwrap();
    signature_close(sig_handle).unwrap();
}
