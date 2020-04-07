mod ecdsa;
mod eddsa;
mod rsa;
mod signature;
mod signature_keypair;
mod signature_op;
mod signature_publickey;

pub use signature::*;
pub use signature_keypair::*;
pub use signature_op::*;
pub use signature_publickey::*;

#[test]
fn test_signatures() {
    use crate::CryptoCtx;

    let ctx = CryptoCtx::new();
    let op_handle = ctx.signature_op_open("ECDSA_P256_SHA256").unwrap();
    let kp_builder_handle = ctx.signature_keypair_builder_open(op_handle).unwrap();
    let kp_handle = ctx.signature_keypair_generate(kp_builder_handle).unwrap();
    let state_handle = ctx.signature_state_open(kp_handle).unwrap();
    ctx.signature_state_update(state_handle, b"test").unwrap();
    let signature_handle = ctx.signature_state_sign(state_handle).unwrap();

    let pk_handle = ctx.signature_keypair_publickey(kp_handle).unwrap();

    let verification_state_handle = ctx.signature_verification_state_open(pk_handle).unwrap();
    ctx.signature_verification_state_update(verification_state_handle, b"test")
        .unwrap();
    ctx.signature_verification_state_verify(verification_state_handle, signature_handle)
        .unwrap();

    ctx.signature_op_close(op_handle).unwrap();
    ctx.signature_keypair_builder_close(kp_builder_handle)
        .unwrap();
    ctx.signature_keypair_close(kp_handle).unwrap();
    ctx.signature_state_close(state_handle).unwrap();
    ctx.signature_verification_state_close(verification_state_handle)
        .unwrap();
    ctx.signature_close(signature_handle).unwrap();
}
