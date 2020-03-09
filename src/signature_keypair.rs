use parking_lot::Mutex;
use std::sync::Arc;

use super::ecdsa::*;
use super::eddsa::*;
use super::error::*;
use super::handles::*;
use super::rsa::*;
use super::signature_op::*;
use super::{SIGNATURE_KEYPAIR_BUILDER_MANAGER, SIGNATURE_KEYPAIR_MANAGER, SIGNATURE_OP_MANAGER};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPairEncoding {
    Raw = 1,
    PKCS8 = 2,
}

#[derive(Clone, Copy, Debug)]
pub enum SignatureKeyPairBuilder {
    ECDSA(ECDSASignatureKeyPairBuilder),
    EdDSA(EdDSASignatureKeyPairBuilder),
    RSA(RSASignatureKeyPairBuilder),
}

#[derive(Clone, Debug)]
pub enum SignatureKeyPair {
    ECDSA(ECDSASignatureKeyPair),
    EdDSA(EdDSASignatureKeyPair),
    RSA(RSASignatureKeyPair),
}

impl SignatureKeyPair {
    pub fn export(&self, encoding: KeyPairEncoding) -> Result<Vec<u8>, Error> {
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

pub fn signature_keypair_from_id(_kp_builder_handle: Handle, _id: &[u8]) -> Result<Handle, Error> {
    bail!("Unimplemented")
}

pub fn signature_keypair_export(
    kp_handle: Handle,
    encoding: KeyPairEncoding,
) -> Result<Vec<u8>, Error> {
    let kp = SIGNATURE_KEYPAIR_MANAGER.get(kp_handle)?;
    let encoded = kp.export(encoding)?;
    Ok(encoded)
}

pub fn signature_keypair_builder_close(handle: Handle) -> Result<(), Error> {
    SIGNATURE_KEYPAIR_BUILDER_MANAGER.close(handle)
}

pub fn signature_keypair_close(handle: Handle) -> Result<(), Error> {
    SIGNATURE_KEYPAIR_MANAGER.close(handle)
}
