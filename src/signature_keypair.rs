use super::ecdsa::*;
use super::eddsa::*;
use super::error::*;
use super::handles::*;
use super::rsa::*;
use super::signature_op::*;
use super::WASI_CRYPTO_CTX;

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
    let signature_op = WASI_CRYPTO_CTX.signature_op_manager.get(op_handle)?;
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
    let handle = WASI_CRYPTO_CTX
        .signature_keypair_builder_manager
        .register(kp_builder)?;
    Ok(handle)
}

pub fn signature_keypair_generate(kp_builder_handle: Handle) -> Result<Handle, Error> {
    let kp_builder = WASI_CRYPTO_CTX
        .signature_keypair_builder_manager
        .get(kp_builder_handle)?;
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
    let kp_builder = WASI_CRYPTO_CTX
        .signature_keypair_builder_manager
        .get(kp_builder_handle)?;
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

pub fn signature_keypair_id(kp_handle: Handle) -> Result<Vec<u8>, Error> {
    let _kp = WASI_CRYPTO_CTX.signature_keypair_manager.get(kp_handle)?;
    bail!("Unavailable")
}

pub fn signature_keypair_export(
    kp_handle: Handle,
    encoding: KeyPairEncoding,
) -> Result<Vec<u8>, Error> {
    let kp = WASI_CRYPTO_CTX.signature_keypair_manager.get(kp_handle)?;
    let encoded = kp.export(encoding)?;
    Ok(encoded)
}

pub fn signature_keypair_builder_close(handle: Handle) -> Result<(), Error> {
    WASI_CRYPTO_CTX
        .signature_keypair_builder_manager
        .close(handle)
}

pub fn signature_keypair_close(handle: Handle) -> Result<(), Error> {
    WASI_CRYPTO_CTX.signature_keypair_manager.close(handle)
}
