use super::ecdsa::*;
use super::eddsa::*;
use super::error::*;
use super::handles::*;
use super::rsa::*;
use super::signature::*;
use super::SIGNATURE_OP_MANAGER;

#[derive(Clone, Copy, Debug)]
pub enum SignatureOp {
    ECDSA(ECDSASignatureOp),
    EdDSA(EdDSASignatureOp),
    RSA(RSASignatureOp),
}

impl SignatureOp {
    pub fn alg(self) -> SignatureAlgorithm {
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
