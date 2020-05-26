use super::*;
use crate::types as guest_types;

use std::convert::TryFrom;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPairEncoding {
    Raw,
    Pkcs8,
    Der,
    Pem,
}

impl From<guest_types::KeypairEncoding> for KeyPairEncoding {
    fn from(encoding: guest_types::KeypairEncoding) -> Self {
        match encoding {
            guest_types::KeypairEncoding::Raw => KeyPairEncoding::Raw,
            guest_types::KeypairEncoding::Pkcs8 => KeyPairEncoding::Pkcs8,
            guest_types::KeypairEncoding::Der => KeyPairEncoding::Der,
            guest_types::KeypairEncoding::Pem => KeyPairEncoding::Pem,
        }
    }
}

#[derive(Clone, Debug)]
pub enum KeyPair {
    Signature(SignatureKeyPair),
}

impl KeyPair {
    pub(crate) fn into_signature_keypair(self) -> Result<SignatureKeyPair, CryptoError> {
        match self {
            KeyPair::Signature(kp) => Ok(kp),
        }
    }

    pub fn export(&self, encoding: KeyPairEncoding) -> Result<Vec<u8>, CryptoError> {
        match self {
            KeyPair::Signature(key_pair) => key_pair.export(encoding),
        }
    }

    pub fn generate(
        alg_str: &str,
        options: Option<SignatureOptions>,
    ) -> Result<KeyPair, CryptoError> {
        match AsymmetricAlgorithm::try_from(alg_str)? {
            AsymmetricAlgorithm::Signature(alg) => Ok(KeyPair::Signature(
                SignatureKeyPair::generate(alg, options)?,
            )),
        }
    }

    pub fn import(
        alg_str: &str,
        encoded: &[u8],
        encoding: KeyPairEncoding,
    ) -> Result<KeyPair, CryptoError> {
        match AsymmetricAlgorithm::try_from(alg_str)? {
            AsymmetricAlgorithm::Signature(alg) => Ok(KeyPair::Signature(
                SignatureKeyPair::import(alg, encoded, encoding)?,
            )),
        }
    }

    pub fn public_key(&self) -> Result<PublicKey, CryptoError> {
        match self {
            KeyPair::Signature(key_pair) => Ok(PublicKey::Signature(key_pair.public_key()?)),
        }
    }
}

impl CryptoCtx {
    pub fn keypair_generate(
        &self,
        alg_str: &str,
        options_handle: Option<Handle>,
    ) -> Result<Handle, CryptoError> {
        let options = match options_handle {
            None => None,
            Some(options_handle) => Some(
                self.handles
                    .options
                    .get(options_handle)?
                    .into_signatures()?,
            ),
        };
        let kp = KeyPair::generate(alg_str, options)?;
        let handle = self.handles.keypair.register(kp)?;
        Ok(handle)
    }

    pub fn keypair_import(
        &self,
        alg_str: &str,
        encoded: &[u8],
        encoding: KeyPairEncoding,
    ) -> Result<Handle, CryptoError> {
        let kp = KeyPair::import(alg_str, encoded, encoding)?;
        let handle = self.handles.keypair.register(kp)?;
        Ok(handle)
    }

    pub fn keypair_id(&self, kp_handle: Handle) -> Result<(Vec<u8>, Version), CryptoError> {
        let _kp = self.handles.keypair.get(kp_handle)?;
        bail!(CryptoError::UnsupportedFeature)
    }

    pub fn keypair_export(
        &self,
        kp_handle: Handle,
        encoding: KeyPairEncoding,
    ) -> Result<Handle, CryptoError> {
        let kp = self.handles.keypair.get(kp_handle)?;
        let encoded = kp.export(encoding)?;
        let array_output_handle = ArrayOutput::register(&self.handles, encoded)?;
        Ok(array_output_handle)
    }

    pub fn keypair_publickey(&self, kp_handle: Handle) -> Result<Handle, CryptoError> {
        let kp = self.handles.keypair.get(kp_handle)?;
        let pk = kp.public_key()?;
        let handle = self.handles.publickey.register(pk)?;
        Ok(handle)
    }

    pub fn keypair_close(&self, kp_handle: Handle) -> Result<(), CryptoError> {
        self.handles.keypair.close(kp_handle)
    }
}