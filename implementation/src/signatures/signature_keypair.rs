use super::ecdsa::*;
use super::eddsa::*;
use super::rsa::*;
use super::signature_op::*;
use super::signature_publickey::*;
use crate::array_output::*;
use crate::error::*;
use crate::handles::*;
use crate::types as guest_types;
use crate::version::Version;
use crate::{CryptoCtx, HandleManagers, WasiCryptoCtx};

use std::convert::{TryFrom, TryInto};

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
pub enum SignatureKeyPair {
    Ecdsa(EcdsaSignatureKeyPair),
    Eddsa(EddsaSignatureKeyPair),
    Rsa(RsaSignatureKeyPair),
}

impl SignatureKeyPair {
    fn export(&self, encoding: KeyPairEncoding) -> Result<Vec<u8>, CryptoError> {
        let encoded = match encoding {
            KeyPairEncoding::Pkcs8 => match self {
                SignatureKeyPair::Ecdsa(kp) => kp.as_pkcs8()?.to_vec(),
                SignatureKeyPair::Eddsa(kp) => kp.as_pkcs8()?.to_vec(),
                SignatureKeyPair::Rsa(kp) => kp.as_pkcs8()?.to_vec(),
            },
            _ => bail!(CryptoError::UnsupportedEncoding),
        };
        Ok(encoded)
    }

    fn generate(handles: &HandleManagers, alg_str: &str) -> Result<Handle, CryptoError> {
        let alg = SignatureAlgorithm::try_from(alg_str)?;
        let kp = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 | SignatureAlgorithm::ECDSA_P384_SHA384 => {
                SignatureKeyPair::Ecdsa(EcdsaSignatureKeyPair::generate(alg)?)
            }
            SignatureAlgorithm::Ed25519 => {
                SignatureKeyPair::Eddsa(EddsaSignatureKeyPair::generate(alg)?)
            }
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256
            | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384
            | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512
            | SignatureAlgorithm::RSA_PKCS1_3072_8192_SHA384 => {
                SignatureKeyPair::Rsa(RsaSignatureKeyPair::generate(alg)?)
            }
        };
        let handle = handles.signature_keypair.register(kp)?;
        Ok(handle)
    }

    fn import(
        handles: &HandleManagers,
        alg_str: &str,
        encoded: &[u8],
        encoding: KeyPairEncoding,
    ) -> Result<Handle, CryptoError> {
        let alg = SignatureAlgorithm::try_from(alg_str)?;
        let kp = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 | SignatureAlgorithm::ECDSA_P384_SHA384 => {
                SignatureKeyPair::Ecdsa(EcdsaSignatureKeyPair::import(alg, encoded, encoding)?)
            }
            SignatureAlgorithm::Ed25519 => {
                SignatureKeyPair::Eddsa(EddsaSignatureKeyPair::import(alg, encoded, encoding)?)
            }
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256
            | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384
            | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512
            | SignatureAlgorithm::RSA_PKCS1_3072_8192_SHA384 => {
                SignatureKeyPair::Rsa(RsaSignatureKeyPair::import(alg, encoded, encoding)?)
            }
        };
        let handle = handles.signature_keypair.register(kp)?;
        Ok(handle)
    }

    fn public_key(&self, handles: &HandleManagers) -> Result<Handle, CryptoError> {
        let pk = match self {
            SignatureKeyPair::Ecdsa(kp) => {
                let raw_pk = kp.raw_public_key();
                SignaturePublicKey::Ecdsa(EcdsaSignaturePublicKey::from_raw(kp.alg, raw_pk)?)
            }
            SignatureKeyPair::Eddsa(kp) => {
                let raw_pk = kp.raw_public_key();
                SignaturePublicKey::Eddsa(EddsaSignaturePublicKey::from_raw(kp.alg, raw_pk)?)
            }
            SignatureKeyPair::Rsa(kp) => {
                let raw_pk = kp.raw_public_key();
                SignaturePublicKey::Rsa(RsaSignaturePublicKey::from_raw(kp.alg, raw_pk)?)
            }
        };
        let handle = handles.signature_publickey.register(pk)?;
        Ok(handle)
    }
}

impl CryptoCtx {
    pub fn signature_keypair_builder_open(&self) -> Result<Handle, CryptoError> {
        bail!(CryptoError::UnsupportedFeature)
    }

    pub fn signature_keypair_builder_close(
        &self,
        _kp_builder_handle: Handle,
    ) -> Result<(), CryptoError> {
        bail!(CryptoError::UnsupportedFeature)
    }

    pub fn signature_keypair_generate(&self, alg_str: &str) -> Result<Handle, CryptoError> {
        SignatureKeyPair::generate(&self.handles, alg_str)
    }

    pub fn signature_keypair_import(
        &self,
        alg_str: &str,
        encoded: &[u8],
        encoding: KeyPairEncoding,
    ) -> Result<Handle, CryptoError> {
        SignatureKeyPair::import(&self.handles, alg_str, encoded, encoding)
    }

    pub fn signature_keypair_from_id(
        &self,
        _kp_builder_handle: Handle,
        _kp_id: &[u8],
        _kp_version: Version,
    ) -> Result<Handle, CryptoError> {
        bail!(CryptoError::UnsupportedFeature)
    }

    pub fn signature_keypair_id(
        &self,
        kp_handle: Handle,
    ) -> Result<(Vec<u8>, Version), CryptoError> {
        let _kp = self.handles.signature_keypair.get(kp_handle)?;
        bail!(CryptoError::UnsupportedFeature)
    }

    pub fn signature_keypair_invalidate(
        &self,
        _kp_builder_handle: Handle,
        _kp_id: &[u8],
        _kp_version: Version,
    ) -> Result<(), CryptoError> {
        bail!(CryptoError::UnsupportedFeature)
    }

    pub fn signature_keypair_export(
        &self,
        kp_handle: Handle,
        encoding: KeyPairEncoding,
    ) -> Result<Handle, CryptoError> {
        let kp = self.handles.signature_keypair.get(kp_handle)?;
        let encoded = kp.export(encoding)?;
        let array_output_handle = ArrayOutput::register(&self.handles, encoded)?;
        Ok(array_output_handle)
    }

    pub fn signature_keypair_publickey(&self, kp_handle: Handle) -> Result<Handle, CryptoError> {
        let kp = self.handles.signature_keypair.get(kp_handle)?;
        let handle = kp.public_key(&self.handles)?;
        Ok(handle)
    }

    pub fn signature_keypair_close(&self, kp_handle: Handle) -> Result<(), CryptoError> {
        self.handles.signature_keypair.close(kp_handle)
    }
}

impl WasiCryptoCtx {
    pub fn signature_keypair_builder_open(
        &self,
    ) -> Result<guest_types::SignatureKeypairBuilder, CryptoError> {
        Ok(self.ctx.signature_keypair_builder_open()?.into())
    }

    pub fn signature_keypair_builder_close(
        &self,
        kp_builder_handle: guest_types::SignatureKeypairBuilder,
    ) -> Result<(), CryptoError> {
        self.ctx
            .signature_keypair_builder_close(kp_builder_handle.into())
    }

    pub fn signature_keypair_generate(
        &self,
        alg_str: &wiggle::GuestPtr<'_, str>,
    ) -> Result<guest_types::SignatureKeypair, CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
        let alg_str: &str = unsafe { &*alg_str.as_raw(&mut guest_borrow)? };
        Ok(self.ctx.signature_keypair_generate(alg_str)?.into())
    }

    pub fn signature_keypair_import(
        &self,
        alg_str: &wiggle::GuestPtr<'_, str>,
        encoded_ptr: &wiggle::GuestPtr<'_, u8>,
        encoded_len: guest_types::Size,
        encoding: guest_types::KeypairEncoding,
    ) -> Result<guest_types::SignatureKeypair, CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
        let alg_str: &str = unsafe { &*alg_str.as_raw(&mut guest_borrow)? };
        let encoded: &[u8] = unsafe {
            &*encoded_ptr
                .as_array(encoded_len as _)
                .as_raw(&mut guest_borrow)?
        };
        Ok(self
            .ctx
            .signature_keypair_import(alg_str, encoded, encoding.into())?
            .into())
    }

    pub fn signature_keypair_from_id(
        &self,
        kp_builder_handle: guest_types::SignatureKeypairBuilder,
        kp_id_ptr: &wiggle::GuestPtr<'_, u8>,
        kp_id_len: guest_types::Size,
        kp_version: guest_types::Version,
    ) -> Result<guest_types::SignatureKeypair, CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
        let kp_id: &[u8] = unsafe {
            &*kp_id_ptr
                .as_array(kp_id_len as _)
                .as_raw(&mut guest_borrow)?
        };
        Ok(self
            .ctx
            .signature_keypair_from_id(kp_builder_handle.into(), kp_id, kp_version.into())?
            .into())
    }

    pub fn signature_keypair_id(
        &self,
        kp_handle: guest_types::SignatureKeypair,
        kp_id_ptr: &wiggle::GuestPtr<'_, u8>,
        kp_id_max_len: guest_types::Size,
    ) -> Result<(guest_types::Size, guest_types::Version), CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
        let kp_id_buf: &mut [u8] = unsafe {
            &mut *kp_id_ptr
                .as_array(kp_id_max_len as _)
                .as_raw(&mut guest_borrow)?
        };
        let (kp_id, version) = self.ctx.signature_keypair_id(kp_handle.into())?;
        ensure!(kp_id.len() <= kp_id_buf.len(), CryptoError::Overflow);
        kp_id_buf.copy_from_slice(&kp_id);
        Ok((kp_id.len().try_into()?, version.into()))
    }

    pub fn signature_keypair_invalidate(
        &self,
        kp_builder_handle: guest_types::SignatureKeypairBuilder,
        kp_id_ptr: &wiggle::GuestPtr<'_, u8>,
        kp_id_len: guest_types::Size,
        kp_version: guest_types::Version,
    ) -> Result<(), CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
        let kp_id: &[u8] = unsafe {
            &*kp_id_ptr
                .as_array(kp_id_len as _)
                .as_raw(&mut guest_borrow)?
        };
        Ok(self
            .ctx
            .signature_keypair_invalidate(kp_builder_handle.into(), kp_id, kp_version.into())?
            .into())
    }

    pub fn signature_keypair_export(
        &self,
        kp_handle: guest_types::SignatureKeypair,
        encoding: guest_types::KeypairEncoding,
    ) -> Result<guest_types::ArrayOutput, CryptoError> {
        Ok(self
            .ctx
            .signature_keypair_export(kp_handle.into(), encoding.into())?
            .into())
    }

    pub fn signature_keypair_publickey(
        &self,
        kp_handle: guest_types::SignatureKeypair,
    ) -> Result<guest_types::SignaturePublickey, CryptoError> {
        Ok(self
            .ctx
            .signature_keypair_publickey(kp_handle.into())?
            .into())
    }

    pub fn signature_keypair_close(
        &self,
        kp_handle: guest_types::SignatureKeypair,
    ) -> Result<(), CryptoError> {
        Ok(self.ctx.signature_keypair_close(kp_handle.into())?.into())
    }
}

#[derive(Copy, Clone, Debug)]
pub struct SignatureKeyPairManager;
