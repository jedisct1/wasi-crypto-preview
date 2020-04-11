use parking_lot::{Mutex, MutexGuard};
use std::convert::TryFrom;
use std::sync::Arc;

use super::ecdsa::*;
use super::eddsa::*;
use super::keypair::*;
use super::publickey::*;
use super::rsa::*;
use super::*;
use crate::array_output::*;
use crate::error::*;
use crate::handles::*;
use crate::types as guest_types;
use crate::{CryptoCtx, HandleManagers, WasiCryptoCtx};

#[derive(Clone, Debug)]
pub enum Signature {
    Ecdsa(EcdsaSignature),
    Eddsa(EddsaSignature),
    Rsa(RsaSignature),
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Signature::Ecdsa(signature) => signature.as_ref(),
            Signature::Eddsa(signature) => signature.as_ref(),
            Signature::Rsa(signature) => signature.as_ref(),
        }
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        ring::constant_time::verify_slices_are_equal(self.as_ref(), other.as_ref()).is_ok()
    }
}

impl Eq for Signature {}

impl Signature {
    fn from_raw(alg: SignatureAlgorithm, encoded: &[u8]) -> Result<Self, CryptoError> {
        let signature = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 => {
                ensure!(encoded.len() == 64, CryptoError::InvalidSignature);
                Signature::Ecdsa(EcdsaSignature::new(
                    SignatureEncoding::Raw,
                    encoded.to_vec(),
                ))
            }
            SignatureAlgorithm::ECDSA_P384_SHA384 => {
                ensure!(encoded.len() == 96, CryptoError::InvalidSignature);
                Signature::Ecdsa(EcdsaSignature::new(
                    SignatureEncoding::Raw,
                    encoded.to_vec(),
                ))
            }
            SignatureAlgorithm::Ed25519 => {
                ensure!(encoded.len() == 64, CryptoError::InvalidSignature);
                Signature::Eddsa(EddsaSignature::new(encoded.to_vec()))
            }
            SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256
            | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384
            | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512
            | SignatureAlgorithm::RSA_PKCS1_3072_8192_SHA384 => {
                Signature::Rsa(RsaSignature::new(encoded.to_vec()))
            }
        };
        Ok(signature)
    }

    pub fn as_ecdsa(&self) -> Result<&EcdsaSignature, CryptoError> {
        match self {
            Signature::Ecdsa(signature) => Ok(signature),
            _ => bail!(CryptoError::InvalidSignature),
        }
    }

    pub fn as_eddsa(&self) -> Result<&EddsaSignature, CryptoError> {
        match self {
            Signature::Eddsa(signature) => Ok(signature),
            _ => bail!(CryptoError::InvalidSignature),
        }
    }

    pub fn as_rsa(&self) -> Result<&RsaSignature, CryptoError> {
        match self {
            Signature::Rsa(signature) => Ok(signature),
            _ => bail!(CryptoError::InvalidSignature),
        }
    }
}

#[derive(Clone)]
pub struct SignatureState {
    inner: Arc<Mutex<Box<dyn SignatureStateLike>>>,
}

impl SignatureState {
    fn new(signature_state_like: Box<dyn SignatureStateLike>) -> Self {
        SignatureState {
            inner: Arc::new(Mutex::new(signature_state_like)),
        }
    }

    fn inner(&self) -> MutexGuard<Box<dyn SignatureStateLike>> {
        self.inner.lock()
    }

    fn locked<T, U>(&self, mut f: T) -> U
    where
        T: FnMut(MutexGuard<Box<dyn SignatureStateLike>>) -> U,
    {
        f(self.inner())
    }

    fn open(handles: &HandleManagers, kp_handle: Handle) -> Result<Handle, CryptoError> {
        let kp = handles.signature_keypair.get(kp_handle)?;
        let signature_state = match kp {
            SignatureKeyPair::Ecdsa(kp) => {
                SignatureState::new(Box::new(EcdsaSignatureState::new(kp)))
            }
            SignatureKeyPair::Eddsa(kp) => {
                SignatureState::new(Box::new(EddsaSignatureState::new(kp)))
            }
            SignatureKeyPair::Rsa(kp) => SignatureState::new(Box::new(RsaSignatureState::new(kp))),
        };
        let handle = handles.signature_state.register(signature_state)?;
        Ok(handle)
    }
}

pub trait SignatureStateLike: Sync + Send {
    fn update(&mut self, input: &[u8]) -> Result<(), CryptoError>;
    fn sign(&mut self) -> Result<Signature, CryptoError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureEncoding {
    Raw,
    Der,
}

impl From<guest_types::SignatureEncoding> for SignatureEncoding {
    fn from(encoding: guest_types::SignatureEncoding) -> Self {
        match encoding {
            guest_types::SignatureEncoding::Raw => SignatureEncoding::Raw,
            guest_types::SignatureEncoding::Der => SignatureEncoding::Der,
        }
    }
}

#[derive(Clone)]
pub struct SignatureVerificationState {
    inner: Arc<Mutex<Box<dyn SignatureVerificationStateLike>>>,
}

impl SignatureVerificationState {
    fn new(signature_verification_state_like: Box<dyn SignatureVerificationStateLike>) -> Self {
        SignatureVerificationState {
            inner: Arc::new(Mutex::new(signature_verification_state_like)),
        }
    }

    fn inner(&self) -> MutexGuard<Box<dyn SignatureVerificationStateLike>> {
        self.inner.lock()
    }

    fn locked<T, U>(&self, mut f: T) -> U
    where
        T: FnMut(MutexGuard<Box<dyn SignatureVerificationStateLike>>) -> U,
    {
        f(self.inner())
    }

    fn open(handles: &HandleManagers, pk_handle: Handle) -> Result<Handle, CryptoError> {
        let pk = handles.signature_publickey.get(pk_handle)?;
        let signature_verification_state = match pk {
            SignaturePublicKey::Ecdsa(pk) => {
                SignatureVerificationState::new(Box::new(EcdsaSignatureVerificationState::new(pk)))
            }
            SignaturePublicKey::Eddsa(pk) => {
                SignatureVerificationState::new(Box::new(EddsaSignatureVerificationState::new(pk)))
            }
            SignaturePublicKey::Rsa(pk) => {
                SignatureVerificationState::new(Box::new(RsaSignatureVerificationState::new(pk)))
            }
        };
        let handle = handles
            .signature_verification_state
            .register(signature_verification_state)?;
        Ok(handle)
    }
}

pub trait SignatureVerificationStateLike: Sync + Send {
    fn update(&mut self, input: &[u8]) -> Result<(), CryptoError>;
    fn verify(&self, signature: &Signature) -> Result<(), CryptoError>;
}

impl CryptoCtx {
    pub fn signature_export(
        &self,
        signature_handle: Handle,
        encoding: SignatureEncoding,
    ) -> Result<Handle, CryptoError> {
        match encoding {
            SignatureEncoding::Raw => {}
            _ => bail!(CryptoError::UnsupportedEncoding),
        }
        let signature = self.handles.signature.get(signature_handle)?;
        let array_output_handle =
            ArrayOutput::register(&self.handles, signature.as_ref().to_vec())?;
        Ok(array_output_handle)
    }

    pub fn signature_import(
        &self,
        alg_str: &str,
        encoding: SignatureEncoding,
        encoded: &[u8],
    ) -> Result<Handle, CryptoError> {
        let alg = SignatureAlgorithm::try_from(alg_str)?;
        let signature = match encoding {
            SignatureEncoding::Raw => Signature::from_raw(alg, encoded)?,
            _ => bail!(CryptoError::UnsupportedEncoding),
        };
        let handle = self.handles.signature.register(signature)?;
        Ok(handle)
    }

    pub fn signature_state_open(&self, kp_handle: Handle) -> Result<Handle, CryptoError> {
        SignatureState::open(&self.handles, kp_handle)
    }

    pub fn signature_state_update(
        &self,
        state_handle: Handle,
        input: &[u8],
    ) -> Result<(), CryptoError> {
        let state = self.handles.signature_state.get(state_handle)?;
        state.locked(|mut state| state.update(input))
    }

    pub fn signature_state_sign(&self, state_handle: Handle) -> Result<Handle, CryptoError> {
        let state = self.handles.signature_state.get(state_handle)?;
        let signature = state.locked(|mut state| state.sign())?;
        let handle = self.handles.signature.register(signature)?;
        Ok(handle)
    }

    pub fn signature_state_close(&self, handle: Handle) -> Result<(), CryptoError> {
        self.handles.signature_state.close(handle)
    }

    pub fn signature_verification_state_open(
        &self,
        pk_handle: Handle,
    ) -> Result<Handle, CryptoError> {
        SignatureVerificationState::open(&self.handles, pk_handle)
    }

    pub fn signature_verification_state_update(
        &self,
        verification_state_handle: Handle,
        input: &[u8],
    ) -> Result<(), CryptoError> {
        let state = self
            .handles
            .signature_verification_state
            .get(verification_state_handle)?;
        state.locked(|mut state| state.update(input))
    }

    pub fn signature_verification_state_verify(
        &self,
        verification_state_handle: Handle,
        signature_handle: Handle,
    ) -> Result<(), CryptoError> {
        let state = self
            .handles
            .signature_verification_state
            .get(verification_state_handle)?;
        let signature = self.handles.signature.get(signature_handle)?;
        state.locked(|state| state.verify(&signature))
    }

    pub fn signature_verification_state_close(
        &self,
        verification_state_handle: Handle,
    ) -> Result<(), CryptoError> {
        self.handles
            .signature_verification_state
            .close(verification_state_handle)
    }

    pub fn signature_close(&self, signature_handle: Handle) -> Result<(), CryptoError> {
        self.handles.signature.close(signature_handle)
    }
}

impl WasiCryptoCtx {
    pub fn signature_export(
        &self,
        signature_handle: guest_types::Signature,
        encoding: guest_types::SignatureEncoding,
    ) -> Result<guest_types::ArrayOutput, CryptoError> {
        Ok(self
            .ctx
            .signature_export(signature_handle.into(), encoding.into())?
            .into())
    }

    pub fn signature_import(
        &self,
        alg_str: &wiggle::GuestPtr<'_, str>,
        encoding: guest_types::SignatureEncoding,
        encoded_ptr: &wiggle::GuestPtr<'_, u8>,
        encoded_len: guest_types::Size,
    ) -> Result<guest_types::Signature, CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
        let alg_str: &str = unsafe { &*alg_str.as_raw(&mut guest_borrow)? };
        let encoded: &[u8] = unsafe {
            &*encoded_ptr
                .as_array(encoded_len as _)
                .as_raw(&mut guest_borrow)?
        };
        Ok(self
            .ctx
            .signature_import(alg_str, encoding.into(), encoded)?
            .into())
    }

    pub fn signature_state_open(
        &self,
        kp_handle: guest_types::SignatureKeypair,
    ) -> Result<guest_types::SignatureState, CryptoError> {
        Ok(self.ctx.signature_state_open(kp_handle.into())?.into())
    }

    pub fn signature_state_update(
        &self,
        state_handle: guest_types::SignatureState,
        input_ptr: &wiggle::GuestPtr<'_, u8>,
        input_len: guest_types::Size,
    ) -> Result<(), CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
        let input: &[u8] = unsafe {
            &*input_ptr
                .as_array(input_len as _)
                .as_raw(&mut guest_borrow)?
        };
        Ok(self
            .ctx
            .signature_state_update(state_handle.into(), input)?
            .into())
    }

    pub fn signature_state_sign(
        &self,
        signature_state_handle: guest_types::SignatureState,
    ) -> Result<guest_types::ArrayOutput, CryptoError> {
        Ok(self
            .ctx
            .signature_state_sign(signature_state_handle.into())?
            .into())
    }

    pub fn signature_state_close(
        &self,
        signature_state_handle: guest_types::SignatureState,
    ) -> Result<(), CryptoError> {
        Ok(self
            .ctx
            .signature_state_close(signature_state_handle.into())?
            .into())
    }

    pub fn signature_verification_state_open(
        &self,
        pk_handle: guest_types::SignaturePublickey,
    ) -> Result<guest_types::SignatureVerificationState, CryptoError> {
        Ok(self
            .ctx
            .signature_verification_state_open(pk_handle.into())?
            .into())
    }

    pub fn signature_verification_state_update(
        &self,
        verification_state_handle: guest_types::SignatureVerificationState,
        input_ptr: &wiggle::GuestPtr<'_, u8>,
        input_len: guest_types::Size,
    ) -> Result<(), CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
        let input: &[u8] = unsafe {
            &*input_ptr
                .as_array(input_len as _)
                .as_raw(&mut guest_borrow)?
        };
        Ok(self
            .ctx
            .signature_verification_state_update(verification_state_handle.into(), input)?
            .into())
    }

    pub fn signature_verification_state_verify(
        &self,
        verification_state_handle: guest_types::SignatureVerificationState,
        signature_handle: guest_types::Signature,
    ) -> Result<(), CryptoError> {
        Ok(self
            .ctx
            .signature_verification_state_verify(
                verification_state_handle.into(),
                signature_handle.into(),
            )?
            .into())
    }

    pub fn signature_verification_state_close(
        &self,
        verification_state_handle: guest_types::SignatureVerificationState,
    ) -> Result<(), CryptoError> {
        Ok(self
            .ctx
            .signature_verification_state_close(verification_state_handle.into())?
            .into())
    }

    pub fn signature_close(
        &self,
        signature_handle: guest_types::Signature,
    ) -> Result<(), CryptoError> {
        Ok(self.ctx.signature_close(signature_handle.into())?.into())
    }
}
