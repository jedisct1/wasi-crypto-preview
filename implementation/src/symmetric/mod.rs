mod aes_gcm;
mod hmac_sha2;
mod key;
mod sha2;
mod state;
mod tag;

use crate::error::*;
use crate::handles::*;
use crate::options::*;
use crate::CryptoCtx;
use aes_gcm::*;
use hmac_sha2::*;
use parking_lot::Mutex;
use sha2::*;
use std::any::Any;
use std::convert::TryFrom;
use std::sync::Arc;

pub use key::SymmetricKey;
pub use state::SymmetricState;
pub use tag::SymmetricTag;

#[derive(Debug, Default)]
pub struct SymmetricOptionsInner {
    context: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    memory_limit: Option<u64>,
    ops_limit: Option<u64>,
    parallelism: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct SymmetricOptions {
    inner: Arc<Mutex<SymmetricOptionsInner>>,
}

impl Default for SymmetricOptions {
    fn default() -> Self {
        SymmetricOptions {
            inner: Default::default(),
        }
    }
}

impl OptionsLike for SymmetricOptions {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn set(&mut self, name: &str, value: &[u8]) -> Result<(), CryptoError> {
        let mut inner = self.inner.lock();
        let option = match name.to_lowercase().as_str() {
            "context" => &mut inner.context,
            "salt" => &mut inner.salt,
            "nonce" => &mut inner.nonce,
            _ => bail!(CryptoError::UnsupportedOption),
        };
        *option = Some(value.to_vec());
        Ok(())
    }

    fn set_u64(&mut self, name: &str, value: u64) -> Result<(), CryptoError> {
        let mut inner = self.inner.lock();
        let option = match name.to_lowercase().as_str() {
            "memory_limit" => &mut inner.memory_limit,
            "ops_limit" => &mut inner.ops_limit,
            "parallelism" => &mut inner.parallelism,
            _ => bail!(CryptoError::UnsupportedOption),
        };
        *option = Some(value);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymmetricAlgorithm {
    None,
    HmacSha256,
    HmacSha512,
    Sha256,
    Sha512,
    Sha512_256,
    Aes128Gcm,
    Aes256Gcm,
}

impl TryFrom<&str> for SymmetricAlgorithm {
    type Error = CryptoError;

    fn try_from(alg_str: &str) -> Result<Self, CryptoError> {
        match alg_str {
            "HMAC/SHA-256" => Ok(SymmetricAlgorithm::HmacSha256),
            "HMAC/SHA-512" => Ok(SymmetricAlgorithm::HmacSha512),
            "SHA-256" => Ok(SymmetricAlgorithm::Sha256),
            "SHA-512" => Ok(SymmetricAlgorithm::Sha512),
            "SHA-512/256" => Ok(SymmetricAlgorithm::Sha512_256),
            "AES-128-GCM" => Ok(SymmetricAlgorithm::Aes128Gcm),
            "AES-256-GCM" => Ok(SymmetricAlgorithm::Aes256Gcm),
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        }
    }
}

#[test]
fn test_hash() {
    use crate::CryptoCtx;

    let ctx = CryptoCtx::new();

    let state_handle = ctx.symmetric_state_open("SHA-256", None, None).unwrap();
    ctx.symmetric_state_absorb(state_handle, b"data").unwrap();
    ctx.symmetric_state_absorb(state_handle, b"more_data")
        .unwrap();
    let out = ctx.symmetric_state_squeeze(state_handle, 32).unwrap();
    let expected = [
        227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65,
        228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
    ];
    assert_eq!(out, expected);
    ctx.symmetric_state_close(state_handle).unwrap();
}

#[cfg(test)]
fn array_get(ctx: &CryptoCtx, output_array: Handle) -> Vec<u8> {
    let mut bytes = vec![0u8; ctx.array_output_len(output_array).unwrap()];
    ctx.array_output_pull(output_array, &mut bytes).unwrap();
    bytes
}

#[test]
fn test_hmac() {
    use crate::CryptoCtx;

    let ctx = CryptoCtx::new();

    let key_handle = ctx.symmetric_key_generate("HMAC/SHA-512", None).unwrap();
    let state_handle = ctx
        .symmetric_state_open("HMAC/SHA-512", Some(key_handle), None)
        .unwrap();
    ctx.symmetric_state_absorb(state_handle, b"data").unwrap();
    ctx.symmetric_state_absorb(state_handle, b"more_data")
        .unwrap();
    let tag_handle = ctx.symmetric_state_squeeze_tag(state_handle).unwrap();

    let raw_tag = array_get(&ctx, ctx.symmetric_tag_export(tag_handle).unwrap());
    ctx.symmetric_tag_verify(tag_handle, &raw_tag).unwrap();

    ctx.symmetric_state_close(state_handle).unwrap();
    ctx.symmetric_key_close(key_handle).unwrap();
    ctx.symmetric_tag_close(tag_handle).unwrap();
}

#[test]
fn test_encryption() {
    use crate::CryptoCtx;

    let ctx = CryptoCtx::new();

    let msg = b"test";
    let nonce = [42u8; 12];
    let key_handle = ctx.symmetric_key_generate("AES-256-GCM", None).unwrap();

    let options_handle = ctx.options_open(OptionsType::Symmetric).unwrap();
    ctx.options_set(options_handle, "nonce", &nonce).unwrap();

    let symmetric_state = ctx
        .symmetric_state_open("AES-256-GCM", Some(key_handle), Some(options_handle))
        .unwrap();
    let ciphertext_with_tag = ctx.symmetric_encrypt(symmetric_state, msg).unwrap();
    ctx.symmetric_state_close(symmetric_state).unwrap();

    let symmetric_state = ctx
        .symmetric_state_open("AES-256-GCM", Some(key_handle), Some(options_handle))
        .unwrap();
    let msg2 = ctx
        .symmetric_decrypt(symmetric_state, &ciphertext_with_tag)
        .unwrap();
    ctx.symmetric_state_close(symmetric_state).unwrap();
    assert_eq!(msg, &msg2[..]);

    let symmetric_state = ctx
        .symmetric_state_open("AES-256-GCM", Some(key_handle), Some(options_handle))
        .unwrap();
    let (ciphertext, tag) = ctx
        .symmetric_encrypt_detached(symmetric_state, msg)
        .unwrap();
    ctx.symmetric_state_close(symmetric_state).unwrap();

    let symmetric_state = ctx
        .symmetric_state_open("AES-256-GCM", Some(key_handle), Some(options_handle))
        .unwrap();
    let msg2 = ctx
        .symmetric_decrypt_detached(symmetric_state, &ciphertext, tag.as_ref())
        .unwrap();
    ctx.symmetric_state_close(symmetric_state).unwrap();
    assert_eq!(msg, &msg2[..]);
}
