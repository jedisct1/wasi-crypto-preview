use super::*;

use byteorder::{ByteOrder, LittleEndian};
use parking_lot::Mutex;
use ring::aead::BoundKey;
use ring::rand::SecureRandom;
use std::sync::Arc;
use zeroize::Zeroize;

pub struct AesGcmSymmetricStateInner {}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct AesGcmSymmetricState {
    pub alg: SymmetricAlgorithm,
    #[derivative(Debug = "ignore")]
    pub ring_sealing_key: Arc<Mutex<ring::aead::SealingKey<AesGcmNonceSequence>>>,
    pub ring_opening_key: Arc<Mutex<ring::aead::OpeningKey<AesGcmNonceSequence>>>,
}

#[derive(Clone, Debug, Eq)]
pub struct AesGcmSymmetricKey {
    alg: SymmetricAlgorithm,
    raw: Vec<u8>,
}

impl PartialEq for AesGcmSymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.alg == other.alg
            && ring::constant_time::verify_slices_are_equal(&self.raw, &other.raw).is_ok()
    }
}

impl Drop for AesGcmSymmetricKey {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

impl AesGcmSymmetricKey {
    pub fn new(alg: SymmetricAlgorithm, raw: &[u8]) -> Result<Self, CryptoError> {
        Ok(AesGcmSymmetricKey {
            alg,
            raw: raw.to_vec(),
        })
    }

    pub fn alg(&self) -> SymmetricAlgorithm {
        self.alg
    }

    pub fn as_raw(&self) -> Result<&[u8], CryptoError> {
        Ok(&self.raw)
    }

    pub fn generate(
        alg: SymmetricAlgorithm,
        _options: Option<SymmetricOptions>,
    ) -> Result<AesGcmSymmetricKey, CryptoError> {
        let key_len = match alg {
            SymmetricAlgorithm::Aes128_Gcm => ring::aead::AES_128_GCM.key_len(),
            SymmetricAlgorithm::Aes256_Gcm => ring::aead::AES_256_GCM.key_len(),
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        };
        let rng = ring::rand::SystemRandom::new();
        let mut raw = vec![0u8; key_len];
        rng.fill(&mut raw).map_err(|_| CryptoError::RNGError)?;
        Self::import(alg, &raw)
    }

    pub fn import(alg: SymmetricAlgorithm, raw: &[u8]) -> Result<AesGcmSymmetricKey, CryptoError> {
        let key = AesGcmSymmetricKey::new(alg, raw)?;
        Ok(key)
    }
}

#[derive(Debug)]
pub struct AesGcmNonceSequence {
    nonce: [u8; 12],
}

impl AesGcmNonceSequence {
    fn new(nonce: [u8; 12]) -> Self {
        AesGcmNonceSequence { nonce }
    }
}

impl ring::aead::NonceSequence for AesGcmNonceSequence {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        let b0 = LittleEndian::read_u64(&self.nonce[..8]);
        let b1 = LittleEndian::read_u32(&self.nonce[8..]);
        let (b0, of) = b0.overflowing_add(1);
        let b1 = b1.wrapping_add(of as _);
        LittleEndian::write_u64(&mut self.nonce[..8], b0);
        LittleEndian::write_u32(&mut self.nonce[8..], b1);
        let ring_nonce = ring::aead::Nonce::assume_unique_for_key(self.nonce);
        Ok(ring_nonce)
    }
}

impl AesGcmSymmetricState {
    pub fn new(
        alg: SymmetricAlgorithm,
        key: Option<SymmetricKey>,
        _options: Option<SymmetricOptions>,
    ) -> Result<Self, CryptoError> {
        let key = match key {
            None => bail!(CryptoError::KeyRequired),
            Some(SymmetricKey::AesGcm(key)) => key,
            _ => bail!(CryptoError::InvalidKey),
        };
        let ring_alg = match alg {
            SymmetricAlgorithm::Aes128_Gcm => &ring::aead::AES_128_GCM,
            SymmetricAlgorithm::Aes256_Gcm => &ring::aead::AES_256_GCM,
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        };
        let nonce = [0u8; 12];
        let nonce_sequence = AesGcmNonceSequence::new(nonce);
        let ring_unbound_key = ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, key.as_raw()?)
            .map_err(|_| CryptoError::InvalidKey)?;
        let ring_sealing_key = ring::aead::SealingKey::new(ring_unbound_key, nonce_sequence);
        let nonce_sequence = AesGcmNonceSequence::new(nonce);
        let ring_unbound_key = ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, key.as_raw()?)
            .map_err(|_| CryptoError::InvalidKey)?;
        let ring_opening_key = ring::aead::OpeningKey::new(ring_unbound_key, nonce_sequence);
        Ok(AesGcmSymmetricState {
            alg,
            ring_sealing_key: Arc::new(Mutex::new(ring_sealing_key)),
            ring_opening_key: Arc::new(Mutex::new(ring_opening_key)),
        })
    }

    pub fn alg(&self) -> SymmetricAlgorithm {
        self.alg
    }

    pub fn absorb(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        //        self.ring_ctx.lock().update(data);
        Ok(())
    }

    pub fn squeeze(&mut self, _len: usize) -> Result<Vec<u8>, CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }

    pub fn squeeze_tag(&mut self) -> Result<SymmetricTag, CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }
}
