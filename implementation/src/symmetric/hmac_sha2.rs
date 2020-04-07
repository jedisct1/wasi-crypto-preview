use super::*;
use ring::rand::SecureRandom;
use zeroize::Zeroize;

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct HmacSha2SymmetricOp {
    pub alg: SymmetricAlgorithm,
    #[derivative(Debug = "ignore")]
    pub ring_ctx: ring::hmac::Context,
}

#[derive(Clone, Debug, Eq)]
pub struct HmacSha2SymmetricKey {
    alg: SymmetricAlgorithm,
    raw: Vec<u8>,
}

impl PartialEq for HmacSha2SymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.alg == other.alg
            && ring::constant_time::verify_slices_are_equal(&self.raw, &other.raw).is_ok()
    }
}

impl Drop for HmacSha2SymmetricKey {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

impl HmacSha2SymmetricKey {
    pub fn new(alg: SymmetricAlgorithm, raw: &[u8]) -> Result<Self, CryptoError> {
        Ok(HmacSha2SymmetricKey {
            alg,
            raw: raw.to_vec(),
        })
    }

    pub fn as_raw(&self) -> Result<&[u8], CryptoError> {
        Ok(&self.raw)
    }

    pub fn generate(
        handles: &HandleManagers,
        alg: SymmetricAlgorithm,
    ) -> Result<Handle, CryptoError> {
        let key_len = match alg {
            SymmetricAlgorithm::HmacSha256 => ring::digest::SHA256_OUTPUT_LEN,
            SymmetricAlgorithm::HmacSha512 => ring::digest::SHA512_OUTPUT_LEN,
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        };
        let rng = ring::rand::SystemRandom::new();
        let mut raw = vec![0u8; key_len];
        rng.fill(&mut raw).map_err(|_| CryptoError::RNGError)?;
        Self::import(handles, alg, &raw)
    }

    pub fn import(
        handles: &HandleManagers,
        alg: SymmetricAlgorithm,
        raw: &[u8],
    ) -> Result<Handle, CryptoError> {
        let key = HmacSha2SymmetricKey::new(alg, raw)?;
        let handle = handles
            .symmetric_key
            .register(SymmetricKey::HmacSha2(key))?;
        Ok(handle)
    }
}

impl HmacSha2SymmetricOp {
    pub fn new(
        alg: SymmetricAlgorithm,
        key: Option<&SymmetricKey>,
        _options: &SymmetricOptions,
    ) -> Result<Self, CryptoError> {
        let key: &HmacSha2SymmetricKey = match key {
            None => bail!(CryptoError::KeyRequired),
            Some(SymmetricKey::HmacSha2(key)) => key,
        };
        let ring_alg = match alg {
            SymmetricAlgorithm::HmacSha256 => ring::hmac::HMAC_SHA256,
            SymmetricAlgorithm::HmacSha512 => ring::hmac::HMAC_SHA512,
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        };
        let ring_key = ring::hmac::Key::new(ring_alg, key.as_raw()?);
        let ring_ctx = ring::hmac::Context::with_key(&ring_key);
        Ok(HmacSha2SymmetricOp { alg, ring_ctx })
    }

    pub fn absorb(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        unimplemented!();
    }

    pub fn squeeze(&mut self, len: usize) -> Result<Vec<u8>, CryptoError> {
        unimplemented!();
    }
}
