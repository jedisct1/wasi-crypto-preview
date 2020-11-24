use crate::CryptoError;

use ring::rand::SecureRandom as _;

pub struct SecureRandom {
    rng: ring::rand::SystemRandom,
}

impl SecureRandom {
    pub fn new() -> Self {
        SecureRandom {
            rng: ring::rand::SystemRandom::new(),
        }
    }

    pub fn ring_rng(&self) -> &dyn ring::rand::SecureRandom {
        &self.rng
    }

    pub fn fill(&mut self, bytes: &mut [u8]) -> Result<(), CryptoError> {
        Ok(self.rng.fill(bytes).map_err(|_| CryptoError::RNGError)?)
    }
}
