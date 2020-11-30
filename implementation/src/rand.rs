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

impl rand_core::CryptoRng for SecureRandom {}

impl rand_core::RngCore for SecureRandom {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.rng.fill(&mut bytes).unwrap();
        u32::from_ne_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.rng.fill(&mut bytes).unwrap();
        u64::from_ne_bytes(bytes)
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.rng.fill(bytes).unwrap();
    }

    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        self.rng
            .fill(bytes)
            .map_err(|e| rand_core::Error::new(e.to_string()))
    }
}
