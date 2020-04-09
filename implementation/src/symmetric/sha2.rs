use super::state::*;
use super::*;

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct Sha2SymmetricState {
    pub alg: SymmetricAlgorithm,
    #[derivative(Debug = "ignore")]
    pub ring_ctx: ring::digest::Context,
}

impl Sha2SymmetricState {
    pub fn new(
        alg: SymmetricAlgorithm,
        key: Option<&SymmetricKey>,
        _options: Option<SymmetricOptions>,
    ) -> Result<Self, CryptoError> {
        if key.is_some() {
            return Err(CryptoError::KeyNotSupported);
        }
        let ring_alg = match alg {
            SymmetricAlgorithm::Sha256 => &ring::digest::SHA256,
            SymmetricAlgorithm::Sha512 => &ring::digest::SHA512,
            SymmetricAlgorithm::Sha512_256 => &ring::digest::SHA512_256,
            _ => bail!(CryptoError::UnsupportedAlgorithm),
        };
        let ring_ctx = ring::digest::Context::new(ring_alg);
        Ok(Sha2SymmetricState { alg, ring_ctx })
    }
}

impl SymmetricAlgorithmStateLike for Sha2SymmetricState {
    fn alg(&self) -> SymmetricAlgorithm {
        self.alg
    }

    fn absorb(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.ring_ctx.update(data);
        Ok(())
    }

    fn squeeze(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        let digest = self.ring_ctx.clone().finish();
        ensure!(
            digest.as_ref().len() <= out.len(),
            CryptoError::InvalidLength
        );
        out.copy_from_slice(&digest.as_ref()[..out.len()]);
        Ok(())
    }
}
