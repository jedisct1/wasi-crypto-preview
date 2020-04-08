use super::*;
use symmetric_key::*;

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

    pub fn absorb(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.ring_ctx.update(data);
        Ok(())
    }

    pub fn squeeze(&mut self, len: usize) -> Result<Vec<u8>, CryptoError> {
        let out = self.ring_ctx.clone().finish();
        ensure!(
            len > 0 && len <= out.as_ref().len(),
            CryptoError::InvalidLength
        );
        let out = out.as_ref()[..len].to_vec();
        Ok(out)
    }

    pub fn squeeze_tag(&mut self) -> Result<SymmetricTag, CryptoError> {
        bail!(CryptoError::InvalidOperation)
    }
}
