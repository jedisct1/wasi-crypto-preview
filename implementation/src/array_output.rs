use super::error::*;
use super::handles::*;
use super::WASI_CRYPTO_CTX;

#[derive(Clone)]
pub struct ArrayOutput {
    data: Vec<u8>,
}

impl ArrayOutput {
    pub fn pull(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let data_len = self.data.len();
        let buf_len = buf.len();
        ensure!(buf_len >= data_len, CryptoError::Overflow);
        buf.copy_from_slice(&self.data[..]);
        Ok(buf_len)
    }

    pub fn new(data: Vec<u8>) -> Self {
        ArrayOutput { data }
    }

    pub fn register(data: Vec<u8>) -> Result<Handle, Error> {
        let array_output = ArrayOutput::new(data);
        let handle = WASI_CRYPTO_CTX
            .array_output_manager
            .register(array_output)?;
        Ok(handle)
    }
}
