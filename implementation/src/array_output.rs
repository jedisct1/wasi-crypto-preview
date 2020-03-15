use std::io::{Cursor, Read};

use super::error::*;
use super::handles::*;
use super::WASI_CRYPTO_CTX;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArrayOutput(Cursor<Vec<u8>>);

impl ArrayOutput {
    fn pull(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let data = self.0.get_ref();
        let data_len = data.len();
        let buf_len = buf.len();
        ensure!(buf_len >= data_len, CryptoError::Overflow);
        buf.copy_from_slice(data);
        Ok(buf_len)
    }

    pub fn new(data: Vec<u8>) -> Self {
        ArrayOutput(Cursor::new(data))
    }

    pub fn register(data: Vec<u8>) -> Result<Handle, Error> {
        let array_output = ArrayOutput::new(data);
        let handle = WASI_CRYPTO_CTX
            .handles
            .array_output
            .register(array_output)?;
        Ok(handle)
    }
}

impl Read for ArrayOutput {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.0.read(buf)
    }
}

pub fn array_output_pull(array_output_handle: Handle, buf: &mut [u8]) -> Result<usize, Error> {
    let array_output = WASI_CRYPTO_CTX
        .handles
        .array_output
        .get(array_output_handle)?;
    let size = array_output.pull(buf)?;
    WASI_CRYPTO_CTX
        .handles
        .array_output
        .close(array_output_handle)?;
    Ok(size)
}