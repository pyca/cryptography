// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::buf::CffiBuf;
use crate::error::CryptographyResult;
use crate::exceptions;

/// Returns the value of the input with the most-significant-bit copied to all
/// of the bits.
fn duplicate_msb_to_all(a: u8) -> u8 {
    0u8.wrapping_sub(a >> 7)
}

/// This returns 0xFF if a < b else 0x00, but does so in a constant time
/// fashion.
fn constant_time_lt(a: u8, b: u8) -> u8 {
    // Derived from:
    // https://github.com/openssl/openssl/blob/OpenSSL_1_1_1i/include/internal/constant_time.h#L120
    duplicate_msb_to_all(a ^ ((a ^ b) | (a.wrapping_sub(b) ^ b)))
}

pub(crate) fn check_pkcs7_padding(data: &[u8]) -> bool {
    let mut mismatch = 0;
    let pad_size = *data.last().unwrap();
    let len: u8 = data.len().try_into().expect("data too long");
    for (i, b) in (0..len).zip(data.iter().rev()) {
        let mask = constant_time_lt(i, pad_size);
        mismatch |= mask & (pad_size ^ b);
    }

    // Check to make sure the pad_size was within the valid range.
    mismatch |= !constant_time_lt(0, pad_size);
    mismatch |= constant_time_lt(len, pad_size);

    // Make sure any bits set are copied to the lowest bit
    mismatch |= mismatch >> 4;
    mismatch |= mismatch >> 2;
    mismatch |= mismatch >> 1;

    // Now check the low bit to see if it's set
    (mismatch & 1) == 0
}

#[pyo3::pyfunction]
pub(crate) fn check_ansix923_padding(data: &[u8]) -> bool {
    let mut mismatch = 0;
    let pad_size = *data.last().unwrap();
    let len: u8 = data.len().try_into().expect("data too long");
    // Skip the first one with the pad size
    for (i, b) in (1..len).zip(data[..data.len() - 1].iter().rev()) {
        let mask = constant_time_lt(i, pad_size);
        mismatch |= mask & b;
    }

    // Check to make sure the pad_size was within the valid range.
    mismatch |= !constant_time_lt(0, pad_size);
    mismatch |= constant_time_lt(len, pad_size);

    // Make sure any bits set are copied to the lowest bit
    mismatch |= mismatch >> 4;
    mismatch |= mismatch >> 2;
    mismatch |= mismatch >> 1;

    // Now check the low bit to see if it's set
    (mismatch & 1) == 0
}

#[pyo3::pyclass]
pub(crate) struct PKCS7PaddingContext {
    block_size: usize,
    length_seen: Option<usize>,
}

#[pyo3::pymethods]
impl PKCS7PaddingContext {
    #[new]
    pub(crate) fn new(block_size: usize) -> PKCS7PaddingContext {
        PKCS7PaddingContext {
            block_size: block_size / 8,
            length_seen: Some(0),
        }
    }

    pub(crate) fn update<'a>(
        &mut self,
        buf: CffiBuf<'a>,
    ) -> CryptographyResult<pyo3::Bound<'a, pyo3::PyAny>> {
        match self.length_seen.as_mut() {
            Some(v) => {
                *v += buf.as_bytes().len();
                Ok(buf.into_pyobj())
            }
            None => Err(exceptions::already_finalized_error()),
        }
    }

    pub(crate) fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        match self.length_seen.take() {
            Some(v) => {
                let pad_size = self.block_size - (v % self.block_size);
                let pad = vec![pad_size as u8; pad_size];
                Ok(pyo3::types::PyBytes::new(py, &pad))
            }
            None => Err(exceptions::already_finalized_error()),
        }
    }
}

#[pyo3::pyclass]
pub(crate) struct PKCS7UnpaddingContext {
    block_size: usize,
    buffer: Option<Vec<u8>>,
}

#[pyo3::pymethods]
impl PKCS7UnpaddingContext {
    #[new]
    pub(crate) fn new(block_size: usize) -> PKCS7UnpaddingContext {
        PKCS7UnpaddingContext {
            block_size: block_size / 8,
            buffer: Some(Vec::new()),
        }
    }

    pub(crate) fn update<'a>(
        &mut self,
        py: pyo3::Python<'a>,
        buf: CffiBuf<'a>,
    ) -> CryptographyResult<pyo3::Bound<'a, pyo3::types::PyBytes>> {
        match self.buffer.as_mut() {
            Some(v) => {
                v.extend_from_slice(buf.as_bytes());
                let finished_blocks = (v.len() / self.block_size).saturating_sub(1);
                let result_size = finished_blocks * self.block_size;
                let result = v.drain(..result_size);
                Ok(pyo3::types::PyBytes::new(py, result.as_slice()))
            }
            None => Err(exceptions::already_finalized_error()),
        }
    }

    pub(crate) fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        match self.buffer.take() {
            Some(v) => {
                if v.len() != self.block_size {
                    return Err(
                        pyo3::exceptions::PyValueError::new_err("Invalid padding bytes.").into(),
                    );
                }
                if !check_pkcs7_padding(&v) {
                    return Err(
                        pyo3::exceptions::PyValueError::new_err("Invalid padding bytes.").into(),
                    );
                }

                let pad_size = *v.last().unwrap();
                let result = &v[..v.len() - pad_size as usize];
                Ok(pyo3::types::PyBytes::new(py, result))
            }
            None => Err(exceptions::already_finalized_error()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::constant_time_lt;

    #[test]
    fn test_constant_time_lt() {
        for a in 0..=255 {
            for b in 0..=255 {
                let expected = if a < b { 0xff } else { 0 };
                assert_eq!(constant_time_lt(a, b), expected);
            }
        }
    }
}
