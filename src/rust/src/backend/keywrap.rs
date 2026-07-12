// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_crypto::constant_time;

use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

fn ecb_ctx(
    wrapping_key: &[u8],
    side: openssl::symm::Mode,
) -> CryptographyResult<openssl::cipher_ctx::CipherCtx> {
    let cipher = match wrapping_key.len() {
        16 => openssl::cipher::Cipher::aes_128_ecb(),
        24 => openssl::cipher::Cipher::aes_192_ecb(),
        32 => openssl::cipher::Cipher::aes_256_ecb(),
        _ => {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "The wrapping key must be a valid AES key length",
                ),
            ))
        }
    };

    let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;
    match side {
        openssl::symm::Mode::Encrypt => {
            ctx.encrypt_init(Some(cipher), Some(wrapping_key), None)?;
        }
        openssl::symm::Mode::Decrypt => {
            ctx.decrypt_init(Some(cipher), Some(wrapping_key), None)?;
        }
    }
    ctx.set_padding(false);
    Ok(ctx)
}

fn cipher_block(
    ctx: &mut openssl::cipher_ctx::CipherCtx,
    input: &[u8; 16],
    out: &mut [u8; 16],
) -> CryptographyResult<()> {
    // SAFETY: `out` is exactly one block and ECB with padding disabled
    // always writes exactly one block of output per block of input.
    let n = unsafe { ctx.cipher_update_unchecked(input, Some(out))? };
    debug_assert_eq!(n, 16);
    Ok(())
}

fn wrap_core(
    ctx: &mut openssl::cipher_ctx::CipherCtx,
    mut a: [u8; 8],
    r: &mut [u8],
) -> CryptographyResult<Vec<u8>> {
    debug_assert_eq!(r.len() % 8, 0);
    let n = r.len() / 8;
    let mut block = [0u8; 16];
    let mut out = [0u8; 16];
    for j in 0..6u64 {
        for i in 0..n {
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(&r[i * 8..i * 8 + 8]);
            cipher_block(ctx, &block, &mut out)?;
            let t = (n as u64) * j + (i as u64) + 1;
            a = (u64::from_be_bytes(out[..8].try_into().unwrap()) ^ t).to_be_bytes();
            r[i * 8..i * 8 + 8].copy_from_slice(&out[8..]);
        }
    }

    let mut result = Vec::with_capacity(8 + r.len());
    result.extend_from_slice(&a);
    result.extend_from_slice(r);
    Ok(result)
}

fn unwrap_core(
    ctx: &mut openssl::cipher_ctx::CipherCtx,
    mut a: [u8; 8],
    r: &mut [u8],
) -> CryptographyResult<[u8; 8]> {
    debug_assert_eq!(r.len() % 8, 0);
    let n = r.len() / 8;
    let mut block = [0u8; 16];
    let mut out = [0u8; 16];
    for j in (0..6u64).rev() {
        for i in (0..n).rev() {
            let t = (n as u64) * j + (i as u64) + 1;
            block[..8].copy_from_slice(&(u64::from_be_bytes(a) ^ t).to_be_bytes());
            block[8..].copy_from_slice(&r[i * 8..i * 8 + 8]);
            cipher_block(ctx, &block, &mut out)?;
            a.copy_from_slice(&out[..8]);
            r[i * 8..i * 8 + 8].copy_from_slice(&out[8..]);
        }
    }

    Ok(a)
}

#[pyo3::pyfunction]
#[pyo3(signature = (wrapping_key, key_to_wrap, backend=None))]
fn aes_key_wrap<'p>(
    py: pyo3::Python<'p>,
    wrapping_key: CffiBuf<'_>,
    key_to_wrap: CffiBuf<'_>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let _ = backend;
    let key_to_wrap = key_to_wrap.as_bytes();

    let mut ctx = ecb_ctx(wrapping_key.as_bytes(), openssl::symm::Mode::Encrypt)?;

    if key_to_wrap.len() < 16 {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("The key to wrap must be at least 16 bytes"),
        ));
    }
    if key_to_wrap.len() % 8 != 0 {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "The key to wrap must be a multiple of 8 bytes",
            ),
        ));
    }

    let mut r = key_to_wrap.to_vec();
    let result = wrap_core(&mut ctx, [0xa6; 8], &mut r)?;
    Ok(pyo3::types::PyBytes::new(py, &result))
}

#[pyo3::pyfunction]
#[pyo3(signature = (wrapping_key, wrapped_key, backend=None))]
fn aes_key_unwrap<'p>(
    py: pyo3::Python<'p>,
    wrapping_key: CffiBuf<'_>,
    wrapped_key: CffiBuf<'_>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let _ = backend;
    let wrapped_key = wrapped_key.as_bytes();

    if wrapped_key.len() < 24 {
        return Err(CryptographyError::from(exceptions::InvalidUnwrap::new_err(
            "Must be at least 24 bytes",
        )));
    }
    if wrapped_key.len() % 8 != 0 {
        return Err(CryptographyError::from(exceptions::InvalidUnwrap::new_err(
            "The wrapped key must be a multiple of 8 bytes",
        )));
    }

    let mut ctx = ecb_ctx(wrapping_key.as_bytes(), openssl::symm::Mode::Decrypt)?;

    let a = wrapped_key[..8].try_into().unwrap();
    let mut r = wrapped_key[8..].to_vec();
    let a = unwrap_core(&mut ctx, a, &mut r)?;
    if !constant_time::bytes_eq(&a, &[0xa6; 8]) {
        return Err(CryptographyError::from(exceptions::InvalidUnwrap::new_err(
            (),
        )));
    }

    Ok(pyo3::types::PyBytes::new(py, &r))
}

#[pyo3::pyfunction]
#[pyo3(signature = (wrapping_key, key_to_wrap, backend=None))]
fn aes_key_wrap_with_padding<'p>(
    py: pyo3::Python<'p>,
    wrapping_key: CffiBuf<'_>,
    key_to_wrap: CffiBuf<'_>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let _ = backend;
    let key_to_wrap = key_to_wrap.as_bytes();

    let mut ctx = ecb_ctx(wrapping_key.as_bytes(), openssl::symm::Mode::Encrypt)?;

    if key_to_wrap.is_empty() || key_to_wrap.len() as u64 >= (1 << 32) {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("key_to_wrap must be between 1 and 2^32 bytes"),
        ));
    }

    let mut aiv = [0u8; 8];
    aiv[..4].copy_from_slice(b"\xa6\x59\x59\xa6");
    aiv[4..].copy_from_slice(&(key_to_wrap.len() as u32).to_be_bytes());

    let pad = (8 - (key_to_wrap.len() % 8)) % 8;
    let mut r = Vec::with_capacity(key_to_wrap.len() + pad);
    r.extend_from_slice(key_to_wrap);
    r.resize(key_to_wrap.len() + pad, 0);

    if r.len() == 8 {
        // RFC 5649 - 4.1 - exactly 8 octets after padding
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&aiv);
        block[8..].copy_from_slice(&r);
        let mut out = [0u8; 16];
        cipher_block(&mut ctx, &block, &mut out)?;
        Ok(pyo3::types::PyBytes::new(py, &out))
    } else {
        let result = wrap_core(&mut ctx, aiv, &mut r)?;
        Ok(pyo3::types::PyBytes::new(py, &result))
    }
}

#[pyo3::pyfunction]
#[pyo3(signature = (wrapping_key, wrapped_key, backend=None))]
fn aes_key_unwrap_with_padding<'p>(
    py: pyo3::Python<'p>,
    wrapping_key: CffiBuf<'_>,
    wrapped_key: CffiBuf<'_>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let _ = backend;
    let wrapped_key = wrapped_key.as_bytes();

    if wrapped_key.len() < 16 {
        return Err(CryptographyError::from(exceptions::InvalidUnwrap::new_err(
            "Must be at least 16 bytes",
        )));
    }
    if wrapped_key.len() % 8 != 0 {
        return Err(CryptographyError::from(exceptions::InvalidUnwrap::new_err(
            "The wrapped key must be a multiple of 8 bytes",
        )));
    }

    let mut ctx = ecb_ctx(wrapping_key.as_bytes(), openssl::symm::Mode::Decrypt)?;

    let (a, mut data) = if wrapped_key.len() == 16 {
        // RFC 5649 - 4.2 - exactly two 64-bit blocks
        let mut out = [0u8; 16];
        cipher_block(&mut ctx, wrapped_key.try_into().unwrap(), &mut out)?;
        let a: [u8; 8] = out[..8].try_into().unwrap();
        (a, out[8..].to_vec())
    } else {
        let a = wrapped_key[..8].try_into().unwrap();
        let mut r = wrapped_key[8..].to_vec();
        let a = unwrap_core(&mut ctx, a, &mut r)?;
        (a, r)
    };
    let n = data.len() / 8;

    // 1) Check that MSB(32,A) = A65959A6.
    // 2) Check that 8*(n-1) < LSB(32,A) <= 8*n.  If so, let
    //    MLI = LSB(32,A).
    // 3) Let b = (8*n)-MLI, and then check that the rightmost b octets of
    //    the output data are zero.
    let mli = u32::from_be_bytes(a[4..].try_into().unwrap()) as usize;
    if !(constant_time::bytes_eq(&a[..4], b"\xa6\x59\x59\xa6") && 8 * (n - 1) < mli && mli <= 8 * n)
    {
        return Err(CryptographyError::from(exceptions::InvalidUnwrap::new_err(
            (),
        )));
    }
    let b = 8 * n - mli;
    if b != 0 && !constant_time::bytes_eq(&data[data.len() - b..], &vec![0; b]) {
        return Err(CryptographyError::from(exceptions::InvalidUnwrap::new_err(
            (),
        )));
    }

    data.truncate(data.len() - b);
    Ok(pyo3::types::PyBytes::new(py, &data))
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod keywrap {
    #[pymodule_export]
    use super::{
        aes_key_unwrap, aes_key_unwrap_with_padding, aes_key_wrap, aes_key_wrap_with_padding,
    };
}
