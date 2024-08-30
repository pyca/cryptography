// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::cipher_registry;
use crate::buf::{CffiBuf, CffiMutBuf};
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;
use crate::types;
use pyo3::types::PyAnyMethods;
use pyo3::IntoPy;

pub(crate) struct CipherContext {
    ctx: openssl::cipher_ctx::CipherCtx,
    py_mode: pyo3::PyObject,
    py_algorithm: pyo3::PyObject,
    side: openssl::symm::Mode,
}

impl CipherContext {
    pub(crate) fn new(
        py: pyo3::Python<'_>,
        algorithm: pyo3::Bound<'_, pyo3::PyAny>,
        mode: pyo3::Bound<'_, pyo3::PyAny>,
        side: openssl::symm::Mode,
    ) -> CryptographyResult<CipherContext> {
        let cipher =
            match cipher_registry::get_cipher(py, algorithm.clone(), mode.get_type().into_any())? {
                Some(c) => c,
                None => {
                    return Err(CryptographyError::from(
                        exceptions::UnsupportedAlgorithm::new_err((
                            format!(
                                "cipher {} in {} mode is not supported ",
                                algorithm.getattr(pyo3::intern!(py, "name"))?,
                                if mode.is_truthy()? {
                                    mode.getattr(pyo3::intern!(py, "name"))?
                                } else {
                                    mode
                                }
                            ),
                            exceptions::Reasons::UNSUPPORTED_CIPHER,
                        )),
                    ))
                }
            };

        let iv_nonce = if mode.is_instance(&types::MODE_WITH_INITIALIZATION_VECTOR.get(py)?)? {
            Some(
                mode.getattr(pyo3::intern!(py, "initialization_vector"))?
                    .extract::<CffiBuf<'_>>()?,
            )
        } else if mode.is_instance(&types::MODE_WITH_TWEAK.get(py)?)? {
            Some(
                mode.getattr(pyo3::intern!(py, "tweak"))?
                    .extract::<CffiBuf<'_>>()?,
            )
        } else if mode.is_instance(&types::MODE_WITH_NONCE.get(py)?)? {
            Some(
                mode.getattr(pyo3::intern!(py, "nonce"))?
                    .extract::<CffiBuf<'_>>()?,
            )
        } else if algorithm.is_instance(&types::CHACHA20.get(py)?)? {
            Some(
                algorithm
                    .getattr(pyo3::intern!(py, "nonce"))?
                    .extract::<CffiBuf<'_>>()?,
            )
        } else {
            None
        };

        let key = algorithm
            .getattr(pyo3::intern!(py, "key"))?
            .extract::<CffiBuf<'_>>()?;

        let init_op = match side {
            openssl::symm::Mode::Encrypt => openssl::cipher_ctx::CipherCtxRef::encrypt_init,
            openssl::symm::Mode::Decrypt => openssl::cipher_ctx::CipherCtxRef::decrypt_init,
        };

        let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;
        init_op(&mut ctx, Some(cipher), None, None)?;
        ctx.set_key_length(key.as_bytes().len())?;

        if let Some(iv) = iv_nonce.as_ref() {
            if cipher.iv_length() != 0 && cipher.iv_length() != iv.as_bytes().len() {
                ctx.set_iv_length(iv.as_bytes().len())?;
            }
        }

        if mode.is_instance(&types::XTS.get(py)?)? {
            init_op(
                &mut ctx,
                None,
                Some(key.as_bytes()),
                iv_nonce.as_ref().map(|b| b.as_bytes()),
            )
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "In XTS mode duplicated keys are not allowed",
                )
            })?;
        } else {
            init_op(
                &mut ctx,
                None,
                Some(key.as_bytes()),
                iv_nonce.as_ref().map(|b| b.as_bytes()),
            )?;
        };

        ctx.set_padding(false);

        Ok(CipherContext {
            ctx,
            py_mode: mode.into(),
            py_algorithm: algorithm.into(),
            side,
        })
    }

    fn reset_nonce(&mut self, py: pyo3::Python<'_>, nonce: CffiBuf<'_>) -> CryptographyResult<()> {
        if !self
            .py_mode
            .bind(py)
            .is_instance(&types::MODE_WITH_NONCE.get(py)?)?
            && !self
                .py_algorithm
                .bind(py)
                .is_instance(&types::CHACHA20.get(py)?)?
        {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "This algorithm or mode does not support resetting the nonce.",
                    exceptions::Reasons::UNSUPPORTED_CIPHER,
                )),
            ));
        }
        if nonce.as_bytes().len() != self.ctx.iv_length() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Nonce must be {} bytes long",
                    self.ctx.iv_length()
                )),
            ));
        }
        let init_op = match self.side {
            openssl::symm::Mode::Encrypt => openssl::cipher_ctx::CipherCtxRef::encrypt_init,
            openssl::symm::Mode::Decrypt => openssl::cipher_ctx::CipherCtxRef::decrypt_init,
        };
        init_op(&mut self.ctx, None, None, Some(nonce.as_bytes()))?;
        Ok(())
    }

    fn update<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        buf: &[u8],
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut out_buf = vec![0; buf.len() + self.ctx.block_size()];
        let n = self.update_into(py, buf, &mut out_buf)?;
        Ok(pyo3::types::PyBytes::new_bound(py, &out_buf[..n]))
    }

    pub(crate) fn update_into(
        &mut self,
        py: pyo3::Python<'_>,
        buf: &[u8],
        out_buf: &mut [u8],
    ) -> CryptographyResult<usize> {
        if out_buf.len() < (buf.len() + self.ctx.block_size() - 1) {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be at least {} bytes for this payload",
                    buf.len() + self.ctx.block_size() - 1
                )),
            ));
        }

        let mut total_written = 0;
        for chunk in buf.chunks(1 << 29) {
            // SAFETY: We ensure that outbuf is sufficiently large above.
            unsafe {
                let n = if self.py_mode.bind(py).is_instance(&types::XTS.get(py)?)? {
                    self.ctx.cipher_update_unchecked(chunk, Some(&mut out_buf[total_written..])).map_err(|_| {
                    pyo3::exceptions::PyValueError::new_err(
                        "In XTS mode you must supply at least a full block in the first update call. For AES this is 16 bytes."
                    )
                })?
                } else {
                    self.ctx
                        .cipher_update_unchecked(chunk, Some(&mut out_buf[total_written..]))?
                };
                total_written += n;
            }
        }

        Ok(total_written)
    }

    fn authenticate_additional_data(&mut self, buf: &[u8]) -> CryptographyResult<()> {
        self.ctx.cipher_update(buf, None)?;
        Ok(())
    }

    pub(crate) fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut out_buf = vec![0; self.ctx.block_size()];
        let n = self.ctx.cipher_final(&mut out_buf).or_else(|e| {
            if e.errors().is_empty()
                && self
                    .py_mode
                    .bind(py)
                    .is_instance(&types::MODE_WITH_AUTHENTICATION_TAG.get(py)?)?
            {
                return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
            }
            Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "The length of the provided data is not a multiple of the block length.",
                ),
            ))
        })?;
        Ok(pyo3::types::PyBytes::new_bound(py, &out_buf[..n]))
    }
}

#[pyo3::pyclass(
    module = "cryptography.hazmat.bindings._rust.openssl.ciphers",
    name = "CipherContext"
)]
struct PyCipherContext {
    ctx: Option<CipherContext>,
}

#[pyo3::pyclass(
    module = "cryptography.hazmat.bindings._rust.openssl.ciphers",
    name = "AEADEncryptionContext"
)]
struct PyAEADEncryptionContext {
    ctx: Option<CipherContext>,
    tag: Option<pyo3::Py<pyo3::types::PyBytes>>,
    updated: bool,
    bytes_remaining: u64,
    aad_bytes_remaining: u64,
}

#[pyo3::pyclass(
    module = "cryptography.hazmat.bindings._rust.openssl.ciphers",
    name = "AEADDecryptionContext"
)]
struct PyAEADDecryptionContext {
    ctx: Option<CipherContext>,
    updated: bool,
    bytes_remaining: u64,
    aad_bytes_remaining: u64,
}

fn get_mut_ctx(ctx: Option<&mut CipherContext>) -> CryptographyResult<&mut CipherContext> {
    ctx.ok_or_else(exceptions::already_finalized_error)
}

#[pyo3::pymethods]
impl PyCipherContext {
    fn update<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        buf: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        get_mut_ctx(self.ctx.as_mut())?.update(py, buf.as_bytes())
    }

    fn reset_nonce(&mut self, py: pyo3::Python<'_>, nonce: CffiBuf<'_>) -> CryptographyResult<()> {
        get_mut_ctx(self.ctx.as_mut())?.reset_nonce(py, nonce)
    }

    fn update_into(
        &mut self,
        py: pyo3::Python<'_>,
        buf: CffiBuf<'_>,
        mut out_buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        get_mut_ctx(self.ctx.as_mut())?.update_into(py, buf.as_bytes(), out_buf.as_mut_bytes())
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let result = get_mut_ctx(self.ctx.as_mut())?.finalize(py)?;
        self.ctx = None;
        Ok(result)
    }
}

#[pyo3::pymethods]
impl PyAEADEncryptionContext {
    fn update<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        buf: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data = buf.as_bytes();

        self.updated = true;
        self.bytes_remaining = self
            .bytes_remaining
            .checked_sub(data.len().try_into().unwrap())
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("Exceeded maximum encrypted byte limit")
            })?;
        get_mut_ctx(self.ctx.as_mut())?.update(py, data)
    }

    fn update_into(
        &mut self,
        py: pyo3::Python<'_>,
        buf: CffiBuf<'_>,
        mut out_buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let data = buf.as_bytes();

        self.updated = true;
        self.bytes_remaining = self
            .bytes_remaining
            .checked_sub(data.len().try_into().unwrap())
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("Exceeded maximum encrypted byte limit")
            })?;
        get_mut_ctx(self.ctx.as_mut())?.update_into(py, data, out_buf.as_mut_bytes())
    }

    fn authenticate_additional_data(&mut self, buf: CffiBuf<'_>) -> CryptographyResult<()> {
        let ctx = get_mut_ctx(self.ctx.as_mut())?;
        if self.updated {
            return Err(CryptographyError::from(
                exceptions::AlreadyUpdated::new_err("Update has been called on this context."),
            ));
        }

        let data = buf.as_bytes();
        self.aad_bytes_remaining = self
            .aad_bytes_remaining
            .checked_sub(data.len().try_into().unwrap())
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("Exceeded maximum AAD byte limit")
            })?;
        ctx.authenticate_additional_data(data)
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let ctx = get_mut_ctx(self.ctx.as_mut())?;
        let result = ctx.finalize(py)?;

        // XXX: do not hard code 16
        let tag = pyo3::types::PyBytes::new_bound_with(py, 16, |t| {
            ctx.ctx.tag(t).map_err(CryptographyError::from)?;
            Ok(())
        })?;
        self.tag = Some(tag.unbind());
        self.ctx = None;

        Ok(result)
    }

    #[getter]
    fn tag(&self, py: pyo3::Python<'_>) -> CryptographyResult<pyo3::Py<pyo3::types::PyBytes>> {
        Ok(self
            .tag
            .as_ref()
            .ok_or_else(|| {
                exceptions::NotYetFinalized::new_err(
                    "You must finalize encryption before getting the tag.",
                )
            })?
            .clone_ref(py))
    }

    fn reset_nonce(&mut self, py: pyo3::Python<'_>, nonce: CffiBuf<'_>) -> CryptographyResult<()> {
        get_mut_ctx(self.ctx.as_mut())?.reset_nonce(py, nonce)
    }
}

#[pyo3::pymethods]
impl PyAEADDecryptionContext {
    fn update<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        buf: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data = buf.as_bytes();

        self.updated = true;
        self.bytes_remaining = self
            .bytes_remaining
            .checked_sub(data.len().try_into().unwrap())
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("Exceeded maximum encrypted byte limit")
            })?;
        get_mut_ctx(self.ctx.as_mut())?.update(py, data)
    }

    fn update_into(
        &mut self,
        py: pyo3::Python<'_>,
        buf: CffiBuf<'_>,
        mut out_buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let data = buf.as_bytes();

        self.updated = true;
        self.bytes_remaining = self
            .bytes_remaining
            .checked_sub(data.len().try_into().unwrap())
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("Exceeded maximum encrypted byte limit")
            })?;
        get_mut_ctx(self.ctx.as_mut())?.update_into(py, data, out_buf.as_mut_bytes())
    }

    fn authenticate_additional_data(&mut self, buf: CffiBuf<'_>) -> CryptographyResult<()> {
        let ctx = get_mut_ctx(self.ctx.as_mut())?;
        if self.updated {
            return Err(CryptographyError::from(
                exceptions::AlreadyUpdated::new_err("Update has been called on this context."),
            ));
        }

        let data = buf.as_bytes();
        self.aad_bytes_remaining = self
            .aad_bytes_remaining
            .checked_sub(data.len().try_into().unwrap())
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("Exceeded maximum AAD byte limit")
            })?;
        ctx.authenticate_additional_data(data)
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let ctx = get_mut_ctx(self.ctx.as_mut())?;

        if ctx
            .py_mode
            .bind(py)
            .getattr(pyo3::intern!(py, "tag"))?
            .is_none()
        {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "Authentication tag must be provided when decrypting.",
                ),
            ));
        }

        let result = ctx.finalize(py)?;
        self.ctx = None;
        Ok(result)
    }

    fn finalize_with_tag<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        tag: &[u8],
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let ctx = get_mut_ctx(self.ctx.as_mut())?;

        if !ctx
            .py_mode
            .bind(py)
            .getattr(pyo3::intern!(py, "tag"))?
            .is_none()
        {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "Authentication tag must be provided only once.",
                ),
            ));
        }

        let min_tag_length = ctx
            .py_mode
            .bind(py)
            .getattr(pyo3::intern!(py, "_min_tag_length"))?
            .extract()?;
        // XXX: Do not hard code 16
        if tag.len() < min_tag_length {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Authentication tag must be {} bytes or longer.",
                    min_tag_length
                )),
            ));
        } else if tag.len() > 16 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Authentication tag cannot be more than {} bytes.",
                    16
                )),
            ));
        }

        ctx.ctx.set_tag(tag)?;
        let result = ctx.finalize(py)?;
        self.ctx = None;
        Ok(result)
    }

    fn reset_nonce(&mut self, py: pyo3::Python<'_>, nonce: CffiBuf<'_>) -> CryptographyResult<()> {
        get_mut_ctx(self.ctx.as_mut())?.reset_nonce(py, nonce)
    }
}

#[pyo3::pyfunction]
fn create_encryption_ctx(
    py: pyo3::Python<'_>,
    algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    mode: pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<pyo3::PyObject> {
    let ctx = CipherContext::new(py, algorithm, mode.clone(), openssl::symm::Mode::Encrypt)?;

    if mode.is_instance(&types::MODE_WITH_AUTHENTICATION_TAG.get(py)?)? {
        Ok(PyAEADEncryptionContext {
            ctx: Some(ctx),
            tag: None,
            updated: false,
            bytes_remaining: mode
                .getattr(pyo3::intern!(py, "_MAX_ENCRYPTED_BYTES"))?
                .extract()?,
            aad_bytes_remaining: mode
                .getattr(pyo3::intern!(py, "_MAX_AAD_BYTES"))?
                .extract()?,
        }
        .into_py(py))
    } else {
        Ok(PyCipherContext { ctx: Some(ctx) }.into_py(py))
    }
}

#[pyo3::pyfunction]
fn create_decryption_ctx(
    py: pyo3::Python<'_>,
    algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    mode: pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<pyo3::PyObject> {
    let mut ctx = CipherContext::new(py, algorithm, mode.clone(), openssl::symm::Mode::Decrypt)?;

    if mode.is_instance(&types::MODE_WITH_AUTHENTICATION_TAG.get(py)?)? {
        if let Some(tag) = mode
            .getattr(pyo3::intern!(py, "tag"))?
            .extract::<Option<pyo3::pybacked::PyBackedBytes>>()?
        {
            ctx.ctx.set_tag(&tag)?;
        }

        Ok(PyAEADDecryptionContext {
            ctx: Some(ctx),
            updated: false,
            bytes_remaining: mode
                .getattr(pyo3::intern!(py, "_MAX_ENCRYPTED_BYTES"))?
                .extract()?,
            aad_bytes_remaining: mode
                .getattr(pyo3::intern!(py, "_MAX_AAD_BYTES"))?
                .extract()?,
        }
        .into_py(py))
    } else {
        Ok(PyCipherContext { ctx: Some(ctx) }.into_py(py))
    }
}

#[pyo3::pyfunction]
fn cipher_supported(
    py: pyo3::Python<'_>,
    algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    mode: pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<bool> {
    Ok(cipher_registry::get_cipher(py, algorithm, mode.get_type().into_any())?.is_some())
}

#[pyo3::pyfunction]
fn _advance(ctx: pyo3::Bound<'_, pyo3::PyAny>, n: u64) {
    if let Ok(c) = ctx.downcast::<PyAEADEncryptionContext>() {
        c.borrow_mut().bytes_remaining -= n;
    } else if let Ok(c) = ctx.downcast::<PyAEADDecryptionContext>() {
        c.borrow_mut().bytes_remaining -= n;
    }
}

#[pyo3::pyfunction]
fn _advance_aad(ctx: pyo3::Bound<'_, pyo3::PyAny>, n: u64) {
    if let Ok(c) = ctx.downcast::<PyAEADEncryptionContext>() {
        c.borrow_mut().aad_bytes_remaining -= n;
    } else if let Ok(c) = ctx.downcast::<PyAEADDecryptionContext>() {
        c.borrow_mut().aad_bytes_remaining -= n;
    }
}

#[pyo3::pymodule]
pub(crate) mod ciphers {
    #[pymodule_export]
    use super::{
        _advance, _advance_aad, cipher_supported, create_decryption_ctx, create_encryption_ctx,
        PyAEADDecryptionContext, PyAEADEncryptionContext, PyCipherContext,
    };
}
