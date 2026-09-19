// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyAnyMethods;
use pyo3::IntoPyObject;

use crate::backend::cipher_registry;
use crate::buf::{CffiBuf, CffiMutBuf};
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types};

enum Operation {
    Conventional(openssl_bridge::cipher::Stream),
    Xts(Option<openssl_bridge::cipher::XtsDataUnit>),
    GcmEncrypt(openssl_bridge::gcm::GcmEncrypt),
    GcmDecrypt(openssl_bridge::gcm::UnverifiedGcmDecrypt),
}

pub(crate) struct CipherContext {
    ctx: Option<Operation>,
    py_mode: pyo3::Py<pyo3::PyAny>,
    py_algorithm: pyo3::Py<pyo3::PyAny>,
    block_size: usize,
    iv_size: usize,
    tag: Option<[u8; 16]>,
    expected_tag: Option<Vec<u8>>,
}

impl CipherContext {
    pub(crate) fn new(
        py: pyo3::Python<'_>,
        algorithm: pyo3::Bound<'_, pyo3::PyAny>,
        mode: pyo3::Bound<'_, pyo3::PyAny>,
        side: openssl_bridge::cipher::Direction,
    ) -> CryptographyResult<CipherContext> {
        let cipher =
            match cipher_registry::get_cipher(py, algorithm.clone(), mode.get_type().into_any())? {
                Some(c) => c,
                None => {
                    return Err(exceptions::UnsupportedAlgorithm::new_err((
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
                    ))
                    .into())
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
        let iv = iv_nonce.as_ref().map_or(&[][..], |b| b.as_bytes());
        let key = algorithm
            .getattr(pyo3::intern!(py, "key"))?
            .extract::<CffiBuf<'_>>()?;
        let ctx = match cipher.algorithm {
            cipher_registry::Algorithm::Conventional(cipher) => Operation::Conventional(
                openssl_bridge::cipher::Stream::new(cipher, side, key.as_bytes(), iv, false)?,
            ),
            cipher_registry::Algorithm::Xts => {
                let tweak = iv.try_into().map_err(|_| {
                    pyo3::exceptions::PyValueError::new_err("XTS tweak must contain 16 bytes")
                })?;
                Operation::Xts(Some(
                    openssl_bridge::cipher::XtsDataUnit::new(side, key.as_bytes(), tweak).map_err(
                        |_| {
                            pyo3::exceptions::PyValueError::new_err(
                                "In XTS mode duplicated keys are not allowed",
                            )
                        },
                    )?,
                ))
            }
            cipher_registry::Algorithm::Gcm(cipher) => match side {
                openssl_bridge::cipher::Direction::Encrypt => Operation::GcmEncrypt(
                    openssl_bridge::gcm::GcmEncrypt::new(cipher, key.as_bytes(), iv)?,
                ),
                openssl_bridge::cipher::Direction::Decrypt => Operation::GcmDecrypt(
                    openssl_bridge::gcm::UnverifiedGcmDecrypt::new(cipher, key.as_bytes(), iv)?,
                ),
            },
        };
        let block_size = match &ctx {
            Operation::Conventional(ctx) => ctx.block_size(),
            _ => 1,
        };
        Ok(Self {
            ctx: Some(ctx),
            py_mode: mode.into(),
            py_algorithm: algorithm.into(),
            block_size,
            iv_size: iv.len(),
            tag: None,
            expected_tag: None,
        })
    }
    fn reset_nonce(&mut self, py: pyo3::Python<'_>, nonce: &[u8]) -> CryptographyResult<()> {
        if !self
            .py_mode
            .bind(py)
            .is_instance(&types::MODE_WITH_NONCE.get(py)?)?
            && !self
                .py_algorithm
                .bind(py)
                .is_instance(&types::CHACHA20.get(py)?)?
        {
            return Err(exceptions::UnsupportedAlgorithm::new_err((
                "This algorithm or mode does not support resetting the nonce.",
                exceptions::Reasons::UNSUPPORTED_CIPHER,
            ))
            .into());
        }
        if nonce.len() != self.iv_size {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Nonce must be {} bytes long",
                self.iv_size
            ))
            .into());
        }
        match self
            .ctx
            .as_mut()
            .ok_or_else(exceptions::already_finalized_error)?
        {
            Operation::Conventional(ctx) => ctx.reset_nonce(nonce)?,
            _ => {
                return Err(exceptions::UnsupportedAlgorithm::new_err((
                    "This algorithm or mode does not support resetting the nonce.",
                    exceptions::Reasons::UNSUPPORTED_CIPHER,
                ))
                .into())
            }
        }
        Ok(())
    }
    fn update<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        data: &[u8],
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if self.block_size == 1 {
            return Ok(pyo3::types::PyBytes::new_with(py, data.len(), |b| {
                let n = self.update_into(py, data, b)?;
                assert_eq!(n, data.len());
                Ok(())
            })?);
        }
        let mut buf = vec![0; data.len() + self.block_size];
        let n = self.update_into(py, data, &mut buf)?;
        Ok(pyo3::types::PyBytes::new(py, &buf[..n]))
    }
    pub(crate) fn update_into(
        &mut self,
        py: pyo3::Python<'_>,
        data: &[u8],
        buf: &mut [u8],
    ) -> CryptographyResult<usize> {
        let required = crate::buf::checked_add_length(data.len(), self.block_size - 1)?;
        if buf.len() < required {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "buffer must be at least {required} bytes for this payload"
            ))
            .into());
        }
        crate::backend::run_with_gil_detached(py, data.len(), || self.update_into_inner(data, buf))
    }
    fn update_into_inner(&mut self, data: &[u8], buf: &mut [u8]) -> CryptographyResult<usize> {
        let ctx = self
            .ctx
            .as_mut()
            .ok_or_else(exceptions::already_finalized_error)?;
        if let Operation::Xts(ctx) = ctx {
            if data.is_empty() {
                return Ok(0);
            }
            let unit = ctx.take().ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "An XTS data unit must be supplied in one update call",
                )
            })?;
            return Ok(unit.crypt_into(data, buf).map_err(|_| pyo3::exceptions::PyValueError::new_err("In XTS mode you must supply at least a full block in the first update call. For AES this is 16 bytes."))?);
        }
        let mut written = 0;
        for chunk in data.chunks(1 << 29) {
            written += match ctx {
                Operation::Conventional(ctx) => ctx.update_into(chunk, &mut buf[written..])?,
                Operation::GcmEncrypt(ctx) => ctx.update_into(chunk, &mut buf[written..])?,
                Operation::GcmDecrypt(ctx) => {
                    ctx.update_unverified_into(chunk, &mut buf[written..])?
                }
                // XTS returns before entering this loop.
                // NO-COVERAGE-START
                Operation::Xts(_) => unreachable!(),
                // NO-COVERAGE-END
            };
        }
        Ok(written)
    }
    fn authenticate_additional_data(
        &mut self,
        py: pyo3::Python<'_>,
        data: &[u8],
    ) -> CryptographyResult<()> {
        let ctx = self
            .ctx
            .as_mut()
            .ok_or_else(exceptions::already_finalized_error)?;
        crate::backend::run_with_gil_detached(py, data.len(), || -> CryptographyResult<()> {
            for chunk in data.chunks(1 << 29) {
                match ctx {
                    Operation::GcmEncrypt(ctx) => ctx.authenticate(chunk)?,
                    Operation::GcmDecrypt(ctx) => ctx.authenticate(chunk)?,
                    _ => {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "AAD requires an authenticated cipher",
                        )
                        .into())
                    }
                }
            }
            Ok(())
        })
    }
    pub(crate) fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let ctx = self
            .ctx
            .take()
            .ok_or_else(exceptions::already_finalized_error)?;
        let output = match ctx {
            Operation::Conventional(ctx) => ctx.finish().map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "The length of the provided data is not a multiple of the block length.",
                )
            })?,
            Operation::Xts(_) => vec![],
            Operation::GcmEncrypt(ctx) => {
                self.tag = Some(ctx.finish()?);
                vec![]
            }
            Operation::GcmDecrypt(ctx) => {
                let tag = self.expected_tag.as_ref().ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(
                        "Authentication tag must be provided when decrypting.",
                    )
                })?;
                ctx.finish(tag)
                    .map_err(|_| exceptions::InvalidTag::new_err(()))?;
                vec![]
            }
        };
        Ok(pyo3::types::PyBytes::new(py, &output))
    }
}

// ChaCha20 generates 64 bytes of keystream per 32-bit block counter value.
const CHACHA20_BLOCK_SIZE: u64 = 64;

// The 16-byte ChaCha20 nonce begins with a 32-bit little-endian block counter.
// Encrypting more than `(2**32 - counter) * 64` bytes would overflow that
// counter, at which point the OpenSSL implementation silently diverges from
// RFC 7539 (the counter carries into the rest of the nonce), so we instead
// refuse to encrypt past that point.
fn chacha20_byte_limit(nonce: &[u8]) -> u64 {
    let counter = u32::from_le_bytes(nonce[..4].try_into().unwrap());
    ((1u64 << 32) - u64::from(counter)) * CHACHA20_BLOCK_SIZE
}

fn chacha20_initial_byte_limit(
    py: pyo3::Python<'_>,
    algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<Option<u64>> {
    if algorithm.is_instance(&types::CHACHA20.get(py)?)? {
        let nonce = algorithm
            .getattr(pyo3::intern!(py, "nonce"))?
            .extract::<CffiBuf<'_>>()?;
        Ok(Some(chacha20_byte_limit(nonce.as_bytes())))
    } else {
        Ok(None)
    }
}

#[pyo3::pyclass(
    module = "cryptography.hazmat.bindings._rust.openssl.ciphers",
    name = "CipherContext"
)]
struct PyCipherContext {
    ctx: Option<CipherContext>,
    // For ChaCha20 this tracks how many more bytes may be processed before the
    // 32-bit block counter would overflow. `None` for all other ciphers.
    bytes_remaining: Option<u64>,
}

impl PyCipherContext {
    fn decrement_bytes_remaining(&mut self, n: usize) -> CryptographyResult<()> {
        if let Some(remaining) = self.bytes_remaining {
            self.bytes_remaining = Some(
                remaining
                    .checked_sub(u64::try_from(n).unwrap())
                    .ok_or_else(|| {
                        pyo3::exceptions::PyValueError::new_err(
                            "Exceeded the maximum number of bytes that can be \
                             encrypted with ChaCha20 for this nonce. The 32-bit \
                             counter portion of the nonce would overflow.",
                        )
                    })?,
            );
        }
        Ok(())
    }
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
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data = data.as_bytes();
        self.decrement_bytes_remaining(data.len())?;
        get_mut_ctx(self.ctx.as_mut())?.update(py, data)
    }

    fn reset_nonce(&mut self, py: pyo3::Python<'_>, nonce: CffiBuf<'_>) -> CryptographyResult<()> {
        let nonce = nonce.as_bytes();
        get_mut_ctx(self.ctx.as_mut())?.reset_nonce(py, nonce)?;
        // The reset above validates the nonce length, so recompute the ChaCha20
        // limit for the new counter only after it succeeds.
        if self.bytes_remaining.is_some() {
            self.bytes_remaining = Some(chacha20_byte_limit(nonce));
        }
        Ok(())
    }

    fn update_into(
        &mut self,
        py: pyo3::Python<'_>,
        data: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let data = data.as_bytes();
        self.decrement_bytes_remaining(data.len())?;
        let written = get_mut_ctx(self.ctx.as_mut())?.update_into(py, data, buf.as_mut_bytes())?;
        buf.commit(py, written)?;
        Ok(written)
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
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data = data.as_bytes();

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
        data: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let data = data.as_bytes();

        self.updated = true;
        self.bytes_remaining = self
            .bytes_remaining
            .checked_sub(data.len().try_into().unwrap())
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("Exceeded maximum encrypted byte limit")
            })?;
        let written = get_mut_ctx(self.ctx.as_mut())?.update_into(py, data, buf.as_mut_bytes())?;
        buf.commit(py, written)?;
        Ok(written)
    }

    fn authenticate_additional_data(
        &mut self,
        py: pyo3::Python<'_>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        let ctx = get_mut_ctx(self.ctx.as_mut())?;
        if self.updated {
            return Err(CryptographyError::from(
                exceptions::AlreadyUpdated::new_err("Update has been called on this context."),
            ));
        }

        let data = data.as_bytes();
        self.aad_bytes_remaining = self
            .aad_bytes_remaining
            .checked_sub(data.len().try_into().unwrap())
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("Exceeded maximum AAD byte limit")
            })?;
        ctx.authenticate_additional_data(py, data)
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let ctx = get_mut_ctx(self.ctx.as_mut())?;
        let result = ctx.finalize(py)?;

        // XXX: do not hard code 16
        let tag = pyo3::types::PyBytes::new(py, ctx.tag.as_ref().unwrap());
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
        get_mut_ctx(self.ctx.as_mut())?.reset_nonce(py, nonce.as_bytes())
    }
}

#[pyo3::pymethods]
impl PyAEADDecryptionContext {
    fn update<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data = data.as_bytes();

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
        data: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let data = data.as_bytes();

        self.updated = true;
        self.bytes_remaining = self
            .bytes_remaining
            .checked_sub(data.len().try_into().unwrap())
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("Exceeded maximum encrypted byte limit")
            })?;
        let written = get_mut_ctx(self.ctx.as_mut())?.update_into(py, data, buf.as_mut_bytes())?;
        buf.commit(py, written)?;
        Ok(written)
    }

    fn authenticate_additional_data(
        &mut self,
        py: pyo3::Python<'_>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        let ctx = get_mut_ctx(self.ctx.as_mut())?;
        if self.updated {
            return Err(CryptographyError::from(
                exceptions::AlreadyUpdated::new_err("Update has been called on this context."),
            ));
        }

        let data = data.as_bytes();
        self.aad_bytes_remaining = self
            .aad_bytes_remaining
            .checked_sub(data.len().try_into().unwrap())
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("Exceeded maximum AAD byte limit")
            })?;
        ctx.authenticate_additional_data(py, data)
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
                    "Authentication tag must be {min_tag_length} bytes or longer.",
                )),
            ));
        } else if tag.len() > 16 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "Authentication tag cannot be more than 16 bytes.",
                ),
            ));
        }

        ctx.expected_tag = Some(tag.to_vec());
        let result = ctx.finalize(py)?;
        self.ctx = None;
        Ok(result)
    }

    fn reset_nonce(&mut self, py: pyo3::Python<'_>, nonce: CffiBuf<'_>) -> CryptographyResult<()> {
        get_mut_ctx(self.ctx.as_mut())?.reset_nonce(py, nonce.as_bytes())
    }
}

#[pyo3::pyfunction]
fn create_encryption_ctx<'p>(
    py: pyo3::Python<'p>,
    algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    mode: pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let bytes_remaining = chacha20_initial_byte_limit(py, &algorithm)?;
    let ctx = CipherContext::new(
        py,
        algorithm,
        mode.clone(),
        openssl_bridge::cipher::Direction::Encrypt,
    )?;

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
        .into_pyobject(py)?
        .into_any())
    } else {
        Ok(PyCipherContext {
            ctx: Some(ctx),
            bytes_remaining,
        }
        .into_pyobject(py)?
        .into_any())
    }
}

#[pyo3::pyfunction]
fn create_decryption_ctx<'p>(
    py: pyo3::Python<'p>,
    algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    mode: pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let bytes_remaining = chacha20_initial_byte_limit(py, &algorithm)?;
    let mut ctx = CipherContext::new(
        py,
        algorithm,
        mode.clone(),
        openssl_bridge::cipher::Direction::Decrypt,
    )?;

    if mode.is_instance(&types::MODE_WITH_AUTHENTICATION_TAG.get(py)?)? {
        if let Some(tag) = mode
            .getattr(pyo3::intern!(py, "tag"))?
            .extract::<Option<pyo3::pybacked::PyBackedBytes>>()?
        {
            ctx.expected_tag = Some(tag.to_vec());
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
        .into_pyobject(py)?
        .into_any())
    } else {
        Ok(PyCipherContext {
            ctx: Some(ctx),
            bytes_remaining,
        }
        .into_pyobject(py)?
        .into_any())
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
    if let Ok(c) = ctx.cast::<PyAEADEncryptionContext>() {
        c.borrow_mut().bytes_remaining -= n;
    } else if let Ok(c) = ctx.cast::<PyAEADDecryptionContext>() {
        c.borrow_mut().bytes_remaining -= n;
    }
}

#[pyo3::pyfunction]
fn _advance_aad(ctx: pyo3::Bound<'_, pyo3::PyAny>, n: u64) {
    if let Ok(c) = ctx.cast::<PyAEADEncryptionContext>() {
        c.borrow_mut().aad_bytes_remaining -= n;
    } else if let Ok(c) = ctx.cast::<PyAEADDecryptionContext>() {
        c.borrow_mut().aad_bytes_remaining -= n;
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod ciphers {
    #[pymodule_export]
    use super::{
        _advance, _advance_aad, cipher_supported, create_decryption_ctx, create_encryption_ctx,
        PyAEADDecryptionContext, PyAEADEncryptionContext, PyCipherContext,
    };
}
