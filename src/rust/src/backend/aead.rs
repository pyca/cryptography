// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyListMethods;

use crate::buf::{CffiBuf, CffiMutBuf};
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

fn check_length(data: &[u8]) -> CryptographyResult<()> {
    if data.len() > (i32::MAX as usize) {
        // This is OverflowError to match what cffi would raise
        return Err(CryptographyError::from(
            pyo3::exceptions::PyOverflowError::new_err(
                "Data or associated data too long. Max 2**31 - 1 bytes",
            ),
        ));
    }

    Ok(())
}

pub(crate) enum Aad<'a> {
    Single(CffiBuf<'a>),
    List(pyo3::Bound<'a, pyo3::types::PyList>),
}

/// AAD that has been extracted and length-checked while attached to the
/// interpreter. `CffiBuf` holds no GIL-bound references, so this may be
/// used from a detached region.
enum ExtractedAad<'a> {
    None,
    Single(CffiBuf<'a>),
    List(Vec<CffiBuf<'a>>),
}

/// Returns the extracted AAD and its total length in bytes.
fn extract_aad(aad: Option<Aad<'_>>) -> CryptographyResult<(ExtractedAad<'_>, usize)> {
    match aad {
        None => Ok((ExtractedAad::None, 0)),
        Some(Aad::Single(ad)) => {
            check_length(ad.as_bytes())?;
            let len = ad.as_bytes().len();
            Ok((ExtractedAad::Single(ad), len))
        }
        Some(Aad::List(ads)) => {
            let mut bufs = Vec::with_capacity(ads.len());
            let mut len = 0usize;
            for ad in ads.iter() {
                let buf = crate::buf::extract_aead_buffer(&ad)?;
                check_length(buf.as_bytes())?;
                len = len.checked_add(buf.as_bytes().len()).ok_or_else(|| {
                    pyo3::exceptions::PyOverflowError::new_err("associated data length overflow")
                })?;
                bufs.push(buf);
            }
            Ok((ExtractedAad::List(bufs), len))
        }
    }
}

struct CheckedAead {
    key: openssl_bridge::aead::Key,
    tag_len: usize,
    tag_first: bool,
}

impl ExtractedAad<'_> {
    fn slices(&self) -> Vec<&[u8]> {
        match self {
            Self::None => vec![],
            Self::Single(ad) => vec![ad.as_bytes()],
            Self::List(ads) => ads.iter().map(|ad| ad.as_bytes()).collect(),
        }
    }
}

impl CheckedAead {
    fn new(
        py: pyo3::Python<'_>,
        algorithm: openssl_bridge::aead::Algorithm,
        key: pyo3::Py<pyo3::PyAny>,
        tag_len: usize,
        tag_first: bool,
    ) -> CryptographyResult<Self> {
        let key_buf = key.extract::<CffiBuf<'_>>(py)?;
        let key = if matches!(
            algorithm,
            openssl_bridge::aead::Algorithm::Aes128Ccm
                | openssl_bridge::aead::Algorithm::Aes192Ccm
                | openssl_bridge::aead::Algorithm::Aes256Ccm
        ) {
            openssl_bridge::aead::Key::ccm(key_buf.as_bytes(), tag_len)?
        } else {
            openssl_bridge::aead::Key::new(algorithm, key_buf.as_bytes())?
        };
        Ok(Self {
            tag_len: key.tag_size(),
            key,
            tag_first,
        })
    }
    #[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))]
    fn from_bytes(
        algorithm: openssl_bridge::aead::Algorithm,
        key: &[u8],
        tag_len: usize,
    ) -> CryptographyResult<Self> {
        let key = openssl_bridge::aead::Key::new(algorithm, key)?;
        assert_eq!(tag_len, key.tag_size());
        Ok(Self {
            key,
            tag_len,
            tag_first: false,
        })
    }
    fn encrypt_into(
        &self,
        py: pyo3::Python<'_>,
        plaintext: &[u8],
        aad: Option<Aad<'_>>,
        nonce: Option<&[u8]>,
        buf: &mut [u8],
    ) -> CryptographyResult<()> {
        check_length(plaintext)?;
        if buf.len() != plaintext.len() + self.tag_len {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "incorrect AEAD output buffer length",
            )
            .into());
        }
        let (ciphertext, tag) = if self.tag_first {
            let (tag, ciphertext) = buf.split_at_mut(self.tag_len);
            (ciphertext, tag)
        } else {
            buf.split_at_mut(plaintext.len())
        };
        let (aad, aad_len) = extract_aad(aad)?;
        let components = aad.slices();
        crate::backend::run_with_gil_detached(
            py,
            plaintext.len().saturating_add(aad_len),
            || -> CryptographyResult<()> {
                self.key.seal_into(
                    nonce.unwrap_or(&[]),
                    &components,
                    plaintext,
                    ciphertext,
                    tag,
                )?;
                Ok(())
            },
        )
    }
    fn decrypt_into(
        &self,
        py: pyo3::Python<'_>,
        ciphertext: &[u8],
        aad: Option<Aad<'_>>,
        nonce: Option<&[u8]>,
        buf: &mut [u8],
    ) -> CryptographyResult<()> {
        check_length(ciphertext)?;
        if ciphertext.len() < self.tag_len {
            return Err(exceptions::InvalidTag::new_err(()).into());
        }
        let (data, tag) = if self.tag_first {
            let (tag, data) = ciphertext.split_at(self.tag_len);
            (data, tag)
        } else {
            ciphertext.split_at(ciphertext.len() - self.tag_len)
        };
        let (aad, aad_len) = extract_aad(aad)?;
        let components = aad.slices();
        crate::backend::run_with_gil_detached(
            py,
            data.len().saturating_add(aad_len),
            || -> CryptographyResult<()> {
                self.key
                    .open_into(nonce.unwrap_or(&[]), &components, data, tag, buf)
                    .map_err(|_| exceptions::InvalidTag::new_err(()))?;
                Ok(())
            },
        )
    }
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.aead")]
pub(crate) struct ChaCha20Poly1305 {
    ctx: CheckedAead,
}

#[pyo3::pymethods]
impl ChaCha20Poly1305 {
    #[new]
    pub(crate) fn new(
        py: pyo3::Python<'_>,
        key: pyo3::Py<pyo3::PyAny>,
    ) -> CryptographyResult<Self> {
        let key_buf = key.extract::<CffiBuf<'_>>(py)?;
        if key_buf.as_bytes().len() != 32 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("ChaCha20Poly1305 key must be 32 bytes."),
            ));
        }
        if openssl_bridge::runtime::is_fips_enabled() {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "ChaCha20Poly1305 is not supported by this version of OpenSSL",
                    exceptions::Reasons::UNSUPPORTED_CIPHER,
                )),
            ));
        }

        cfg_if::cfg_if! {
            if #[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))] {
                Ok(ChaCha20Poly1305 {
                    ctx: CheckedAead::from_bytes(
                        openssl_bridge::aead::Algorithm::ChaCha20Poly1305,
                        key_buf.as_bytes(),
                        16,
                    )?,
                })
            } else {
                Ok(ChaCha20Poly1305 {
                    ctx: CheckedAead::new(
                        py,
                        openssl_bridge::aead::Algorithm::ChaCha20Poly1305,
                        key,
                        16,
                        false,
                    )?,
                })
            }
        }
    }

    #[staticmethod]
    fn generate_key(
        py: pyo3::Python<'_>,
    ) -> CryptographyResult<pyo3::Bound<'_, pyo3::types::PyBytes>> {
        crate::backend::rand::get_rand_bytes(py, 32)
    }

    #[pyo3(signature = (nonce, data, associated_data))]
    pub(crate) fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data_bytes = data.as_bytes();
        check_length(data_bytes)?;
        Ok(pyo3::types::PyBytes::new_with(
            py,
            data_bytes.len() + self.ctx.tag_len,
            |b| {
                let buf = CffiMutBuf::from_bytes(py, b);
                self.encrypt_into(py, nonce, data, associated_data, buf)?;
                Ok(())
            },
        )?)
    }

    #[pyo3(signature = (nonce, data, associated_data, buf))]
    pub(crate) fn encrypt_into(
        &self,
        py: pyo3::Python<'_>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let nonce_bytes = nonce.as_bytes();
        let data_bytes = data.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() != 12 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be 12 bytes"),
            ));
        }

        // Check this early so we know we can add tag_len without overflow
        // check_length requires that the length be 2 ** 31 - 1 or smaller.
        check_length(data_bytes)?;
        let expected_len = data_bytes.len() + 16;
        if buf.as_mut_bytes().len() != expected_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    expected_len
                )),
            ));
        }

        self.ctx
            .encrypt_into(py, data_bytes, aad, Some(nonce_bytes), buf.as_mut_bytes())?;
        buf.commit(py, expected_len)?;
        Ok(expected_len)
    }

    #[pyo3(signature = (nonce, data, associated_data))]
    pub(crate) fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if nonce.as_bytes().len() != 12 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be 12 bytes"),
            ));
        }
        if data.as_bytes().len() < self.ctx.tag_len {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }
        Ok(pyo3::types::PyBytes::new_with(
            py,
            data.as_bytes().len() - self.ctx.tag_len,
            |b| {
                let buf = CffiMutBuf::from_bytes(py, b);
                self.decrypt_into(py, nonce, data, associated_data, buf)?;
                Ok(())
            },
        )?)
    }

    #[pyo3(signature = (nonce, data, associated_data, buf))]
    fn decrypt_into(
        &self,
        py: pyo3::Python<'_>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let nonce_bytes = nonce.as_bytes();
        let data_bytes = data.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() != 12 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be 12 bytes"),
            ));
        }

        if data.as_bytes().len() < self.ctx.tag_len {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        let expected_len = data_bytes.len() - self.ctx.tag_len;
        if buf.as_mut_bytes().len() != expected_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    expected_len
                )),
            ));
        }

        self.ctx
            .decrypt_into(py, data_bytes, aad, Some(nonce_bytes), buf.as_mut_bytes())?;

        buf.commit(py, expected_len)?;
        Ok(expected_len)
    }
}

// NO-COVERAGE-START
#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.aead",
    name = "AESGCM"
)]
// NO-COVERAGE-END
pub(crate) struct AesGcm {
    ctx: CheckedAead,
}

#[pyo3::pymethods]
impl AesGcm {
    #[new]
    pub(crate) fn new(
        py: pyo3::Python<'_>,
        key: pyo3::Py<pyo3::PyAny>,
    ) -> CryptographyResult<AesGcm> {
        let key_buf = key.extract::<CffiBuf<'_>>(py)?;
        let cipher = match key_buf.as_bytes().len() {
            16 => openssl_bridge::aead::Algorithm::Aes128Gcm,
            24 => openssl_bridge::aead::Algorithm::Aes192Gcm,
            32 => openssl_bridge::aead::Algorithm::Aes256Gcm,
            _ => {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "AESGCM key must be 128, 192, or 256 bits.",
                    ),
                ))
            }
        };

        Ok(AesGcm {
            ctx: CheckedAead::new(py, cipher, key, 16, false)?,
        })
    }

    #[staticmethod]
    fn generate_key(
        py: pyo3::Python<'_>,
        bit_length: usize,
    ) -> CryptographyResult<pyo3::Bound<'_, pyo3::types::PyBytes>> {
        if bit_length != 128 && bit_length != 192 && bit_length != 256 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("bit_length must be 128, 192, or 256"),
            ));
        }

        crate::backend::rand::get_rand_bytes(py, bit_length / 8)
    }

    #[pyo3(signature = (nonce, data, associated_data))]
    pub(crate) fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data_bytes = data.as_bytes();
        check_length(data_bytes)?;
        Ok(pyo3::types::PyBytes::new_with(
            py,
            data_bytes.len() + self.ctx.tag_len,
            |b| {
                let buf = CffiMutBuf::from_bytes(py, b);
                self.encrypt_into(py, nonce, data, associated_data, buf)?;
                Ok(())
            },
        )?)
    }

    #[pyo3(signature = (nonce, data, associated_data, buf))]
    pub(crate) fn encrypt_into(
        &self,
        py: pyo3::Python<'_>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let nonce_bytes = nonce.as_bytes();
        let data_bytes = data.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() < 8 || nonce_bytes.len() > 128 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be between 8 and 128 bytes"),
            ));
        }

        // Check this early so we know we can add tag_len without overflow
        // check_length requires that the length be 2 ** 31 - 1 or smaller.
        check_length(data_bytes)?;
        let expected_len = data_bytes.len() + 16;
        if buf.as_mut_bytes().len() != expected_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    expected_len
                )),
            ));
        }

        self.ctx
            .encrypt_into(py, data_bytes, aad, Some(nonce_bytes), buf.as_mut_bytes())?;
        buf.commit(py, expected_len)?;
        Ok(expected_len)
    }

    #[pyo3(signature = (nonce, data, associated_data))]
    pub(crate) fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let nonce_bytes = nonce.as_bytes();
        let data_bytes = data.as_bytes();

        if nonce_bytes.len() < 8 || nonce_bytes.len() > 128 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be between 8 and 128 bytes"),
            ));
        }

        if data_bytes.len() < self.ctx.tag_len {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        Ok(pyo3::types::PyBytes::new_with(
            py,
            data_bytes.len() - self.ctx.tag_len,
            |b| {
                let buf = CffiMutBuf::from_bytes(py, b);
                self.decrypt_into(py, nonce, data, associated_data, buf)?;
                Ok(())
            },
        )?)
    }

    #[pyo3(signature = (nonce, data, associated_data, buf))]
    pub(crate) fn decrypt_into(
        &self,
        py: pyo3::Python<'_>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let nonce_bytes = nonce.as_bytes();
        let data_bytes = data.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() < 8 || nonce_bytes.len() > 128 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be between 8 and 128 bytes"),
            ));
        }

        if data_bytes.len() < self.ctx.tag_len {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        let expected_len = data_bytes.len() - self.ctx.tag_len;
        if buf.as_mut_bytes().len() != expected_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    expected_len
                )),
            ));
        }

        self.ctx
            .decrypt_into(py, data_bytes, aad, Some(nonce_bytes), buf.as_mut_bytes())?;

        buf.commit(py, expected_len)?;
        Ok(expected_len)
    }
}

// NO-COVERAGE-START
#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.aead",
    name = "AESCCM"
)]
// NO-COVERAGE-END
struct AesCcm {
    ctx: CheckedAead,
    tag_length: usize,
}

#[pyo3::pymethods]
impl AesCcm {
    #[new]
    #[pyo3(signature = (key, tag_length=None))]
    fn new(
        py: pyo3::Python<'_>,
        key: pyo3::Py<pyo3::PyAny>,
        tag_length: Option<usize>,
    ) -> CryptographyResult<AesCcm> {
        cfg_if::cfg_if! {
            if #[cfg(CRYPTOGRAPHY_IS_BORINGSSL)] {
                let _ = py;
                let _ = key;
                let _ = tag_length;
                Err(CryptographyError::from(
                    exceptions::UnsupportedAlgorithm::new_err((
                        "AES-CCM is not supported by this version of OpenSSL",
                        exceptions::Reasons::UNSUPPORTED_CIPHER,
                    )),
                ))
            } else {
                let key_buf = key.extract::<CffiBuf<'_>>(py)?;
                let cipher = match key_buf.as_bytes().len() {
                    16 => openssl_bridge::aead::Algorithm::Aes128Ccm,
                    24 => openssl_bridge::aead::Algorithm::Aes192Ccm,
                    32 => openssl_bridge::aead::Algorithm::Aes256Ccm,
                    _ => {
                        return Err(CryptographyError::from(
                            pyo3::exceptions::PyValueError::new_err(
                                "AESCCM key must be 128, 192, or 256 bits.",
                            ),
                        ))
                    }
                };
                let tag_length = tag_length.unwrap_or(16);
                if ![4, 6, 8, 10, 12, 14, 16].contains(&tag_length) {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err("Invalid tag_length"),
                    ));
                }

                Ok(AesCcm {
                    ctx: CheckedAead::new(
                        py,
                        cipher,
                        key,
                        tag_length,
                        false,
                    )?,
                    tag_length
                })
            }
        }
    }

    #[staticmethod]
    fn generate_key(
        py: pyo3::Python<'_>,
        bit_length: usize,
    ) -> CryptographyResult<pyo3::Bound<'_, pyo3::types::PyBytes>> {
        if bit_length != 128 && bit_length != 192 && bit_length != 256 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("bit_length must be 128, 192, or 256"),
            ));
        }
        crate::backend::rand::get_rand_bytes(py, bit_length / 8)
    }

    #[pyo3(signature = (nonce, data, associated_data))]
    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data_bytes = data.as_bytes();
        check_length(data_bytes)?;
        Ok(pyo3::types::PyBytes::new_with(
            py,
            data_bytes.len() + self.tag_length,
            |b| {
                let buf = CffiMutBuf::from_bytes(py, b);
                self.encrypt_into(py, nonce, data, associated_data, buf)?;
                Ok(())
            },
        )?)
    }

    #[pyo3(signature = (nonce, data, associated_data, buf))]
    fn encrypt_into(
        &self,
        py: pyo3::Python<'_>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let nonce_bytes = nonce.as_bytes();
        let data_bytes = data.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() < 7 || nonce_bytes.len() > 13 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be between 7 and 13 bytes"),
            ));
        }

        // Check this early so we know we can add tag_len without overflow
        // check_length requires that the length be 2 ** 31 - 1 or smaller.
        check_length(data_bytes)?;
        // For information about computing this, see
        // https://tools.ietf.org/html/rfc3610#section-2.1
        let l_val = 15 - nonce_bytes.len();
        let max_length = 1usize.checked_shl(8 * l_val as u32);
        // If `max_length` overflowed, then it's not possible for data to be
        // longer than it.
        if max_length.map(|v| v < data_bytes.len()).unwrap_or(false) {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Data too long for nonce"),
            ));
        }

        let expected_len = data_bytes.len() + self.tag_length;
        if buf.as_mut_bytes().len() != expected_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    expected_len
                )),
            ));
        }

        self.ctx
            .encrypt_into(py, data_bytes, aad, Some(nonce_bytes), buf.as_mut_bytes())?;
        buf.commit(py, expected_len)?;
        Ok(expected_len)
    }

    #[pyo3(signature = (nonce, data, associated_data))]
    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let nonce_bytes = nonce.as_bytes();
        let data_bytes = data.as_bytes();

        if nonce_bytes.len() < 7 || nonce_bytes.len() > 13 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be between 7 and 13 bytes"),
            ));
        }
        if data_bytes.len() < self.tag_length {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        Ok(pyo3::types::PyBytes::new_with(
            py,
            data_bytes.len() - self.tag_length,
            |b| {
                let buf = CffiMutBuf::from_bytes(py, b);
                self.decrypt_into(py, nonce, data, associated_data, buf)?;
                Ok(())
            },
        )?)
    }

    #[pyo3(signature = (nonce, data, associated_data, buf))]
    fn decrypt_into(
        &self,
        py: pyo3::Python<'_>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let nonce_bytes = nonce.as_bytes();
        let data_bytes = data.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() < 7 || nonce_bytes.len() > 13 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be between 7 and 13 bytes"),
            ));
        }

        if data_bytes.len() < self.tag_length {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        // For information about computing this, see
        // https://tools.ietf.org/html/rfc3610#section-2.1
        let l_val = 15 - nonce_bytes.len();
        let max_length = 1usize.checked_shl(8 * l_val as u32);
        // If `max_length` overflowed, then it's not possible for data to be
        // longer than it.
        let expected_len = data_bytes.len() - self.tag_length;
        if max_length.map(|v| v < expected_len).unwrap_or(false) {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Data too long for nonce"),
            ));
        }

        if buf.as_mut_bytes().len() != expected_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    expected_len
                )),
            ));
        }

        self.ctx
            .decrypt_into(py, data_bytes, aad, Some(nonce_bytes), buf.as_mut_bytes())?;

        buf.commit(py, expected_len)?;
        Ok(expected_len)
    }
}

// NO-COVERAGE-START
#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.aead",
    name = "AESSIV"
)]
// NO-COVERAGE-END
struct AesSiv {
    ctx: CheckedAead,
}

#[pyo3::pymethods]
impl AesSiv {
    #[new]
    fn new(py: pyo3::Python<'_>, key: pyo3::Py<pyo3::PyAny>) -> CryptographyResult<AesSiv> {
        let key_buf = key.extract::<CffiBuf<'_>>(py)?;
        let cipher_name = match key_buf.as_bytes().len() {
            32 => "aes-128-siv",
            48 => "aes-192-siv",
            64 => "aes-256-siv",
            _ => {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "AESSIV key must be 256, 384, or 512 bits.",
                    ),
                ))
            }
        };

        cfg_if::cfg_if! {
            if #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))] {
                if openssl_bridge::runtime::is_fips_enabled() {
                    return Err(CryptographyError::from(
                        exceptions::UnsupportedAlgorithm::new_err((
                            "AES-SIV is not supported by this version of OpenSSL",
                            exceptions::Reasons::UNSUPPORTED_CIPHER,
                        )),
                    ));
                }

                let cipher = openssl_bridge::aead::Algorithm::from_name(cipher_name)?;
                Ok(AesSiv {
                    ctx: CheckedAead::new(
                        py,
                        cipher,
                        key,
                        16,
                        true,
                    )?,
                })
            } else {
                _ = cipher_name;

                Err(CryptographyError::from(
                    exceptions::UnsupportedAlgorithm::new_err((
                        "AES-SIV is not supported by this version of OpenSSL",
                        exceptions::Reasons::UNSUPPORTED_CIPHER,
                    )),
                ))
            }
        }
    }

    #[staticmethod]
    fn generate_key(
        py: pyo3::Python<'_>,
        bit_length: usize,
    ) -> CryptographyResult<pyo3::Bound<'_, pyo3::types::PyBytes>> {
        if bit_length != 256 && bit_length != 384 && bit_length != 512 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("bit_length must be 256, 384, or 512"),
            ));
        }

        crate::backend::rand::get_rand_bytes(py, bit_length / 8)
    }

    #[pyo3(signature = (data, associated_data))]
    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        associated_data: Option<pyo3::Bound<'p, pyo3::types::PyList>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        check_length(data.as_bytes())?;
        Ok(pyo3::types::PyBytes::new_with(
            py,
            data.as_bytes().len() + self.ctx.tag_len,
            |b| {
                let buf = CffiMutBuf::from_bytes(py, b);
                self.encrypt_into(py, data, associated_data, buf)?;
                Ok(())
            },
        )?)
    }

    #[pyo3(signature = (data, associated_data, buf))]
    fn encrypt_into(
        &self,
        py: pyo3::Python<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        associated_data: Option<pyo3::Bound<'_, pyo3::types::PyList>>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let data_bytes = data.as_bytes();
        let aad = associated_data.map(Aad::List);

        #[cfg(not(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER))]
        if data_bytes.is_empty() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("data must not be zero length"),
            ));
        };

        // Check this early so we know we can add tag_len without overflow
        // check_length requires that the length be 2 ** 31 - 1 or smaller.
        check_length(data_bytes)?;
        let expected_len = data_bytes.len() + self.ctx.tag_len;
        if buf.as_mut_bytes().len() != expected_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    expected_len
                )),
            ));
        }

        self.ctx
            .encrypt_into(py, data_bytes, aad, None, buf.as_mut_bytes())?;

        buf.commit(py, expected_len)?;
        Ok(expected_len)
    }

    #[pyo3(signature = (data, associated_data))]
    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        associated_data: Option<pyo3::Bound<'_, pyo3::types::PyList>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if data.as_bytes().len() < self.ctx.tag_len {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }
        Ok(pyo3::types::PyBytes::new_with(
            py,
            data.as_bytes().len() - self.ctx.tag_len,
            |b| {
                let buf = CffiMutBuf::from_bytes(py, b);
                self.decrypt_into(py, data, associated_data, buf)?;
                Ok(())
            },
        )?)
    }

    #[pyo3(signature = (data, associated_data, buf))]
    fn decrypt_into(
        &self,
        py: pyo3::Python<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        associated_data: Option<pyo3::Bound<'_, pyo3::types::PyList>>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let data_bytes = data.as_bytes();
        let aad = associated_data.map(Aad::List);

        // We need to do this check early to prevent underflow when computing expected_len
        if data_bytes.len() < self.ctx.tag_len {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        let expected_len = data_bytes.len() - self.ctx.tag_len;
        if buf.as_mut_bytes().len() != expected_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    expected_len
                )),
            ));
        }

        self.ctx
            .decrypt_into(py, data_bytes, aad, None, buf.as_mut_bytes())?;

        buf.commit(py, expected_len)?;
        Ok(expected_len)
    }
}

// NO-COVERAGE-START
#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.aead",
    name = "AESOCB3"
)]
// NO-COVERAGE-END
struct AesOcb3 {
    ctx: CheckedAead,
}

#[pyo3::pymethods]
impl AesOcb3 {
    #[new]
    fn new(py: pyo3::Python<'_>, key: pyo3::Py<pyo3::PyAny>) -> CryptographyResult<AesOcb3> {
        let key_buf = key.extract::<CffiBuf<'_>>(py)?;
        cfg_if::cfg_if! {
            if #[cfg(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))] {
                _ = key_buf;
                _ = key;

                Err(CryptographyError::from(
                    exceptions::UnsupportedAlgorithm::new_err((
                        "AES-OCB3 is not supported by this version of OpenSSL",
                        exceptions::Reasons::UNSUPPORTED_CIPHER,
                    )),
                ))
            } else {
                if openssl_bridge::runtime::is_fips_enabled() {
                    return Err(CryptographyError::from(
                        exceptions::UnsupportedAlgorithm::new_err((
                            "AES-OCB3 is not supported by this version of OpenSSL",
                            exceptions::Reasons::UNSUPPORTED_CIPHER,
                        )),
                    ));
                }

                let cipher = match key_buf.as_bytes().len() {
                    16 => openssl_bridge::aead::Algorithm::Aes128Ocb,
                    24 => openssl_bridge::aead::Algorithm::Aes192Ocb,
                    32 => openssl_bridge::aead::Algorithm::Aes256Ocb,
                    _ => {
                        return Err(CryptographyError::from(
                            pyo3::exceptions::PyValueError::new_err(
                                "AESOCB3 key must be 128, 192, or 256 bits.",
                            ),
                        ))
                    }
                };

                Ok(AesOcb3 {
                    ctx: CheckedAead::new(
                        py,
                        cipher,
                        key,
                        16,
                        false,
                    )?,
                })
            }
        }
    }

    #[staticmethod]
    fn generate_key(
        py: pyo3::Python<'_>,
        bit_length: usize,
    ) -> CryptographyResult<pyo3::Bound<'_, pyo3::types::PyBytes>> {
        if bit_length != 128 && bit_length != 192 && bit_length != 256 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("bit_length must be 128, 192, or 256"),
            ));
        }

        crate::backend::rand::get_rand_bytes(py, bit_length / 8)
    }

    #[pyo3(signature = (nonce, data, associated_data))]
    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data_bytes = data.as_bytes();
        check_length(data_bytes)?;
        Ok(pyo3::types::PyBytes::new_with(
            py,
            data_bytes.len() + 16,
            |b| {
                let buf = CffiMutBuf::from_bytes(py, b);
                self.encrypt_into(py, nonce, data, associated_data, buf)?;
                Ok(())
            },
        )?)
    }

    #[pyo3(signature = (nonce, data, associated_data, buf))]
    fn encrypt_into(
        &self,
        py: pyo3::Python<'_>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let nonce_bytes = nonce.as_bytes();
        let data_bytes = data.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() < 12 || nonce_bytes.len() > 15 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be between 12 and 15 bytes"),
            ));
        }

        // Check this early so we know we can add tag_len without overflow
        // check_length requires that the length be 2 ** 31 - 1 or smaller.
        check_length(data_bytes)?;
        let expected_len = data_bytes.len() + 16;
        if buf.as_mut_bytes().len() != expected_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    expected_len
                )),
            ));
        }

        self.ctx
            .encrypt_into(py, data_bytes, aad, Some(nonce_bytes), buf.as_mut_bytes())?;
        buf.commit(py, expected_len)?;
        Ok(expected_len)
    }

    #[pyo3(signature = (nonce, data, associated_data))]
    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let nonce_bytes = nonce.as_bytes();
        let data_bytes = data.as_bytes();

        if nonce_bytes.len() < 12 || nonce_bytes.len() > 15 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be between 12 and 15 bytes"),
            ));
        }

        if data_bytes.len() < self.ctx.tag_len {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        Ok(pyo3::types::PyBytes::new_with(
            py,
            data_bytes.len() - self.ctx.tag_len,
            |b| {
                let buf = CffiMutBuf::from_bytes(py, b);
                self.decrypt_into(py, nonce, data, associated_data, buf)?;
                Ok(())
            },
        )?)
    }

    #[pyo3(signature = (nonce, data, associated_data, buf))]
    fn decrypt_into(
        &self,
        py: pyo3::Python<'_>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let nonce_bytes = nonce.as_bytes();
        let data_bytes = data.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() < 12 || nonce_bytes.len() > 15 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be between 12 and 15 bytes"),
            ));
        }

        if data_bytes.len() < self.ctx.tag_len {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        let expected_len = data_bytes.len() - self.ctx.tag_len;
        if buf.as_mut_bytes().len() != expected_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    expected_len
                )),
            ));
        }

        self.ctx
            .decrypt_into(py, data_bytes, aad, Some(nonce_bytes), buf.as_mut_bytes())?;

        buf.commit(py, expected_len)?;
        Ok(expected_len)
    }
}

// NO-COVERAGE-START
#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.aead",
    name = "AESGCMSIV"
)]
// NO-COVERAGE-END
struct AesGcmSiv {
    ctx: CheckedAead,
}

#[pyo3::pymethods]
impl AesGcmSiv {
    #[new]
    fn new(py: pyo3::Python<'_>, key: pyo3::Py<pyo3::PyAny>) -> CryptographyResult<AesGcmSiv> {
        let key_buf = key.extract::<CffiBuf<'_>>(py)?;
        let cipher_name = match key_buf.as_bytes().len() {
            16 => "aes-128-gcm-siv",
            24 => "aes-192-gcm-siv",
            32 => "aes-256-gcm-siv",
            _ => {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "AES-GCM-SIV key must be 128, 192 or 256 bits.",
                    ),
                ))
            }
        };

        cfg_if::cfg_if! {
            if #[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))] {
                let _ = cipher_name;
                let aead_type = match key_buf.as_bytes().len() {
                    16 => openssl_bridge::aead::Algorithm::Aes128GcmSiv,
                    32 => openssl_bridge::aead::Algorithm::Aes256GcmSiv,
                    _ => return Err(CryptographyError::from(
                        exceptions::UnsupportedAlgorithm::new_err((
                            "Only 128-bit and 256-bit keys are supported for AES-GCM-SIV with AWS-LC or BoringSSL",
                            exceptions::Reasons::UNSUPPORTED_CIPHER,
                        )),
                    ))
                };
                Ok(AesGcmSiv {
                    ctx: CheckedAead::from_bytes(aead_type, key_buf.as_bytes(), 16)?,
                })
            } else if #[cfg(not(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER))] {
                let _ = cipher_name;
                Err(CryptographyError::from(
                    exceptions::UnsupportedAlgorithm::new_err((
                        "AES-GCM-SIV is not supported by this version of OpenSSL",
                        exceptions::Reasons::UNSUPPORTED_CIPHER,
                    )),
                ))
            } else {
                if openssl_bridge::runtime::is_fips_enabled() {
                    return Err(CryptographyError::from(
                        exceptions::UnsupportedAlgorithm::new_err((
                            "AES-GCM-SIV is not supported by this version of OpenSSL",
                            exceptions::Reasons::UNSUPPORTED_CIPHER,
                        )),
                    ));
                }
                let cipher = openssl_bridge::aead::Algorithm::from_name(cipher_name)?;
                Ok(AesGcmSiv {
                    ctx: CheckedAead::new(
                        py,
                        cipher,
                        key,
                        16,
                        false,
                    )?,
                })
            }
        }
    }

    #[staticmethod]
    fn generate_key(
        py: pyo3::Python<'_>,
        bit_length: usize,
    ) -> CryptographyResult<pyo3::Bound<'_, pyo3::types::PyBytes>> {
        if bit_length != 128 && bit_length != 192 && bit_length != 256 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("bit_length must be 128, 192, or 256"),
            ));
        }

        crate::backend::rand::get_rand_bytes(py, bit_length / 8)
    }

    #[pyo3(signature = (nonce, data, associated_data))]
    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data_bytes = data.as_bytes();
        check_length(data_bytes)?;
        Ok(pyo3::types::PyBytes::new_with(
            py,
            data_bytes.len() + 16,
            |b| {
                let buf = CffiMutBuf::from_bytes(py, b);
                self.encrypt_into(py, nonce, data, associated_data, buf)?;
                Ok(())
            },
        )?)
    }

    #[pyo3(signature = (nonce, data, associated_data, buf))]
    fn encrypt_into(
        &self,
        py: pyo3::Python<'_>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let nonce_bytes = nonce.as_bytes();
        let data_bytes = data.as_bytes();
        let aad = associated_data.map(Aad::Single);

        #[cfg(not(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        if data_bytes.is_empty() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("data must not be zero length"),
            ));
        };
        if nonce_bytes.len() != 12 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be 12 bytes long"),
            ));
        }

        // Check this early so we know we can add tag_len without overflow
        // check_length requires that the length be 2 ** 31 - 1 or smaller.
        check_length(data_bytes)?;
        let expected_len = data_bytes.len() + 16;
        if buf.as_mut_bytes().len() != expected_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    expected_len
                )),
            ));
        }

        self.ctx
            .encrypt_into(py, data_bytes, aad, Some(nonce_bytes), buf.as_mut_bytes())?;
        buf.commit(py, expected_len)?;
        Ok(expected_len)
    }

    #[pyo3(signature = (nonce, data, associated_data))]
    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let nonce_bytes = nonce.as_bytes();
        let data_bytes = data.as_bytes();

        if nonce_bytes.len() != 12 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be 12 bytes long"),
            ));
        }

        if data_bytes.len() < self.ctx.tag_len {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        Ok(pyo3::types::PyBytes::new_with(
            py,
            data_bytes.len() - 16,
            |b| {
                let buf = CffiMutBuf::from_bytes(py, b);
                self.decrypt_into(py, nonce, data, associated_data, buf)?;
                Ok(())
            },
        )?)
    }

    #[pyo3(signature = (nonce, data, associated_data, buf))]
    fn decrypt_into(
        &self,
        py: pyo3::Python<'_>,
        nonce: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_aead_buffer)] data: CffiBuf<'_>,
        #[pyo3(from_py_with = crate::buf::extract_optional_aead_buffer)] associated_data: Option<
            CffiBuf<'_>,
        >,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        let nonce_bytes = nonce.as_bytes();
        let data_bytes = data.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() != 12 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be 12 bytes long"),
            ));
        }

        if data_bytes.len() < self.ctx.tag_len {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        let expected_len = data_bytes.len() - self.ctx.tag_len;
        if buf.as_mut_bytes().len() != expected_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    expected_len
                )),
            ));
        }

        self.ctx
            .decrypt_into(py, data_bytes, aad, Some(nonce_bytes), buf.as_mut_bytes())?;

        buf.commit(py, expected_len)?;
        Ok(expected_len)
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod aead {
    #[pymodule_export]
    use super::{AesCcm, AesGcm, AesGcmSiv, AesOcb3, AesSiv, ChaCha20Poly1305};
}
