// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::{PyAnyMethods, PyListMethods};

use crate::buf::CffiBuf;
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

enum Aad<'a> {
    Single(CffiBuf<'a>),
    List(pyo3::Bound<'a, pyo3::types::PyList>),
}

struct EvpCipherAead {
    base_encryption_ctx: openssl::cipher_ctx::CipherCtx,
    base_decryption_ctx: openssl::cipher_ctx::CipherCtx,
    tag_len: usize,
    tag_first: bool,
}

impl EvpCipherAead {
    fn new(
        cipher: &openssl::cipher::CipherRef,
        key: &[u8],
        tag_len: usize,
        tag_first: bool,
    ) -> CryptographyResult<EvpCipherAead> {
        let mut base_encryption_ctx = openssl::cipher_ctx::CipherCtx::new()?;
        base_encryption_ctx.encrypt_init(Some(cipher), Some(key), None)?;
        let mut base_decryption_ctx = openssl::cipher_ctx::CipherCtx::new()?;
        base_decryption_ctx.decrypt_init(Some(cipher), Some(key), None)?;

        Ok(EvpCipherAead {
            base_encryption_ctx,
            base_decryption_ctx,
            tag_len,
            tag_first,
        })
    }

    fn process_aad(
        ctx: &mut openssl::cipher_ctx::CipherCtx,
        aad: Option<Aad<'_>>,
    ) -> CryptographyResult<()> {
        match aad {
            Some(Aad::Single(ad)) => {
                check_length(ad.as_bytes())?;
                ctx.cipher_update(ad.as_bytes(), None)?;
            }
            Some(Aad::List(ads)) => {
                for ad in ads.iter() {
                    let ad = ad.extract::<CffiBuf<'_>>()?;
                    check_length(ad.as_bytes())?;
                    ctx.cipher_update(ad.as_bytes(), None)?;
                }
            }
            None => {}
        }

        Ok(())
    }

    fn process_data(
        ctx: &mut openssl::cipher_ctx::CipherCtx,
        data: &[u8],
        out: &mut [u8],
        is_ccm: bool,
    ) -> CryptographyResult<()> {
        let bs = ctx.block_size();

        // For AEADs that operate as if they are streaming there's an easy
        // path. For AEADs that are more like block ciphers (notably, OCB),
        // this is a bit more complicated.
        if bs == 1 {
            let n = ctx.cipher_update(data, Some(out))?;
            assert_eq!(n, data.len());

            if !is_ccm {
                let mut final_block = [0];
                let n = ctx.cipher_final(&mut final_block)?;
                assert_eq!(n, 0);
            }
        } else {
            // Our algorithm here is: split the data into the full chunks, and
            // the remaining partial chunk. Feed the full chunks into OpenSSL
            // and let it write the results to `out`. Then feed the trailer
            // in, allowing it to write the results to a buffer on the
            // stack -- this never writes anything. Finally, finalize the AEAD
            // and let it write the results to the stack buffer, then copy
            // from the stack buffer over to `out`. The indirection via the
            // stack buffer is required because OpenSSL uses it as scratch
            // space, and `out` wouldn't be long enough.
            let (initial, trailer) = data.split_at((data.len() / bs) * bs);

            let n =
                // SAFETY: `initial.len()` is a precise multiple of the block
                // size, which means the space required in the output is
                // exactly `initial.len()`.
                unsafe { ctx.cipher_update_unchecked(initial, Some(&mut out[..initial.len()]))? };
            assert_eq!(n, initial.len());

            assert!(bs <= 16);
            let mut buf = [0; 32];
            let n = ctx.cipher_update(trailer, Some(&mut buf))?;
            assert_eq!(n, 0);

            let n = ctx.cipher_final(&mut buf)?;
            assert_eq!(n, trailer.len());
            out[initial.len()..].copy_from_slice(&buf[..n]);
        }

        Ok(())
    }

    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        plaintext: &[u8],
        aad: Option<Aad<'_>>,
        nonce: Option<&[u8]>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;
        ctx.copy(&self.base_encryption_ctx)?;
        Self::encrypt_with_context(
            py,
            ctx,
            plaintext,
            aad,
            nonce,
            self.tag_len,
            self.tag_first,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn encrypt_with_context<'p>(
        py: pyo3::Python<'p>,
        mut ctx: openssl::cipher_ctx::CipherCtx,
        plaintext: &[u8],
        aad: Option<Aad<'_>>,
        nonce: Option<&[u8]>,
        tag_len: usize,
        tag_first: bool,
        is_ccm: bool,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        check_length(plaintext)?;

        if !is_ccm {
            if let Some(nonce) = nonce {
                ctx.set_iv_length(nonce.len())?;
            }
            ctx.encrypt_init(None, None, nonce)?;
        }
        if is_ccm {
            ctx.set_data_len(plaintext.len())?;
        }

        Self::process_aad(&mut ctx, aad)?;

        Ok(pyo3::types::PyBytes::new_with(
            py,
            plaintext.len() + tag_len,
            |b| {
                let ciphertext;
                let tag;
                if tag_first {
                    (tag, ciphertext) = b.split_at_mut(tag_len);
                } else {
                    (ciphertext, tag) = b.split_at_mut(plaintext.len());
                }

                Self::process_data(&mut ctx, plaintext, ciphertext, is_ccm)?;

                ctx.tag(tag).map_err(CryptographyError::from)?;

                Ok(())
            },
        )?)
    }

    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: &[u8],
        aad: Option<Aad<'_>>,
        nonce: Option<&[u8]>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;
        ctx.copy(&self.base_decryption_ctx)?;
        Self::decrypt_with_context(
            py,
            ctx,
            ciphertext,
            aad,
            nonce,
            self.tag_len,
            self.tag_first,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn decrypt_with_context<'p>(
        py: pyo3::Python<'p>,
        mut ctx: openssl::cipher_ctx::CipherCtx,
        ciphertext: &[u8],
        aad: Option<Aad<'_>>,
        nonce: Option<&[u8]>,
        tag_len: usize,
        tag_first: bool,
        is_ccm: bool,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if ciphertext.len() < tag_len {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        let tag;
        let ciphertext_data;
        if tag_first {
            // RFC 5297 defines the output as IV || C, where the tag we generate
            // is the "IV" and C is the ciphertext. This is the opposite of our
            // other AEADs, which are Ciphertext || Tag.
            (tag, ciphertext_data) = ciphertext.split_at(tag_len);
        } else {
            (ciphertext_data, tag) = ciphertext.split_at(ciphertext.len() - tag_len);
        }

        if !is_ccm {
            if let Some(nonce) = nonce {
                ctx.set_iv_length(nonce.len())?;
            }

            ctx.decrypt_init(None, None, nonce)?;
            ctx.set_tag(tag)?;
        }
        if is_ccm {
            ctx.set_data_len(ciphertext_data.len())?;
        }

        Self::process_aad(&mut ctx, aad)?;

        Ok(pyo3::types::PyBytes::new_with(
            py,
            ciphertext_data.len(),
            |b| {
                Self::process_data(&mut ctx, ciphertext_data, b, is_ccm)
                    .map_err(|_| exceptions::InvalidTag::new_err(()))?;

                Ok(())
            },
        )?)
    }
}

struct LazyEvpCipherAead {
    cipher: &'static openssl::cipher::CipherRef,
    key: pyo3::Py<pyo3::PyAny>,

    tag_len: usize,
    tag_first: bool,
    is_ccm: bool,
}

impl LazyEvpCipherAead {
    #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
    fn new(
        cipher: &'static openssl::cipher::CipherRef,
        key: pyo3::Py<pyo3::PyAny>,
        tag_len: usize,
        tag_first: bool,
        is_ccm: bool,
    ) -> LazyEvpCipherAead {
        LazyEvpCipherAead {
            cipher,
            key,
            tag_len,
            tag_first,
            is_ccm,
        }
    }

    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        plaintext: &[u8],
        aad: Option<Aad<'_>>,
        nonce: Option<&[u8]>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let key_buf = self.key.bind(py).extract::<CffiBuf<'_>>()?;

        let mut encryption_ctx = openssl::cipher_ctx::CipherCtx::new()?;
        if self.is_ccm {
            encryption_ctx.encrypt_init(Some(self.cipher), None, None)?;
            encryption_ctx.set_iv_length(nonce.as_ref().unwrap().len())?;
            encryption_ctx.set_tag_length(self.tag_len)?;
            encryption_ctx.encrypt_init(None, Some(key_buf.as_bytes()), nonce)?;
        } else {
            encryption_ctx.encrypt_init(Some(self.cipher), Some(key_buf.as_bytes()), None)?;
        }

        EvpCipherAead::encrypt_with_context(
            py,
            encryption_ctx,
            plaintext,
            aad,
            nonce,
            self.tag_len,
            self.tag_first,
            self.is_ccm,
        )
    }

    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: &[u8],
        aad: Option<Aad<'_>>,
        nonce: Option<&[u8]>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let key_buf = self.key.bind(py).extract::<CffiBuf<'_>>()?;

        let mut decryption_ctx = openssl::cipher_ctx::CipherCtx::new()?;
        if self.is_ccm {
            decryption_ctx.decrypt_init(Some(self.cipher), None, None)?;
            decryption_ctx.set_iv_length(nonce.as_ref().unwrap().len())?;

            if ciphertext.len() < self.tag_len {
                return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
            }

            let (_, tag) = ciphertext.split_at(ciphertext.len() - self.tag_len);
            decryption_ctx.set_tag(tag)?;

            decryption_ctx.decrypt_init(None, Some(key_buf.as_bytes()), nonce)?;
        } else {
            decryption_ctx.decrypt_init(Some(self.cipher), Some(key_buf.as_bytes()), None)?;
        }

        EvpCipherAead::decrypt_with_context(
            py,
            decryption_ctx,
            ciphertext,
            aad,
            nonce,
            self.tag_len,
            self.tag_first,
            self.is_ccm,
        )
    }
}

#[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))]
struct EvpAead {
    ctx: cryptography_openssl::aead::AeadCtx,
    tag_len: usize,
}

#[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))]
impl EvpAead {
    fn new(
        algorithm: cryptography_openssl::aead::AeadType,
        key: &[u8],
        tag_len: usize,
    ) -> CryptographyResult<EvpAead> {
        Ok(EvpAead {
            ctx: cryptography_openssl::aead::AeadCtx::new(algorithm, key)?,
            tag_len,
        })
    }

    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        plaintext: &[u8],
        aad: Option<Aad<'_>>,
        nonce: Option<&[u8]>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        check_length(plaintext)?;

        let ad = if let Some(Aad::Single(ad)) = &aad {
            check_length(ad.as_bytes())?;
            ad.as_bytes()
        } else {
            assert!(aad.is_none());
            b""
        };
        Ok(pyo3::types::PyBytes::new_with(
            py,
            plaintext.len() + self.tag_len,
            |b| {
                self.ctx
                    .encrypt(plaintext, nonce.unwrap_or(b""), ad, b)
                    .map_err(CryptographyError::from)?;
                Ok(())
            },
        )?)
    }

    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: &[u8],
        aad: Option<Aad<'_>>,
        nonce: Option<&[u8]>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if ciphertext.len() < self.tag_len {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        let ad = if let Some(Aad::Single(ad)) = &aad {
            check_length(ad.as_bytes())?;
            ad.as_bytes()
        } else {
            assert!(aad.is_none());
            b""
        };

        Ok(pyo3::types::PyBytes::new_with(
            py,
            ciphertext.len() - self.tag_len,
            |b| {
                self.ctx
                    .decrypt(ciphertext, nonce.unwrap_or(b""), ad, b)
                    .map_err(|_| exceptions::InvalidTag::new_err(()))?;

                Ok(())
            },
        )?)
    }
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.aead")]
struct ChaCha20Poly1305 {
    #[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))]
    ctx: EvpAead,
    #[cfg(any(
        CRYPTOGRAPHY_OPENSSL_320_OR_GREATER,
        CRYPTOGRAPHY_IS_LIBRESSL,
        not(any(
            CRYPTOGRAPHY_OPENSSL_300_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))
    ))]
    ctx: EvpCipherAead,
    #[cfg(not(any(
        CRYPTOGRAPHY_IS_LIBRESSL,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC,
        not(CRYPTOGRAPHY_OPENSSL_300_OR_GREATER),
        CRYPTOGRAPHY_OPENSSL_320_OR_GREATER
    )))]
    ctx: LazyEvpCipherAead,
}

#[pyo3::pymethods]
impl ChaCha20Poly1305 {
    #[new]
    fn new(py: pyo3::Python<'_>, key: pyo3::Py<pyo3::PyAny>) -> CryptographyResult<Self> {
        let key_buf = key.extract::<CffiBuf<'_>>(py)?;
        if key_buf.as_bytes().len() != 32 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("ChaCha20Poly1305 key must be 32 bytes."),
            ));
        }
        if cryptography_openssl::fips::is_enabled() {
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
                    ctx: EvpAead::new(
                        cryptography_openssl::aead::AeadType::ChaCha20Poly1305,
                        key_buf.as_bytes(),
                        16,
                    )?,
                })
            } else if #[cfg(any(
                CRYPTOGRAPHY_IS_LIBRESSL,
                CRYPTOGRAPHY_OPENSSL_320_OR_GREATER,
                not(CRYPTOGRAPHY_OPENSSL_300_OR_GREATER),
            ))] {
                Ok(ChaCha20Poly1305 {
                    ctx: EvpCipherAead::new(
                        openssl::cipher::Cipher::chacha20_poly1305(),
                        key_buf.as_bytes(),
                        16,
                        false,
                    )?,
                })
            } else {
                Ok(ChaCha20Poly1305{
                    ctx: LazyEvpCipherAead::new(
                        openssl::cipher::Cipher::chacha20_poly1305(),
                        key,
                        16,
                        false,
                        false,
                    )
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
    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        data: CffiBuf<'_>,
        associated_data: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let nonce_bytes = nonce.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() != 12 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be 12 bytes"),
            ));
        }

        self.ctx
            .encrypt(py, data.as_bytes(), aad, Some(nonce_bytes))
    }

    #[pyo3(signature = (nonce, data, associated_data))]
    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        data: CffiBuf<'_>,
        associated_data: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let nonce_bytes = nonce.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() != 12 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be 12 bytes"),
            ));
        }

        self.ctx
            .decrypt(py, data.as_bytes(), aad, Some(nonce_bytes))
    }
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.aead",
    name = "AESGCM"
)]
struct AesGcm {
    #[cfg(any(
        CRYPTOGRAPHY_OPENSSL_320_OR_GREATER,
        CRYPTOGRAPHY_IS_LIBRESSL,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC,
        not(CRYPTOGRAPHY_OPENSSL_300_OR_GREATER),
    ))]
    ctx: EvpCipherAead,

    #[cfg(not(any(
        CRYPTOGRAPHY_OPENSSL_320_OR_GREATER,
        CRYPTOGRAPHY_IS_LIBRESSL,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC,
        not(CRYPTOGRAPHY_OPENSSL_300_OR_GREATER),
    )))]
    ctx: LazyEvpCipherAead,
}

#[pyo3::pymethods]
impl AesGcm {
    #[new]
    fn new(py: pyo3::Python<'_>, key: pyo3::Py<pyo3::PyAny>) -> CryptographyResult<AesGcm> {
        let key_buf = key.extract::<CffiBuf<'_>>(py)?;
        let cipher = match key_buf.as_bytes().len() {
            16 => openssl::cipher::Cipher::aes_128_gcm(),
            24 => openssl::cipher::Cipher::aes_192_gcm(),
            32 => openssl::cipher::Cipher::aes_256_gcm(),
            _ => {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "AESGCM key must be 128, 192, or 256 bits.",
                    ),
                ))
            }
        };

        cfg_if::cfg_if! {
            if #[cfg(any(
                CRYPTOGRAPHY_OPENSSL_320_OR_GREATER,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_LIBRESSL,
                CRYPTOGRAPHY_IS_AWSLC,
                not(CRYPTOGRAPHY_OPENSSL_300_OR_GREATER),
            ))] {
                Ok(AesGcm {
                    ctx: EvpCipherAead::new(cipher, key_buf.as_bytes(), 16, false)?,
                })
            } else {
                Ok(AesGcm {
                    ctx: LazyEvpCipherAead::new(cipher, key, 16, false, false),
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
        data: CffiBuf<'_>,
        associated_data: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let nonce_bytes = nonce.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() < 8 || nonce_bytes.len() > 128 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be between 8 and 128 bytes"),
            ));
        }

        self.ctx
            .encrypt(py, data.as_bytes(), aad, Some(nonce_bytes))
    }

    #[pyo3(signature = (nonce, data, associated_data))]
    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        data: CffiBuf<'_>,
        associated_data: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let nonce_bytes = nonce.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() < 8 || nonce_bytes.len() > 128 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be between 8 and 128 bytes"),
            ));
        }

        self.ctx
            .decrypt(py, data.as_bytes(), aad, Some(nonce_bytes))
    }
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.aead",
    name = "AESCCM"
)]
struct AesCcm {
    ctx: LazyEvpCipherAead,
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
                    16 => openssl::cipher::Cipher::aes_128_ccm(),
                    24 => openssl::cipher::Cipher::aes_192_ccm(),
                    32 => openssl::cipher::Cipher::aes_256_ccm(),
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
                    ctx: LazyEvpCipherAead::new(cipher, key, tag_length, false, true),
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
        data: CffiBuf<'_>,
        associated_data: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let nonce_bytes = nonce.as_bytes();
        let data_bytes = data.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() < 7 || nonce_bytes.len() > 13 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be between 7 and 13 bytes"),
            ));
        }

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

        self.ctx.encrypt(py, data_bytes, aad, Some(nonce_bytes))
    }

    #[pyo3(signature = (nonce, data, associated_data))]
    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        data: CffiBuf<'_>,
        associated_data: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let nonce_bytes = nonce.as_bytes();
        let data_bytes = data.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() < 7 || nonce_bytes.len() > 13 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be between 7 and 13 bytes"),
            ));
        }
        // For information about computing this, see
        // https://tools.ietf.org/html/rfc3610#section-2.1
        let l_val = 15 - nonce_bytes.len();
        let max_length = 1usize.checked_shl(8 * l_val as u32);
        // If `max_length` overflowed, then it's not possible for data to be
        // longer than it.
        let pt_length = data_bytes.len().saturating_sub(self.tag_length);
        if max_length.map(|v| v < pt_length).unwrap_or(false) {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Data too long for nonce"),
            ));
        }

        self.ctx.decrypt(py, data_bytes, aad, Some(nonce_bytes))
    }
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.aead",
    name = "AESSIV"
)]
struct AesSiv {
    ctx: EvpCipherAead,
}

#[pyo3::pymethods]
impl AesSiv {
    #[new]
    fn new(key: CffiBuf<'_>) -> CryptographyResult<AesSiv> {
        let cipher_name = match key.as_bytes().len() {
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
            if #[cfg(CRYPTOGRAPHY_OPENSSL_300_OR_GREATER)] {
                if cryptography_openssl::fips::is_enabled() {
                    return Err(CryptographyError::from(
                        exceptions::UnsupportedAlgorithm::new_err((
                            "AES-SIV is not supported by this version of OpenSSL",
                            exceptions::Reasons::UNSUPPORTED_CIPHER,
                        )),
                    ));
                }

                let cipher = openssl::cipher::Cipher::fetch(None, cipher_name, None)?;
                Ok(AesSiv {
                    ctx: EvpCipherAead::new(&cipher, key.as_bytes(), 16, true)?,
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
        data: CffiBuf<'_>,
        associated_data: Option<pyo3::Bound<'p, pyo3::types::PyList>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data_bytes = data.as_bytes();
        let aad = associated_data.map(Aad::List);

        #[cfg(not(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER))]
        if data_bytes.is_empty() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("data must not be zero length"),
            ));
        };
        self.ctx.encrypt(py, data_bytes, aad, None)
    }

    #[pyo3(signature = (data, associated_data))]
    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        associated_data: Option<pyo3::Bound<'_, pyo3::types::PyList>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let aad = associated_data.map(Aad::List);
        self.ctx.decrypt(py, data.as_bytes(), aad, None)
    }
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.aead",
    name = "AESOCB3"
)]
struct AesOcb3 {
    ctx: EvpCipherAead,
}

#[pyo3::pymethods]
impl AesOcb3 {
    #[new]
    fn new(key: CffiBuf<'_>) -> CryptographyResult<AesOcb3> {
        cfg_if::cfg_if! {
            if #[cfg(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))] {
                _ = key;

                Err(CryptographyError::from(
                    exceptions::UnsupportedAlgorithm::new_err((
                        "AES-OCB3 is not supported by this version of OpenSSL",
                        exceptions::Reasons::UNSUPPORTED_CIPHER,
                    )),
                ))
            } else {
                if cryptography_openssl::fips::is_enabled() {
                    return Err(CryptographyError::from(
                        exceptions::UnsupportedAlgorithm::new_err((
                            "AES-OCB3 is not supported by this version of OpenSSL",
                            exceptions::Reasons::UNSUPPORTED_CIPHER,
                        )),
                    ));
                }

                let cipher = match key.as_bytes().len() {
                    16 => openssl::cipher::Cipher::aes_128_ocb(),
                    24 => openssl::cipher::Cipher::aes_192_ocb(),
                    32 => openssl::cipher::Cipher::aes_256_ocb(),
                    _ => {
                        return Err(CryptographyError::from(
                            pyo3::exceptions::PyValueError::new_err(
                                "AESOCB3 key must be 128, 192, or 256 bits.",
                            ),
                        ))
                    }
                };

                Ok(AesOcb3 {
                    ctx: EvpCipherAead::new(cipher, key.as_bytes(), 16, false)?,
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
        data: CffiBuf<'_>,
        associated_data: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let nonce_bytes = nonce.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() < 12 || nonce_bytes.len() > 15 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be between 12 and 15 bytes"),
            ));
        }

        self.ctx
            .encrypt(py, data.as_bytes(), aad, Some(nonce_bytes))
    }

    #[pyo3(signature = (nonce, data, associated_data))]
    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        data: CffiBuf<'_>,
        associated_data: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let nonce_bytes = nonce.as_bytes();
        let aad = associated_data.map(Aad::Single);

        if nonce_bytes.len() < 12 || nonce_bytes.len() > 15 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be between 12 and 15 bytes"),
            ));
        }

        self.ctx
            .decrypt(py, data.as_bytes(), aad, Some(nonce_bytes))
    }
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.aead",
    name = "AESGCMSIV"
)]
struct AesGcmSiv {
    #[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))]
    ctx: EvpAead,
    #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
    ctx: EvpCipherAead,
}

#[pyo3::pymethods]
impl AesGcmSiv {
    #[new]
    fn new(key: CffiBuf<'_>) -> CryptographyResult<AesGcmSiv> {
        let cipher_name = match key.as_bytes().len() {
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
                let aead_type = match key.as_bytes().len() {
                    16 => cryptography_openssl::aead::AeadType::Aes128GcmSiv,
                    32 => cryptography_openssl::aead::AeadType::Aes256GcmSiv,
                    _ => return Err(CryptographyError::from(
                        exceptions::UnsupportedAlgorithm::new_err((
                            "Only 128-bit and 256-bit keys are supported for AES-GCM-SIV with AWS-LC or BoringSSL",
                            exceptions::Reasons::UNSUPPORTED_CIPHER,
                        )),
                    ))
                };
                Ok(AesGcmSiv {
                    ctx: EvpAead::new(aead_type, key.as_bytes(), 16)?,
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
                if cryptography_openssl::fips::is_enabled() {
                    return Err(CryptographyError::from(
                        exceptions::UnsupportedAlgorithm::new_err((
                            "AES-GCM-SIV is not supported by this version of OpenSSL",
                            exceptions::Reasons::UNSUPPORTED_CIPHER,
                        )),
                    ));
                }
                let cipher = openssl::cipher::Cipher::fetch(None, cipher_name, None)?;
                Ok(AesGcmSiv {
                    ctx: EvpCipherAead::new(&cipher, key.as_bytes(), 16, false)?,
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
        data: CffiBuf<'_>,
        associated_data: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
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
        self.ctx.encrypt(py, data_bytes, aad, Some(nonce_bytes))
    }

    #[pyo3(signature = (nonce, data, associated_data))]
    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        data: CffiBuf<'_>,
        associated_data: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let nonce_bytes = nonce.as_bytes();
        let aad = associated_data.map(Aad::Single);
        if nonce_bytes.len() != 12 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Nonce must be 12 bytes long"),
            ));
        }
        self.ctx
            .decrypt(py, data.as_bytes(), aad, Some(nonce_bytes))
    }
}

#[pyo3::pymodule]
pub(crate) mod aead {
    #[pymodule_export]
    use super::{AesCcm, AesGcm, AesGcmSiv, AesOcb3, AesSiv, ChaCha20Poly1305};
}
