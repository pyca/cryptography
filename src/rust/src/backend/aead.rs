// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types};

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
    List(&'a pyo3::types::PyList),
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
        &self,
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
        &self,
        ctx: &mut openssl::cipher_ctx::CipherCtx,
        data: &[u8],
        out: &mut [u8],
    ) -> CryptographyResult<()> {
        let bs = ctx.block_size();

        // For AEADs that operate as if they are streaming there's an easy
        // path. For AEADs that are more like block ciphers (notably, OCB),
        // this is a bit more complicated.
        if bs == 1 {
            let n = ctx.cipher_update(data, Some(out))?;
            assert_eq!(n, data.len());

            let mut final_block = [0];
            let n = ctx.cipher_final(&mut final_block)?;
            assert_eq!(n, 0);
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
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        check_length(plaintext)?;

        let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;
        ctx.copy(&self.base_encryption_ctx)?;
        if let Some(nonce) = nonce {
            ctx.set_iv_length(nonce.len())?;
        }
        ctx.encrypt_init(None, None, nonce)?;

        self.process_aad(&mut ctx, aad)?;

        Ok(pyo3::types::PyBytes::new_with(
            py,
            plaintext.len() + self.tag_len,
            |b| {
                let ciphertext;
                let tag;
                if self.tag_first {
                    (tag, ciphertext) = b.split_at_mut(self.tag_len);
                } else {
                    (ciphertext, tag) = b.split_at_mut(plaintext.len());
                }

                self.process_data(&mut ctx, plaintext, ciphertext)?;

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
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        if ciphertext.len() < self.tag_len {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;
        ctx.copy(&self.base_decryption_ctx)?;
        if let Some(nonce) = nonce {
            ctx.set_iv_length(nonce.len())?;
        }
        ctx.decrypt_init(None, None, nonce)?;

        let tag;
        let ciphertext_data;
        if self.tag_first {
            // RFC 5297 defines the output as IV || C, where the tag we generate
            // is the "IV" and C is the ciphertext. This is the opposite of our
            // other AEADs, which are Ciphertext || Tag.
            (tag, ciphertext_data) = ciphertext.split_at(self.tag_len);
        } else {
            (ciphertext_data, tag) = ciphertext.split_at(ciphertext.len() - self.tag_len);
        }
        ctx.set_tag(tag)?;

        self.process_aad(&mut ctx, aad)?;

        Ok(pyo3::types::PyBytes::new_with(
            py,
            ciphertext_data.len(),
            |b| {
                self.process_data(&mut ctx, ciphertext_data, b)
                    .map_err(|_| exceptions::InvalidTag::new_err(()))?;

                Ok(())
            },
        )?)
    }
}

#[pyo3::prelude::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.aead",
    name = "AESSIV"
)]
struct AesSiv {
    ctx: EvpCipherAead,
}

#[pyo3::prelude::pymethods]
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

        #[cfg(not(CRYPTOGRAPHY_OPENSSL_300_OR_GREATER))]
        {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "AES-SIV is not supported by this version of OpenSSL",
                    exceptions::Reasons::UNSUPPORTED_CIPHER,
                )),
            ));
        }
        #[cfg(CRYPTOGRAPHY_OPENSSL_300_OR_GREATER)]
        {
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
                ctx: EvpCipherAead::new(&cipher, key_buf.as_bytes(), 16, true)?,
            })
        }
    }

    #[staticmethod]
    fn generate_key(py: pyo3::Python<'_>, bit_length: usize) -> CryptographyResult<&pyo3::PyAny> {
        if bit_length != 256 && bit_length != 384 && bit_length != 512 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("bit_length must be 256, 384, or 512"),
            ));
        }

        Ok(types::OS_URANDOM.get(py)?.call1((bit_length / 8,))?)
    }

    #[pyo3(signature = (data, associated_data))]
    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        associated_data: Option<&pyo3::types::PyList>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let data_bytes = data.as_bytes();
        let aad = associated_data.map(Aad::List);

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
        associated_data: Option<&pyo3::types::PyList>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let aad = associated_data.map(Aad::List);
        self.ctx.decrypt(py, data.as_bytes(), aad, None)
    }
}

#[pyo3::prelude::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.aead",
    name = "AESOCB3"
)]
struct AesOcb3 {
    ctx: EvpCipherAead,
}

#[pyo3::prelude::pymethods]
impl AesOcb3 {
    #[new]
    fn new(py: pyo3::Python<'_>, key: pyo3::Py<pyo3::PyAny>) -> CryptographyResult<AesOcb3> {
        let key_buf = key.extract::<CffiBuf<'_>>(py)?;

        cfg_if::cfg_if! {
            if #[cfg(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL))] {
                return Err(CryptographyError::from(
                    exceptions::UnsupportedAlgorithm::new_err((
                        "AES-OCB3 is not supported by this version of OpenSSL",
                        exceptions::Reasons::UNSUPPORTED_CIPHER,
                    )),
                ));
            } else {
                if cryptography_openssl::fips::is_enabled() {
                    return Err(CryptographyError::from(
                        exceptions::UnsupportedAlgorithm::new_err((
                            "AES-OCB3 is not supported by this version of OpenSSL",
                            exceptions::Reasons::UNSUPPORTED_CIPHER,
                        )),
                    ));
                }

                let cipher = match key_buf.as_bytes().len() {
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
                    ctx: EvpCipherAead::new(cipher, key_buf.as_bytes(), 16, false)?,
                })
            }
        }
    }

    #[staticmethod]
    fn generate_key(py: pyo3::Python<'_>, bit_length: usize) -> CryptographyResult<&pyo3::PyAny> {
        if bit_length != 128 && bit_length != 192 && bit_length != 256 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("bit_length must be 128, 192, or 256"),
            ));
        }

        Ok(types::OS_URANDOM.get(py)?.call1((bit_length / 8,))?)
    }

    #[pyo3(signature = (nonce, data, associated_data))]
    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        nonce: CffiBuf<'_>,
        data: CffiBuf<'_>,
        associated_data: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
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
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
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

pub(crate) fn create_module(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let m = pyo3::prelude::PyModule::new(py, "aead")?;

    m.add_class::<AesSiv>()?;
    m.add_class::<AesOcb3>()?;

    Ok(m)
}
