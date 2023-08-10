// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

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

fn encrypt_value<'p>(
    py: pyo3::Python<'p>,
    mut ctx: openssl::cipher_ctx::CipherCtx,
    plaintext: &[u8],
    tag_len: usize,
    tag_first: bool,
) -> CryptographyResult<&'p pyo3::types::PyBytes> {
    Ok(pyo3::types::PyBytes::new_with(
        py,
        plaintext.len() + tag_len,
        |b| {
            let ciphertext;
            let tag;
            // TODO: remove once we have a second AEAD implemented here.
            assert!(tag_first);
            (tag, ciphertext) = b.split_at_mut(tag_len);

            let n = ctx
                .cipher_update(plaintext, Some(ciphertext))
                .map_err(CryptographyError::from)?;
            assert_eq!(n, ciphertext.len());

            let mut final_block = [0];
            let n = ctx
                .cipher_final(&mut final_block)
                .map_err(CryptographyError::from)?;
            assert_eq!(n, 0);

            ctx.tag(tag).map_err(CryptographyError::from)?;

            Ok(())
        },
    )?)
}

fn decrypt_value<'p>(
    py: pyo3::Python<'p>,
    mut ctx: openssl::cipher_ctx::CipherCtx,
    ciphertext: &[u8],
) -> CryptographyResult<&'p pyo3::types::PyBytes> {
    Ok(pyo3::types::PyBytes::new_with(py, ciphertext.len(), |b| {
        // AES SIV can error here if the data is invalid on decrypt
        let n = ctx
            .cipher_update(ciphertext, Some(b))
            .map_err(|_| exceptions::InvalidTag::new_err(()))?;
        assert_eq!(n, b.len());

        let mut final_block = [0];
        let n = ctx
            .cipher_final(&mut final_block)
            .map_err(|_| exceptions::InvalidTag::new_err(()))?;
        assert_eq!(n, 0);

        Ok(())
    })?)
}

#[pyo3::prelude::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.aead",
    name = "AESSIV"
)]
struct AesSiv {
    key: pyo3::Py<pyo3::PyAny>,
    cipher: openssl::cipher::Cipher,
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
            Ok(AesSiv { key, cipher })
        }
    }

    #[staticmethod]
    fn generate_key(py: pyo3::Python<'_>, bit_length: usize) -> CryptographyResult<&pyo3::PyAny> {
        if bit_length != 256 && bit_length != 384 && bit_length != 512 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("bit_length must be 256, 384, or 512"),
            ));
        }

        Ok(py
            .import(pyo3::intern!(py, "os"))?
            .call_method1(pyo3::intern!(py, "urandom"), (bit_length / 8,))?)
    }

    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        associated_data: Option<&pyo3::types::PyList>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let key_buf = self.key.extract::<CffiBuf<'_>>(py)?;
        let data_bytes = data.as_bytes();

        if data_bytes.is_empty() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("data must not be zero length"),
            ));
        };
        check_length(data_bytes)?;

        let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;
        ctx.encrypt_init(Some(&self.cipher), Some(key_buf.as_bytes()), None)?;

        if let Some(ads) = associated_data {
            for ad in ads.iter() {
                let ad = ad.extract::<CffiBuf<'_>>()?;
                check_length(ad.as_bytes())?;
                ctx.cipher_update(ad.as_bytes(), None)?;
            }
        }

        encrypt_value(py, ctx, data_bytes, 16, true)
    }

    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        associated_data: Option<&pyo3::types::PyList>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let key_buf = self.key.extract::<CffiBuf<'_>>(py)?;
        let data_bytes = data.as_bytes();

        if data_bytes.is_empty() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("data must not be zero length"),
            ));
        }

        let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;
        ctx.decrypt_init(Some(&self.cipher), Some(key_buf.as_bytes()), None)?;

        if data_bytes.len() < 16 {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }
        // RFC 5297 defines the output as IV || C, where the tag we generate
        // is the "IV" and C is the ciphertext. This is the opposite of our
        // other AEADs, which are Ciphertext || Tag.
        let (tag, ciphertext) = data_bytes.split_at(16);
        ctx.set_tag(tag)?;

        if let Some(ads) = associated_data {
            for ad in ads.iter() {
                let ad = ad.extract::<CffiBuf<'_>>()?;
                check_length(ad.as_bytes())?;

                ctx.cipher_update(ad.as_bytes(), None)?;
            }
        }

        decrypt_value(py, ctx, ciphertext)
    }
}

pub(crate) fn create_module(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let m = pyo3::prelude::PyModule::new(py, "aead")?;

    m.add_class::<AesSiv>()?;

    Ok(m)
}
