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
    List(&'a pyo3::types::PyList),
}

struct EvpCipherAead {
    base_ctx: openssl::cipher_ctx::CipherCtx,
    tag_len: usize,
    tag_first: bool,
}

impl EvpCipherAead {
    fn new(
        base_ctx: openssl::cipher_ctx::CipherCtx,
        tag_len: usize,
        tag_first: bool,
    ) -> EvpCipherAead {
        EvpCipherAead {
            base_ctx,
            tag_len,
            tag_first,
        }
    }

    fn process_aad(
        &self,
        ctx: &mut openssl::cipher_ctx::CipherCtx,
        aad: Option<Aad<'_>>,
    ) -> CryptographyResult<()> {
        if let Some(Aad::List(ads)) = aad {
            for ad in ads.iter() {
                let ad = ad.extract::<CffiBuf<'_>>()?;
                check_length(ad.as_bytes())?;
                ctx.cipher_update(ad.as_bytes(), None)?;
            }
        }

        Ok(())
    }

    fn process_data(
        &self,
        ctx: &mut openssl::cipher_ctx::CipherCtx,
        data: &[u8],
        out: &mut [u8],
    ) -> CryptographyResult<()> {
        let n = ctx
            .cipher_update(data, Some(out))
            .map_err(CryptographyError::from)?;
        assert_eq!(n, data.len());

        let mut final_block = [0];
        let n = ctx
            .cipher_final(&mut final_block)
            .map_err(CryptographyError::from)?;
        assert_eq!(n, 0);

        Ok(())
    }

    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        plaintext: &[u8],
        aad: Option<Aad<'_>>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        check_length(plaintext)?;

        let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;
        ctx.copy(&self.base_ctx)?;
        ctx.encrypt_init(None, None, None)?;

        self.process_aad(&mut ctx, aad)?;

        Ok(pyo3::types::PyBytes::new_with(
            py,
            plaintext.len() + self.tag_len,
            |b| {
                let ciphertext;
                let tag;
                // TODO: remove once we have a second AEAD implemented here.
                assert!(self.tag_first);
                (tag, ciphertext) = b.split_at_mut(self.tag_len);

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
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        if ciphertext.len() < self.tag_len {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }

        let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;
        ctx.copy(&self.base_ctx)?;
        ctx.decrypt_init(None, None, None)?;

        assert!(self.tag_first);
        // RFC 5297 defines the output as IV || C, where the tag we generate
        // is the "IV" and C is the ciphertext. This is the opposite of our
        // other AEADs, which are Ciphertext || Tag.
        let (tag, ciphertext) = ciphertext.split_at(self.tag_len);
        ctx.set_tag(tag)?;

        self.process_aad(&mut ctx, aad)?;

        Ok(pyo3::types::PyBytes::new_with(py, ciphertext.len(), |b| {
            // AES SIV can error here if the data is invalid on decrypt
            self.process_data(&mut ctx, ciphertext, b)
                .map_err(|_| exceptions::InvalidTag::new_err(()))?;

            Ok(())
        })?)
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
            let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;
            ctx.encrypt_init(Some(&cipher), Some(key_buf.as_bytes()), None)?;
            Ok(AesSiv {
                ctx: EvpCipherAead::new(ctx, 16, true),
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
        self.ctx.encrypt(py, data_bytes, aad)
    }

    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        associated_data: Option<&pyo3::types::PyList>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let aad = associated_data.map(Aad::List);
        self.ctx.decrypt(py, data.as_bytes(), aad)
    }
}

pub(crate) fn create_module(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let m = pyo3::prelude::PyModule::new(py, "aead")?;

    m.add_class::<AesSiv>()?;

    Ok(m)
}
