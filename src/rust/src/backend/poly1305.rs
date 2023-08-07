// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::hashes::already_finalized_error;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

#[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_LIBRESSL))]
struct Poly1305Boring {
    context: Option<Box<openssl_sys::poly1305_state>>,
}

#[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_LIBRESSL))]
impl Poly1305Boring {
    fn new(key: CffiBuf<'_>) -> CryptographyResult<Poly1305Boring> {
        if key.as_bytes().len() != 32 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("A poly1305 key is 32 bytes long"),
            ));
        }
        #[cfg(CRYPTOGRAPHY_IS_BORINGSSL)]
        let mut ctx: Box<openssl_sys::poly1305_state> = Box::new([0; 512usize]);
        #[cfg(CRYPTOGRAPHY_IS_LIBRESSL)]
        let mut ctx: Box<openssl_sys::poly1305_state> = Box::new(openssl_sys::poly1305_state {
            aligner: 0,
            opaque: [0; 136usize],
        });

        unsafe {
            openssl_sys::CRYPTO_poly1305_init(ctx.as_mut(), key.as_bytes().as_ptr());
        }
        Ok(Poly1305Boring { context: Some(ctx) })
    }

    fn get_mut_context(&mut self) -> CryptographyResult<&mut openssl_sys::poly1305_state> {
        if let Some(ctx) = self.context.as_mut() {
            return Ok(ctx);
        };
        Err(already_finalized_error())
    }

    fn update(&mut self, data: CffiBuf<'_>) -> CryptographyResult<()> {
        let buf = data.as_bytes();
        let ctx = self.get_mut_context()?;
        unsafe {
            openssl_sys::CRYPTO_poly1305_update(ctx, buf.as_ptr(), buf.len());
        };
        Ok(())
    }
    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let ctx = self.get_mut_context()?;
        let result = pyo3::types::PyBytes::new_with(py, 16usize, |b| {
            unsafe { openssl_sys::CRYPTO_poly1305_finish(ctx, b.as_mut_ptr()) };
            Ok(())
        })?;
        self.context = None;
        Ok(result)
    }
}

#[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
struct Poly1305Open {
    signer: Option<openssl::sign::Signer<'static>>,
}

#[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
impl Poly1305Open {
    fn get_mut_signer(&mut self) -> CryptographyResult<&mut openssl::sign::Signer<'static>> {
        if let Some(signer) = self.signer.as_mut() {
            return Ok(signer);
        };
        Err(already_finalized_error())
    }

    fn new(key: CffiBuf<'_>) -> CryptographyResult<Poly1305Open> {
        if cryptography_openssl::fips::is_enabled() {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "poly1305 is not supported by this version of OpenSSL.",
                    exceptions::Reasons::UNSUPPORTED_MAC,
                )),
            ));
        }

        let pkey = openssl::pkey::PKey::private_key_from_raw_bytes(
            key.as_bytes(),
            openssl::pkey::Id::POLY1305,
        )
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("A poly1305 key is 32 bytes long"))?;

        Ok(Poly1305Open {
            signer: Some(
                openssl::sign::Signer::new_without_digest(&pkey).map_err(|_| {
                    pyo3::exceptions::PyValueError::new_err("A poly1305 key is 32 bytes long")
                })?,
            ),
        })
    }
    fn update(&mut self, data: CffiBuf<'_>) -> CryptographyResult<()> {
        let buf = data.as_bytes();
        self.get_mut_signer()?.update(buf)?;
        Ok(())
    }
    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let signer = self.get_mut_signer()?;
        let result = pyo3::types::PyBytes::new_with(py, signer.len()?, |b| {
            let n = signer.sign(b).unwrap();
            assert_eq!(n, b.len());
            Ok(())
        })?;
        self.signer = None;
        Ok(result)
    }
}

#[pyo3::prelude::pyclass(module = "cryptography.hazmat.bindings._rust.openssl.poly1305")]
struct Poly1305 {
    #[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_LIBRESSL))]
    backend: Poly1305Boring,
    #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
    backend: Poly1305Open,
}

#[pyo3::pymethods]
impl Poly1305 {
    #[new]
    fn new(key: CffiBuf<'_>) -> CryptographyResult<Poly1305> {
        #[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_LIBRESSL))]
        return Ok(Poly1305 {
            backend: Poly1305Boring::new(key)?,
        });
        #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
        return Ok(Poly1305 {
            backend: Poly1305Open::new(key)?,
        });
    }

    #[staticmethod]
    fn generate_tag<'p>(
        py: pyo3::Python<'p>,
        key: CffiBuf<'_>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let mut p = Poly1305::new(key)?;
        p.update(data)?;
        p.finalize(py)
    }

    #[staticmethod]
    fn verify_tag(
        py: pyo3::Python<'_>,
        key: CffiBuf<'_>,
        data: CffiBuf<'_>,
        tag: &[u8],
    ) -> CryptographyResult<()> {
        let mut p = Poly1305::new(key)?;
        p.update(data)?;
        p.verify(py, tag)
    }

    fn update(&mut self, data: CffiBuf<'_>) -> CryptographyResult<()> {
        self.backend.update(data)
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        self.backend.finalize(py)
    }

    fn verify(&mut self, py: pyo3::Python<'_>, signature: &[u8]) -> CryptographyResult<()> {
        let actual = self.finalize(py)?.as_bytes();
        if actual.len() != signature.len() || !openssl::memcmp::eq(actual, signature) {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err("Value did not match computed tag."),
            ));
        }

        Ok(())
    }
}

pub(crate) fn create_module(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let m = pyo3::prelude::PyModule::new(py, "poly1305")?;

    m.add_class::<Poly1305>()?;

    Ok(m)
}
