// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::{hashes, utils};
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;
use foreign_types_shared::ForeignTypeRef;

#[pyo3::prelude::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.rsa",
    name = "RSAPrivateKey"
)]
struct RsaPrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::prelude::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.rsa",
    name = "RSAPublicKey"
)]
struct RsaPublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

fn check_rsa_private_key(
    rsa: &openssl::rsa::Rsa<openssl::pkey::Private>,
) -> CryptographyResult<()> {
    if !rsa.check_key().unwrap_or(false) || rsa.p().unwrap().is_even() || rsa.q().unwrap().is_even()
    {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("Invalid private key"),
        ));
    }
    Ok(())
}

#[pyo3::prelude::pyfunction]
fn private_key_from_ptr(
    ptr: usize,
    unsafe_skip_rsa_key_validation: bool,
) -> CryptographyResult<RsaPrivateKey> {
    let pkey = unsafe { openssl::pkey::PKeyRef::from_ptr(ptr as *mut _) };
    if !unsafe_skip_rsa_key_validation {
        check_rsa_private_key(&pkey.rsa().unwrap())?;
    }
    Ok(RsaPrivateKey {
        pkey: pkey.to_owned(),
    })
}

#[pyo3::prelude::pyfunction]
fn public_key_from_ptr(ptr: usize) -> RsaPublicKey {
    let pkey = unsafe { openssl::pkey::PKeyRef::from_ptr(ptr as *mut _) };
    RsaPublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::prelude::pyfunction]
fn generate_private_key(public_exponent: u32, key_size: u32) -> CryptographyResult<RsaPrivateKey> {
    let e = openssl::bn::BigNum::from_u32(public_exponent)?;
    let rsa = openssl::rsa::Rsa::generate_with_e(key_size, &e)?;
    let pkey = openssl::pkey::PKey::from_rsa(rsa)?;
    Ok(RsaPrivateKey { pkey })
}

#[pyo3::prelude::pyfunction]
fn from_private_numbers(
    py: pyo3::Python<'_>,
    numbers: &pyo3::PyAny,
    unsafe_skip_rsa_key_validation: bool,
) -> CryptographyResult<RsaPrivateKey> {
    let public_numbers = numbers.getattr(pyo3::intern!(py, "public_numbers"))?;

    let rsa = openssl::rsa::Rsa::from_private_components(
        utils::py_int_to_bn(py, public_numbers.getattr(pyo3::intern!(py, "n"))?)?,
        utils::py_int_to_bn(py, public_numbers.getattr(pyo3::intern!(py, "e"))?)?,
        utils::py_int_to_bn(py, numbers.getattr(pyo3::intern!(py, "d"))?)?,
        utils::py_int_to_bn(py, numbers.getattr(pyo3::intern!(py, "p"))?)?,
        utils::py_int_to_bn(py, numbers.getattr(pyo3::intern!(py, "q"))?)?,
        utils::py_int_to_bn(py, numbers.getattr(pyo3::intern!(py, "dmp1"))?)?,
        utils::py_int_to_bn(py, numbers.getattr(pyo3::intern!(py, "dmq1"))?)?,
        utils::py_int_to_bn(py, numbers.getattr(pyo3::intern!(py, "iqmp"))?)?,
    )
    .unwrap();
    if !unsafe_skip_rsa_key_validation {
        check_rsa_private_key(&rsa)?;
    }
    let pkey = openssl::pkey::PKey::from_rsa(rsa)?;
    Ok(RsaPrivateKey { pkey })
}

#[pyo3::prelude::pyfunction]
fn from_public_numbers(
    py: pyo3::Python<'_>,
    numbers: &pyo3::PyAny,
) -> CryptographyResult<RsaPublicKey> {
    let rsa = openssl::rsa::Rsa::from_public_components(
        utils::py_int_to_bn(py, numbers.getattr(pyo3::intern!(py, "n"))?)?,
        utils::py_int_to_bn(py, numbers.getattr(pyo3::intern!(py, "e"))?)?,
    )
    .unwrap();
    let pkey = openssl::pkey::PKey::from_rsa(rsa)?;
    Ok(RsaPublicKey { pkey })
}

fn oaep_hash_supported(md: &openssl::hash::MessageDigest) -> bool {
    (!cryptography_openssl::fips::is_enabled() && md == &openssl::hash::MessageDigest::sha1())
        || md == &openssl::hash::MessageDigest::sha224()
        || md == &openssl::hash::MessageDigest::sha256()
        || md == &openssl::hash::MessageDigest::sha384()
        || md == &openssl::hash::MessageDigest::sha512()
}

fn setup_encryption_ctx(
    py: pyo3::Python<'_>,
    ctx: &mut openssl::pkey_ctx::PkeyCtx<impl openssl::pkey::HasPublic>,
    padding: &pyo3::PyAny,
) -> CryptographyResult<()> {
    let padding_mod = py.import(pyo3::intern!(
        py,
        "cryptography.hazmat.primitives.asymmetric.padding"
    ))?;
    let asymmetric_padding_class = padding_mod
        .getattr(pyo3::intern!(py, "AsymmetricPadding"))?
        .extract()?;
    let pkcs1_class = padding_mod
        .getattr(pyo3::intern!(py, "PKCS1v15"))?
        .extract()?;
    let oaep_class = padding_mod.getattr(pyo3::intern!(py, "OAEP"))?.extract()?;
    let mgf1_class = padding_mod.getattr(pyo3::intern!(py, "MGF1"))?.extract()?;

    if !padding.is_instance(asymmetric_padding_class)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "Padding must be an instance of AsymmetricPadding.",
            ),
        ));
    }

    let padding_enum = if padding.is_instance(pkcs1_class)? {
        openssl::rsa::Padding::PKCS1
    } else if padding.is_instance(oaep_class)? {
        if !padding
            .getattr(pyo3::intern!(py, "_mgf"))?
            .is_instance(mgf1_class)?
        {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Only MGF1 is supported.",
                    exceptions::Reasons::UNSUPPORTED_MGF,
                )),
            ));
        }

        openssl::rsa::Padding::PKCS1_OAEP
    } else {
        return Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err((
                format!(
                    "{} is not supported by this backend.",
                    padding.getattr(pyo3::intern!(py, "name"))?
                ),
                exceptions::Reasons::UNSUPPORTED_PADDING,
            )),
        ));
    };

    ctx.set_rsa_padding(padding_enum)?;

    if padding_enum == openssl::rsa::Padding::PKCS1_OAEP {
        let mgf1_md = hashes::message_digest_from_algorithm(
            py,
            padding
                .getattr(pyo3::intern!(py, "_mgf"))?
                .getattr(pyo3::intern!(py, "_algorithm"))?,
        )?;
        let oaep_md = hashes::message_digest_from_algorithm(
            py,
            padding.getattr(pyo3::intern!(py, "_algorithm"))?,
        )?;

        if !oaep_hash_supported(&mgf1_md) || !oaep_hash_supported(&oaep_md) {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "This combination of padding and hash algorithm is not supported",
                    exceptions::Reasons::UNSUPPORTED_PADDING,
                )),
            ));
        }

        ctx.set_rsa_mgf1_md(openssl::md::Md::from_nid(mgf1_md.type_()).unwrap())?;
        ctx.set_rsa_oaep_md(openssl::md::Md::from_nid(oaep_md.type_()).unwrap())?;

        if let Some(label) = padding
            .getattr(pyo3::intern!(py, "_label"))?
            .extract::<Option<&[u8]>>()?
        {
            if !label.is_empty() {
                ctx.set_rsa_oaep_label(label)?;
            }
        }
    }

    Ok(())
}

fn setup_signature_ctx(
    py: pyo3::Python<'_>,
    ctx: &mut openssl::pkey_ctx::PkeyCtx<impl openssl::pkey::HasPublic>,
    padding: &pyo3::PyAny,
    algorithm: &pyo3::PyAny,
    key_size: usize,
    is_signing: bool,
) -> CryptographyResult<()> {
    let padding_mod = py.import(pyo3::intern!(
        py,
        "cryptography.hazmat.primitives.asymmetric.padding"
    ))?;
    let asymmetric_padding_class = padding_mod.getattr(pyo3::intern!(py, "AsymmetricPadding"))?;
    let pkcs1_class = padding_mod.getattr(pyo3::intern!(py, "PKCS1v15"))?;
    let pss_class = padding_mod.getattr(pyo3::intern!(py, "PSS"))?.extract()?;
    let max_length_class = padding_mod.getattr(pyo3::intern!(py, "_MaxLength"))?;
    let digest_length_class = padding_mod.getattr(pyo3::intern!(py, "_DigestLength"))?;
    let auto_class = padding_mod.getattr(pyo3::intern!(py, "_Auto"))?;
    let mgf1_class = padding_mod.getattr(pyo3::intern!(py, "MGF1"))?;
    let hash_algorithm_class = py
        .import(pyo3::intern!(py, "cryptography.hazmat.primitives.hashes"))?
        .getattr(pyo3::intern!(py, "HashAlgorithm"))?;

    if !padding.is_instance(asymmetric_padding_class)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "Padding must be an instance of AsymmetricPadding.",
            ),
        ));
    }

    let padding_enum = if padding.is_instance(pkcs1_class)? {
        openssl::rsa::Padding::PKCS1
    } else if padding.is_instance(pss_class)? {
        if !padding
            .getattr(pyo3::intern!(py, "_mgf"))?
            .is_instance(mgf1_class)?
        {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Only MGF1 is supported.",
                    exceptions::Reasons::UNSUPPORTED_MGF,
                )),
            ));
        }

        // PSS padding requires a hash algorithm
        if !algorithm.is_instance(hash_algorithm_class)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "Expected instance of hashes.HashAlgorithm.",
                ),
            ));
        }

        if algorithm
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?
            + 2
            > key_size
        {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "Digest too large for key size. Use a larger key or different digest.",
                ),
            ));
        }

        openssl::rsa::Padding::PKCS1_PSS
    } else {
        return Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err((
                format!(
                    "{} is not supported by this backend.",
                    padding.getattr(pyo3::intern!(py, "name"))?
                ),
                exceptions::Reasons::UNSUPPORTED_PADDING,
            )),
        ));
    };

    if !algorithm.is_none() {
        let md = hashes::message_digest_from_algorithm(py, algorithm)?;
        ctx.set_signature_md(openssl::md::Md::from_nid(md.type_()).unwrap())
            .or_else(|_| {
                Err(CryptographyError::from(
                    exceptions::UnsupportedAlgorithm::new_err((
                        format!(
                            "{} is not supported by this backend for RSA signing.",
                            algorithm.getattr(pyo3::intern!(py, "name"))?
                        ),
                        exceptions::Reasons::UNSUPPORTED_HASH,
                    )),
                ))
            })?;
    }
    ctx.set_rsa_padding(padding_enum).or_else(|_| {
        Err(exceptions::UnsupportedAlgorithm::new_err((
            format!(
                "{} is not supported for the RSA signature operation",
                padding.getattr(pyo3::intern!(py, "name"))?
            ),
            exceptions::Reasons::UNSUPPORTED_PADDING,
        )))
    })?;

    if padding_enum == openssl::rsa::Padding::PKCS1_PSS {
        let salt = padding.getattr(pyo3::intern!(py, "_salt_length"))?;
        if salt.is_instance(max_length_class)? {
            ctx.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::MAXIMUM_LENGTH)?;
        } else if salt.is_instance(digest_length_class)? {
            ctx.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
        } else if salt.is_instance(auto_class)? {
            if is_signing {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "PSS salt length can only be set to Auto when verifying",
                    ),
                ));
            }
        } else {
            ctx.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::custom(salt.extract::<i32>()?))?;
        };

        let mgf1_md = hashes::message_digest_from_algorithm(
            py,
            padding
                .getattr(pyo3::intern!(py, "_mgf"))?
                .getattr(pyo3::intern!(py, "_algorithm"))?,
        )?;
        ctx.set_rsa_mgf1_md(openssl::md::Md::from_nid(mgf1_md.type_()).unwrap())?;
    }

    Ok(())
}

#[pyo3::prelude::pymethods]
impl RsaPrivateKey {
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: &[u8],
        padding: &pyo3::PyAny,
        algorithm: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::PyAny> {
        let (data, algorithm): (&[u8], &pyo3::PyAny) = py
            .import(pyo3::intern!(
                py,
                "cryptography.hazmat.backends.openssl.utils"
            ))?
            .call_method1(
                pyo3::intern!(py, "_calculate_digest_and_algorithm"),
                (data, algorithm),
            )?
            .extract()?;

        let mut ctx = openssl::pkey_ctx::PkeyCtx::new(&self.pkey)?;
        ctx.sign_init().map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("Unable to sign/verify with this key")
        })?;
        setup_signature_ctx(py, &mut ctx, padding, algorithm, self.pkey.size(), true)?;

        let length = ctx.sign(data, None)?;
        Ok(pyo3::types::PyBytes::new_with(py, length, |b| {
            let length = ctx.sign(data, Some(b)).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "Digest or salt length too long for key size. Use a larger key or shorter salt length if you are specifying a PSS salt",
                )
            })?;
            assert_eq!(length, b.len());
            Ok(())
        })?)
    }

    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: &[u8],
        padding: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let key_size_bytes =
            usize::try_from((self.pkey.rsa().unwrap().n().num_bits() + 7) / 8).unwrap();
        if key_size_bytes != ciphertext.len() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "Ciphertext length must be equal to key size.",
                ),
            ));
        }

        let mut ctx = openssl::pkey_ctx::PkeyCtx::new(&self.pkey)?;
        ctx.decrypt_init()?;

        setup_encryption_ctx(py, &mut ctx, padding)?;

        // Everything from this line onwards is written with the goal of being
        // as constant-time as is practical given the constraints of
        // rust-openssl and our API. See Bleichenbacher's '98 attack on RSA,
        // and its many many variants. As such, you should not attempt to
        // change this (particularly to "clean it up") without understanding
        // why it was written this way (see Chesterton's Fence), and without
        // measuring to verify you have not introduced observable time
        // differences.
        //
        // Once OpenSSL 3.2.0 is out, this can be simplified, as OpenSSL will
        // have its own mitigations for Bleichenbacher's attack.
        let length = ctx.decrypt(ciphertext, None).unwrap();
        let mut plaintext = vec![0; length];
        let result = ctx.decrypt(ciphertext, Some(&mut plaintext));

        let py_result =
            pyo3::types::PyBytes::new(py, &plaintext[..*result.as_ref().unwrap_or(&length)]);
        if result.is_err() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Decryption failed"),
            ));
        }
        Ok(py_result)
    }

    #[getter]
    fn key_size(&self) -> i32 {
        self.pkey.rsa().unwrap().n().num_bits()
    }

    fn public_key(&self) -> CryptographyResult<RsaPublicKey> {
        let priv_rsa = self.pkey.rsa().unwrap();
        let rsa = openssl::rsa::Rsa::from_public_components(
            priv_rsa.n().to_owned()?,
            priv_rsa.e().to_owned()?,
        )
        .unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(rsa)?;
        Ok(RsaPublicKey { pkey })
    }

    fn private_numbers<'p>(&self, py: pyo3::Python<'p>) -> CryptographyResult<&'p pyo3::PyAny> {
        let rsa = self.pkey.rsa().unwrap();

        let py_p = utils::bn_to_py_int(py, rsa.p().unwrap())?;
        let py_q = utils::bn_to_py_int(py, rsa.q().unwrap())?;
        let py_d = utils::bn_to_py_int(py, rsa.d())?;
        let py_dmp1 = utils::bn_to_py_int(py, rsa.dmp1().unwrap())?;
        let py_dmq1 = utils::bn_to_py_int(py, rsa.dmq1().unwrap())?;
        let py_iqmp = utils::bn_to_py_int(py, rsa.iqmp().unwrap())?;
        let py_e = utils::bn_to_py_int(py, rsa.e())?;
        let py_n = utils::bn_to_py_int(py, rsa.n())?;

        let rsa_mod = py.import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.rsa"
        ))?;

        let public_numbers =
            rsa_mod.call_method1(pyo3::intern!(py, "RSAPublicNumbers"), (py_e, py_n))?;
        Ok(rsa_mod.call_method1(
            pyo3::intern!(py, "RSAPrivateNumbers"),
            (py_p, py_q, py_d, py_dmp1, py_dmq1, py_iqmp, public_numbers),
        )?)
    }

    fn private_bytes<'p>(
        slf: &pyo3::PyCell<Self>,
        py: pyo3::Python<'p>,
        encoding: &pyo3::PyAny,
        format: &pyo3::PyAny,
        encryption_algorithm: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        utils::pkey_private_bytes(
            py,
            slf,
            &slf.borrow().pkey,
            encoding,
            format,
            encryption_algorithm,
            true,
            false,
        )
    }
}

#[pyo3::prelude::pymethods]
impl RsaPublicKey {
    fn verify(
        &self,
        py: pyo3::Python<'_>,
        signature: &[u8],
        data: &[u8],
        padding: &pyo3::PyAny,
        algorithm: &pyo3::PyAny,
    ) -> CryptographyResult<()> {
        let (data, algorithm): (&[u8], &pyo3::PyAny) = py
            .import(pyo3::intern!(
                py,
                "cryptography.hazmat.backends.openssl.utils"
            ))?
            .call_method1(
                pyo3::intern!(py, "_calculate_digest_and_algorithm"),
                (data, algorithm),
            )?
            .extract()?;

        let mut ctx = openssl::pkey_ctx::PkeyCtx::new(&self.pkey)?;
        ctx.verify_init()?;
        setup_signature_ctx(py, &mut ctx, padding, algorithm, self.pkey.size(), false)?;

        let valid = ctx.verify(data, signature).unwrap_or(false);
        if !valid {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err(()),
            ));
        }

        Ok(())
    }

    fn encrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        plaintext: &[u8],
        padding: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let mut ctx = openssl::pkey_ctx::PkeyCtx::new(&self.pkey)?;
        ctx.encrypt_init()?;

        setup_encryption_ctx(py, &mut ctx, padding)?;

        let length = ctx.encrypt(plaintext, None)?;
        Ok(pyo3::types::PyBytes::new_with(py, length, |b| {
            let length = ctx
                .encrypt(plaintext, Some(b))
                .map_err(|_| pyo3::exceptions::PyValueError::new_err("Encryption failed"))?;
            assert_eq!(length, b.len());
            Ok(())
        })?)
    }

    fn recover_data_from_signature<'p>(
        &self,
        py: pyo3::Python<'p>,
        signature: &[u8],
        padding: &pyo3::PyAny,
        algorithm: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let prehashed_class = py
            .import(pyo3::intern!(
                py,
                "cryptography.hazmat.primitives.asymmetric.utils"
            ))?
            .getattr(pyo3::intern!(py, "Prehashed"))?;

        if algorithm.is_instance(prehashed_class)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "Prehashed is only supported in the sign and verify methods. It cannot be used with recover_data_from_signature.",
                ),
            ));
        }

        let mut ctx = openssl::pkey_ctx::PkeyCtx::new(&self.pkey)?;
        ctx.verify_recover_init()?;
        setup_signature_ctx(py, &mut ctx, padding, algorithm, self.pkey.size(), false)?;

        let length = ctx.verify_recover(signature, None)?;
        let mut buf = vec![0u8; length];
        let length = ctx
            .verify_recover(signature, Some(&mut buf))
            .map_err(|_| exceptions::InvalidSignature::new_err(()))?;

        Ok(pyo3::types::PyBytes::new(py, &buf[..length]))
    }

    #[getter]
    fn key_size(&self) -> i32 {
        self.pkey.rsa().unwrap().n().num_bits()
    }

    fn public_numbers<'p>(&self, py: pyo3::Python<'p>) -> CryptographyResult<&'p pyo3::PyAny> {
        let rsa = self.pkey.rsa().unwrap();

        let py_e = utils::bn_to_py_int(py, rsa.e())?;
        let py_n = utils::bn_to_py_int(py, rsa.n())?;

        let rsa_mod = py.import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.rsa"
        ))?;

        Ok(rsa_mod.call_method1(pyo3::intern!(py, "RSAPublicNumbers"), (py_e, py_n))?)
    }

    fn public_bytes<'p>(
        slf: &pyo3::PyCell<Self>,
        py: pyo3::Python<'p>,
        encoding: &pyo3::PyAny,
        format: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, true, false)
    }

    fn __richcmp__(
        &self,
        other: pyo3::PyRef<'_, RsaPublicKey>,
        op: pyo3::basic::CompareOp,
    ) -> pyo3::PyResult<bool> {
        match op {
            pyo3::basic::CompareOp::Eq => Ok(self.pkey.public_eq(&other.pkey)),
            pyo3::basic::CompareOp::Ne => Ok(!self.pkey.public_eq(&other.pkey)),
            _ => Err(pyo3::exceptions::PyTypeError::new_err("Cannot be ordered")),
        }
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }
}

pub(crate) fn create_module(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let m = pyo3::prelude::PyModule::new(py, "rsa")?;
    m.add_function(pyo3::wrap_pyfunction!(private_key_from_ptr, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(public_key_from_ptr, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(generate_private_key, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(from_private_numbers, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(from_public_numbers, m)?)?;

    m.add_class::<RsaPrivateKey>()?;
    m.add_class::<RsaPublicKey>()?;

    Ok(m)
}
