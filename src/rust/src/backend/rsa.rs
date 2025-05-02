// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use pyo3::types::PyAnyMethods;

use crate::backend::{hashes, utils};
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types};

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.rsa",
    name = "RSAPrivateKey"
)]
pub(crate) struct RsaPrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.rsa",
    name = "RSAPublicKey"
)]
pub(crate) struct RsaPublicKey {
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

pub(crate) fn private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    unsafe_skip_rsa_key_validation: bool,
) -> CryptographyResult<RsaPrivateKey> {
    if !unsafe_skip_rsa_key_validation {
        check_rsa_private_key(&pkey.rsa().unwrap())?;
    }
    Ok(RsaPrivateKey {
        pkey: pkey.to_owned(),
    })
}

pub(crate) fn public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> RsaPublicKey {
    RsaPublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
fn generate_private_key(public_exponent: u32, key_size: u32) -> CryptographyResult<RsaPrivateKey> {
    let e = openssl::bn::BigNum::from_u32(public_exponent)?;
    let rsa = openssl::rsa::Rsa::generate_with_e(key_size, &e)?;
    let pkey = openssl::pkey::PKey::from_rsa(rsa)?;
    Ok(RsaPrivateKey { pkey })
}

fn oaep_hash_supported(md: &openssl::hash::MessageDigest) -> bool {
    md == &openssl::hash::MessageDigest::sha1()
        || md == &openssl::hash::MessageDigest::sha224()
        || md == &openssl::hash::MessageDigest::sha256()
        || md == &openssl::hash::MessageDigest::sha384()
        || md == &openssl::hash::MessageDigest::sha512()
}

fn setup_encryption_ctx(
    py: pyo3::Python<'_>,
    ctx: &mut openssl::pkey_ctx::PkeyCtx<impl openssl::pkey::HasPublic>,
    padding: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<()> {
    if !padding.is_instance(&types::ASYMMETRIC_PADDING.get(py)?)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "Padding must be an instance of AsymmetricPadding.",
            ),
        ));
    }

    let padding_enum = if padding.is_instance(&types::PKCS1V15.get(py)?)? {
        openssl::rsa::Padding::PKCS1
    } else if padding.is_instance(&types::OAEP.get(py)?)? {
        if !padding
            .getattr(pyo3::intern!(py, "_mgf"))?
            .is_instance(&types::MGF1.get(py)?)?
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
            &padding
                .getattr(pyo3::intern!(py, "_mgf"))?
                .getattr(pyo3::intern!(py, "_algorithm"))?,
        )?;
        let oaep_md = hashes::message_digest_from_algorithm(
            py,
            &padding.getattr(pyo3::intern!(py, "_algorithm"))?,
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
            .extract::<Option<pyo3::pybacked::PyBackedBytes>>()?
        {
            if !label.is_empty() {
                ctx.set_rsa_oaep_label(&label)?;
            }
        }
    }

    Ok(())
}

fn setup_signature_ctx(
    py: pyo3::Python<'_>,
    ctx: &mut openssl::pkey_ctx::PkeyCtx<impl openssl::pkey::HasPublic>,
    padding: &pyo3::Bound<'_, pyo3::PyAny>,
    algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
    key_size: usize,
    is_signing: bool,
) -> CryptographyResult<()> {
    if !padding.is_instance(&types::ASYMMETRIC_PADDING.get(py)?)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "Padding must be an instance of AsymmetricPadding.",
            ),
        ));
    }

    let padding_enum = if padding.is_instance(&types::PKCS1V15.get(py)?)? {
        openssl::rsa::Padding::PKCS1
    } else if padding.is_instance(&types::PSS.get(py)?)? {
        if !padding
            .getattr(pyo3::intern!(py, "_mgf"))?
            .is_instance(&types::MGF1.get(py)?)?
        {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Only MGF1 is supported.",
                    exceptions::Reasons::UNSUPPORTED_MGF,
                )),
            ));
        }

        // PSS padding requires a hash algorithm
        if !algorithm.is_instance(&types::HASH_ALGORITHM.get(py)?)? {
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
        if salt.is_instance(&types::PADDING_MAX_LENGTH.get(py)?)? {
            ctx.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::MAXIMUM_LENGTH)?;
        } else if salt.is_instance(&types::PADDING_DIGEST_LENGTH.get(py)?)? {
            ctx.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
        } else if salt.is_instance(&types::PADDING_AUTO.get(py)?)? {
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
            &padding
                .getattr(pyo3::intern!(py, "_mgf"))?
                .getattr(pyo3::intern!(py, "_algorithm"))?,
        )?;
        ctx.set_rsa_mgf1_md(openssl::md::Md::from_nid(mgf1_md.type_()).unwrap())?;
    }

    Ok(())
}

#[pyo3::pymethods]
impl RsaPrivateKey {
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        padding: &pyo3::Bound<'p, pyo3::PyAny>,
        algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyAny>> {
        let (data, algorithm) =
            utils::calculate_digest_and_algorithm(py, data.as_bytes(), algorithm)?;

        let mut ctx = openssl::pkey_ctx::PkeyCtx::new(&self.pkey)?;
        ctx.sign_init().map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("Unable to sign/verify with this key")
        })?;
        setup_signature_ctx(py, &mut ctx, padding, &algorithm, self.pkey.size(), true)?;

        let length = ctx.sign(data.as_bytes(), None)?;
        Ok(pyo3::types::PyBytes::new_with(py, length, |b| {
            let length = ctx.sign(data.as_bytes(), Some(b)).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "Digest or salt length too long for key size. Use a larger key or shorter salt length if you are specifying a PSS salt",
                )
            })?;
            assert_eq!(length, b.len());
            Ok(())
        })?.into_any())
    }

    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: &[u8],
        padding: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
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

    fn private_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<RsaPrivateNumbers> {
        let rsa = self.pkey.rsa().unwrap();

        let py_p = utils::bn_to_py_int(py, rsa.p().unwrap())?;
        let py_q = utils::bn_to_py_int(py, rsa.q().unwrap())?;
        let py_d = utils::bn_to_py_int(py, rsa.d())?;
        let py_dmp1 = utils::bn_to_py_int(py, rsa.dmp1().unwrap())?;
        let py_dmq1 = utils::bn_to_py_int(py, rsa.dmq1().unwrap())?;
        let py_iqmp = utils::bn_to_py_int(py, rsa.iqmp().unwrap())?;
        let py_e = utils::bn_to_py_int(py, rsa.e())?;
        let py_n = utils::bn_to_py_int(py, rsa.n())?;

        let public_numbers = RsaPublicNumbers {
            e: py_e.extract()?,
            n: py_n.extract()?,
        };
        Ok(RsaPrivateNumbers {
            p: py_p.extract()?,
            q: py_q.extract()?,
            d: py_d.extract()?,
            dmp1: py_dmp1.extract()?,
            dmq1: py_dmq1.extract()?,
            iqmp: py_iqmp.extract()?,
            public_numbers: pyo3::Py::new(py, public_numbers)?,
        })
    }

    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: &pyo3::Bound<'p, pyo3::PyAny>,
        format: &pyo3::Bound<'p, pyo3::PyAny>,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
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

#[pyo3::pymethods]
impl RsaPublicKey {
    fn verify(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        padding: &pyo3::Bound<'_, pyo3::PyAny>,
        algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<()> {
        let (data, algorithm) =
            utils::calculate_digest_and_algorithm(py, data.as_bytes(), algorithm)?;

        let mut ctx = openssl::pkey_ctx::PkeyCtx::new(&self.pkey)?;
        ctx.verify_init()?;
        setup_signature_ctx(py, &mut ctx, padding, &algorithm, self.pkey.size(), false)?;

        let valid = ctx
            .verify(data.as_bytes(), signature.as_bytes())
            .unwrap_or(false);
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
        padding: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
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
        padding: &pyo3::Bound<'_, pyo3::PyAny>,
        algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if algorithm.is_instance(&types::PREHASHED.get(py)?)? {
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

    fn public_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<RsaPublicNumbers> {
        let rsa = self.pkey.rsa().unwrap();

        let py_e = utils::bn_to_py_int(py, rsa.e())?;
        let py_n = utils::bn_to_py_int(py, rsa.n())?;

        Ok(RsaPublicNumbers {
            e: py_e.extract()?,
            n: py_n.extract()?,
        })
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: &pyo3::Bound<'p, pyo3::PyAny>,
        format: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, true, false)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.pkey.public_eq(&other.pkey)
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.primitives.asymmetric.rsa",
    name = "RSAPrivateNumbers"
)]
struct RsaPrivateNumbers {
    #[pyo3(get)]
    p: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    q: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    d: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    dmp1: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    dmq1: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    iqmp: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    public_numbers: pyo3::Py<RsaPublicNumbers>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.primitives.asymmetric.rsa",
    name = "RSAPublicNumbers"
)]
struct RsaPublicNumbers {
    #[pyo3(get)]
    e: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    n: pyo3::Py<pyo3::types::PyInt>,
}

#[allow(clippy::too_many_arguments)]
fn check_private_key_components(
    p: &pyo3::Bound<'_, pyo3::types::PyInt>,
    q: &pyo3::Bound<'_, pyo3::types::PyInt>,
    private_exponent: &pyo3::Bound<'_, pyo3::types::PyInt>,
    dmp1: &pyo3::Bound<'_, pyo3::types::PyInt>,
    dmq1: &pyo3::Bound<'_, pyo3::types::PyInt>,
    iqmp: &pyo3::Bound<'_, pyo3::types::PyInt>,
    public_exponent: &pyo3::Bound<'_, pyo3::types::PyInt>,
    modulus: &pyo3::Bound<'_, pyo3::types::PyInt>,
) -> CryptographyResult<()> {
    if modulus.lt(3)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("modulus must be >= 3."),
        ));
    }

    if p.ge(modulus)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("p must be < modulus."),
        ));
    }

    if q.ge(modulus)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("q must be < modulus."),
        ));
    }

    if dmp1.ge(modulus)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("dmp1 must be < modulus."),
        ));
    }

    if dmq1.ge(modulus)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("dmq1 must be < modulus."),
        ));
    }

    if iqmp.ge(modulus)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("iqmp must be < modulus."),
        ));
    }

    if private_exponent.ge(modulus)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("private_exponent must be < modulus."),
        ));
    }

    if public_exponent.lt(3)? || public_exponent.ge(modulus)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("public_exponent must be >= 3 and < modulus."),
        ));
    }

    if public_exponent.bitand(1)?.eq(0)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("public_exponent must be odd."),
        ));
    }

    if dmp1.bitand(1)?.eq(0)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("dmp1 must be odd."),
        ));
    }

    if dmq1.bitand(1)?.eq(0)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("dmq1 must be odd."),
        ));
    }

    if p.mul(q)?.ne(modulus)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("p*q must equal modulus."),
        ));
    }

    Ok(())
}

#[pyo3::pymethods]
impl RsaPrivateNumbers {
    #[new]
    fn new(
        p: pyo3::Py<pyo3::types::PyInt>,
        q: pyo3::Py<pyo3::types::PyInt>,
        d: pyo3::Py<pyo3::types::PyInt>,
        dmp1: pyo3::Py<pyo3::types::PyInt>,
        dmq1: pyo3::Py<pyo3::types::PyInt>,
        iqmp: pyo3::Py<pyo3::types::PyInt>,
        public_numbers: pyo3::Py<RsaPublicNumbers>,
    ) -> RsaPrivateNumbers {
        Self {
            p,
            q,
            d,
            dmp1,
            dmq1,
            iqmp,
            public_numbers,
        }
    }

    #[pyo3(signature = (backend = None, *, unsafe_skip_rsa_key_validation = false))]
    fn private_key(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<&pyo3::Bound<'_, pyo3::PyAny>>,
        unsafe_skip_rsa_key_validation: bool,
    ) -> CryptographyResult<RsaPrivateKey> {
        let _ = backend;

        check_private_key_components(
            self.p.bind(py),
            self.q.bind(py),
            self.d.bind(py),
            self.dmp1.bind(py),
            self.dmq1.bind(py),
            self.iqmp.bind(py),
            self.public_numbers.get().e.bind(py),
            self.public_numbers.get().n.bind(py),
        )?;
        let public_numbers = self.public_numbers.get();
        let rsa = openssl::rsa::Rsa::from_private_components(
            utils::py_int_to_bn(py, public_numbers.n.bind(py))?,
            utils::py_int_to_bn(py, public_numbers.e.bind(py))?,
            utils::py_int_to_bn(py, self.d.bind(py))?,
            utils::py_int_to_bn(py, self.p.bind(py))?,
            utils::py_int_to_bn(py, self.q.bind(py))?,
            utils::py_int_to_bn(py, self.dmp1.bind(py))?,
            utils::py_int_to_bn(py, self.dmq1.bind(py))?,
            utils::py_int_to_bn(py, self.iqmp.bind(py))?,
        )
        .unwrap();
        if !unsafe_skip_rsa_key_validation {
            check_rsa_private_key(&rsa)?;
        }
        let pkey = openssl::pkey::PKey::from_rsa(rsa)?;
        Ok(RsaPrivateKey { pkey })
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        Ok((**self.p.bind(py)).eq(other.p.bind(py))?
            && (**self.q.bind(py)).eq(other.q.bind(py))?
            && (**self.d.bind(py)).eq(other.d.bind(py))?
            && (**self.dmp1.bind(py)).eq(other.dmp1.bind(py))?
            && (**self.dmq1.bind(py)).eq(other.dmq1.bind(py))?
            && (**self.iqmp.bind(py)).eq(other.iqmp.bind(py))?
            && self
                .public_numbers
                .bind(py)
                .eq(other.public_numbers.bind(py))?)
    }

    fn __hash__(&self, py: pyo3::Python<'_>) -> CryptographyResult<u64> {
        let mut hasher = DefaultHasher::new();
        self.p.bind(py).hash()?.hash(&mut hasher);
        self.q.bind(py).hash()?.hash(&mut hasher);
        self.d.bind(py).hash()?.hash(&mut hasher);
        self.dmp1.bind(py).hash()?.hash(&mut hasher);
        self.dmq1.bind(py).hash()?.hash(&mut hasher);
        self.iqmp.bind(py).hash()?.hash(&mut hasher);
        self.public_numbers.bind(py).hash()?.hash(&mut hasher);
        Ok(hasher.finish())
    }
}

fn check_public_key_components(
    e: &pyo3::Bound<'_, pyo3::types::PyInt>,
    n: &pyo3::Bound<'_, pyo3::types::PyInt>,
) -> CryptographyResult<()> {
    if n.lt(3)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("n must be >= 3."),
        ));
    }

    if e.lt(3)? || e.ge(n)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("e must be >= 3 and < n."),
        ));
    }

    if e.bitand(1)?.eq(0)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("e must be odd."),
        ));
    }

    Ok(())
}

#[pyo3::pymethods]
impl RsaPublicNumbers {
    #[new]
    fn new(e: pyo3::Py<pyo3::types::PyInt>, n: pyo3::Py<pyo3::types::PyInt>) -> RsaPublicNumbers {
        RsaPublicNumbers { e, n }
    }

    #[pyo3(signature = (backend=None))]
    fn public_key(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<&pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<RsaPublicKey> {
        let _ = backend;

        check_public_key_components(self.e.bind(py), self.n.bind(py))?;

        let rsa = openssl::rsa::Rsa::from_public_components(
            utils::py_int_to_bn(py, self.n.bind(py))?,
            utils::py_int_to_bn(py, self.e.bind(py))?,
        )
        .unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(rsa)?;
        Ok(RsaPublicKey { pkey })
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        Ok(
            (**self.e.bind(py)).eq(other.e.bind(py))?
                && (**self.n.bind(py)).eq(other.n.bind(py))?,
        )
    }

    fn __hash__(&self, py: pyo3::Python<'_>) -> CryptographyResult<u64> {
        let mut hasher = DefaultHasher::new();
        self.e.bind(py).hash()?.hash(&mut hasher);
        self.n.bind(py).hash()?.hash(&mut hasher);
        Ok(hasher.finish())
    }

    fn __repr__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<String> {
        let e = self.e.bind(py);
        let n = self.n.bind(py);
        Ok(format!("<RSAPublicNumbers(e={e}, n={n})>"))
    }
}

#[pyo3::pymodule]
pub(crate) mod rsa {
    #[pymodule_export]
    use super::{
        generate_private_key, RsaPrivateKey, RsaPrivateNumbers, RsaPublicKey, RsaPublicNumbers,
    };
}
