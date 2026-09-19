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
    pkey: openssl_bridge::rsa::PrivateKey,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.rsa",
    name = "RSAPublicKey"
)]
pub(crate) struct RsaPublicKey {
    pkey: openssl_bridge::rsa::PublicKey,
}

fn invalid_private_key() -> pyo3::PyErr {
    pyo3::exceptions::PyValueError::new_err("Invalid private key")
}

pub(crate) fn private_key_from_components(
    parts: openssl_bridge::rsa::PrivateComponents<'_>,
    unsafe_skip_rsa_key_validation: bool,
) -> CryptographyResult<RsaPrivateKey> {
    let validation = if unsafe_skip_rsa_key_validation {
        openssl_bridge::rsa::Validation::Structural
    } else {
        openssl_bridge::rsa::Validation::Full
    };
    Ok(RsaPrivateKey {
        pkey: openssl_bridge::rsa::PrivateKey::from_components_with_validation(parts, validation)
            .map_err(|_| invalid_private_key())?,
    })
}
pub(crate) fn public_key_from_key(
    pkey: openssl_bridge::rsa::PublicKey,
) -> CryptographyResult<RsaPublicKey> {
    let parts = pkey.export_components()?;
    check_public_key_components(&parts.e, &parts.n)?;
    Ok(RsaPublicKey { pkey })
}
impl RsaPrivateKey {
    fn serialization_key(&self) -> CryptographyResult<openssl_bridge::rsa::PrivateExport> {
        Ok(self.pkey.export_components()?)
    }
}
impl RsaPublicKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PublicKeyRef<'_>> {
        Ok(cryptography_key_parsing::PublicKeyRef::Rsa(&self.pkey))
    }
}

#[pyo3::pyfunction]
fn generate_private_key(
    py: pyo3::Python<'_>,
    public_exponent: u32,
    key_size: u32,
) -> CryptographyResult<RsaPrivateKey> {
    Ok(RsaPrivateKey {
        pkey: py.detach(|| openssl_bridge::rsa::PrivateKey::generate(key_size, public_exponent))?,
    })
}

enum EncryptionParameters {
    Pkcs1v15,
    Oaep {
        digest: openssl_bridge::hash::Algorithm,
        mgf1: openssl_bridge::hash::Algorithm,
        label: Vec<u8>,
    },
}
impl EncryptionParameters {
    fn native(&self) -> openssl_bridge::rsa::EncryptionPadding<'_> {
        match self {
            Self::Pkcs1v15 => openssl_bridge::rsa::EncryptionPadding::Pkcs1v15,
            Self::Oaep {
                digest,
                mgf1,
                label,
            } => openssl_bridge::rsa::EncryptionPadding::Oaep {
                digest: *digest,
                mgf1: *mgf1,
                label,
            },
        }
    }
}

fn encryption_parameters(
    py: pyo3::Python<'_>,
    padding: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<EncryptionParameters> {
    if !padding.is_instance(&types::ASYMMETRIC_PADDING.get(py)?)? {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "Padding must be an instance of AsymmetricPadding.",
        )
        .into());
    }
    if padding.is_instance(&types::PKCS1V15.get(py)?)? {
        return Ok(EncryptionParameters::Pkcs1v15);
    }
    if !padding.is_instance(&types::OAEP.get(py)?)? {
        return Err(exceptions::UnsupportedAlgorithm::new_err((
            format!(
                "{} is not supported by this backend.",
                padding.getattr(pyo3::intern!(py, "name"))?
            ),
            exceptions::Reasons::UNSUPPORTED_PADDING,
        ))
        .into());
    }
    let mgf = padding.getattr(pyo3::intern!(py, "_mgf"))?;
    if !mgf.is_instance(&types::MGF1.get(py)?)? {
        return Err(exceptions::UnsupportedAlgorithm::new_err((
            "Only MGF1 is supported.",
            exceptions::Reasons::UNSUPPORTED_MGF,
        ))
        .into());
    }
    let mgf_algorithm = mgf.getattr(pyo3::intern!(py, "_algorithm"))?;
    let algorithm = padding.getattr(pyo3::intern!(py, "_algorithm"))?;
    let mgf1 = hashes::bridge_digest_from_algorithm(py, &mgf_algorithm)?;
    let digest = hashes::bridge_digest_from_algorithm(py, &algorithm)?;
    for algorithm in [&mgf_algorithm, &algorithm] {
        let name = algorithm
            .getattr(pyo3::intern!(py, "name"))?
            .extract::<pyo3::pybacked::PyBackedStr>()?;
        if !matches!(&*name, "sha1" | "sha224" | "sha256" | "sha384" | "sha512") {
            return Err(exceptions::UnsupportedAlgorithm::new_err((
                "This combination of padding and hash algorithm is not supported",
                exceptions::Reasons::UNSUPPORTED_PADDING,
            ))
            .into());
        }
    }
    let label = padding
        .getattr(pyo3::intern!(py, "_label"))?
        .extract::<Option<pyo3::pybacked::PyBackedBytes>>()?
        .map(|label| label.to_vec())
        .unwrap_or_default();
    Ok(EncryptionParameters::Oaep {
        digest,
        mgf1,
        label,
    })
}

fn signature_padding(
    py: pyo3::Python<'_>,
    padding: &pyo3::Bound<'_, pyo3::PyAny>,
    algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
    key_size: usize,
    is_signing: bool,
) -> CryptographyResult<openssl_bridge::rsa::VerificationPadding> {
    use openssl_bridge::rsa::{SaltLength, VerificationPadding};
    if !padding.is_instance(&types::ASYMMETRIC_PADDING.get(py)?)? {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "Padding must be an instance of AsymmetricPadding.",
        )
        .into());
    }
    if padding.is_instance(&types::PKCS1V15.get(py)?)? {
        return Ok(VerificationPadding::Pkcs1v15);
    }
    if !padding.is_instance(&types::PSS.get(py)?)? {
        return Err(exceptions::UnsupportedAlgorithm::new_err((
            format!(
                "{} is not supported by this backend.",
                padding.getattr(pyo3::intern!(py, "name"))?
            ),
            exceptions::Reasons::UNSUPPORTED_PADDING,
        ))
        .into());
    }
    let mgf = padding.getattr(pyo3::intern!(py, "_mgf"))?;
    if !mgf.is_instance(&types::MGF1.get(py)?)? {
        return Err(exceptions::UnsupportedAlgorithm::new_err((
            "Only MGF1 is supported.",
            exceptions::Reasons::UNSUPPORTED_MGF,
        ))
        .into());
    }
    if !algorithm.is_instance(&types::HASH_ALGORITHM.get(py)?)? {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "Expected instance of hashes.HashAlgorithm.",
        )
        .into());
    }
    if algorithm
        .getattr(pyo3::intern!(py, "digest_size"))?
        .extract::<usize>()?
        .checked_add(2)
        .is_none_or(|size| size > key_size)
    {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Digest too large for key size. Use a larger key or different digest.",
        )
        .into());
    }
    let mgf1 =
        hashes::bridge_digest_from_algorithm(py, &mgf.getattr(pyo3::intern!(py, "_algorithm"))?)?;
    let salt = padding.getattr(pyo3::intern!(py, "_salt_length"))?;
    let salt = if salt.is_instance(&types::PADDING_MAX_LENGTH.get(py)?)? {
        if !is_signing {
            return Ok(VerificationPadding::PssAuto { mgf1 });
        }
        SaltLength::Maximum
    } else if salt.is_instance(&types::PADDING_DIGEST_LENGTH.get(py)?)? {
        SaltLength::Digest
    } else if salt.is_instance(&types::PADDING_AUTO.get(py)?)? {
        if is_signing {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "PSS salt length can only be set to Auto when verifying",
            )
            .into());
        }
        return Ok(VerificationPadding::PssAuto { mgf1 });
    } else {
        let value = salt.extract::<i32>()?;
        SaltLength::Exact(u32::try_from(value).map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("PSS salt length must be nonnegative")
        })?)
    };
    Ok(VerificationPadding::Pss { mgf1, salt })
}

fn signing_padding(
    padding: openssl_bridge::rsa::VerificationPadding,
) -> CryptographyResult<openssl_bridge::rsa::SigningPadding> {
    use openssl_bridge::rsa::{SigningPadding, VerificationPadding};
    match padding {
        VerificationPadding::Pkcs1v15 => Ok(SigningPadding::Pkcs1v15),
        VerificationPadding::Pss { mgf1, salt } => Ok(SigningPadding::Pss { mgf1, salt }),
        VerificationPadding::PssAuto { .. } => Err(pyo3::exceptions::PyValueError::new_err(
            "PSS salt length can only be set to Auto when verifying",
        )
        .into()),
    }
}

fn signature_digest(
    py: pyo3::Python<'_>,
    algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<Option<openssl_bridge::hash::Algorithm>> {
    if algorithm.is_none() {
        Ok(None)
    } else {
        Ok(Some(hashes::bridge_digest_from_algorithm(py, algorithm)?))
    }
}
fn unsupported_signature_digest(
    py: pyo3::Python<'_>,
    algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<()> {
    Err(exceptions::UnsupportedAlgorithm::new_err((
        format!(
            "{} is not supported by this backend for RSA signing.",
            algorithm.getattr(pyo3::intern!(py, "name"))?
        ),
        exceptions::Reasons::UNSUPPORTED_HASH,
    ))
    .into())
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
        let (data, algorithm) = {
            if algorithm.is_instance(&types::NO_DIGEST_INFO.get(py)?)? {
                (
                    utils::BytesOrPyBytes::Bytes(data.as_bytes()),
                    pyo3::types::PyNone::get(py).to_owned().into_any(),
                )
            } else {
                utils::calculate_digest_and_algorithm(py, data.as_bytes(), algorithm)?
            }
        };

        let padding = signing_padding(signature_padding(
            py,
            padding,
            &algorithm,
            (self.pkey.bits() as usize).div_ceil(8),
            true,
        )?)?;
        let digest = signature_digest(py, &algorithm)?;
        if let Some(digest) = digest {
            if !self.pkey.signature_digest_supported(digest).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("Unable to sign with this key and digest")
            })? {
                unsupported_signature_digest(py, &algorithm)?;
            }
        }
        let bytes = data.as_bytes();
        let signature = py.detach(|| match digest {
            Some(digest) => self.pkey.sign_digest(digest, bytes, padding),
            None => self.pkey.sign_pkcs1v15_block(bytes),
        }).map_err(|_| pyo3::exceptions::PyValueError::new_err(
            "Digest or salt length too long for key size. Use a larger key or shorter salt length if you are specifying a PSS salt"
        ))?;
        Ok(pyo3::types::PyBytes::new(py, &signature).into_any())
    }

    fn decrypt<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: &[u8],
        padding: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let length = (self.pkey.bits() as usize).div_ceil(8);
        if length != ciphertext.len() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Ciphertext length must be equal to key size.",
            )
            .into());
        }
        let parameters = encryption_parameters(py, padding)?;
        // Preserve allocation on both success and failure for the legacy
        // PKCS1 v1.5 behavior. The abstraction checks capacity and erases failed
        // native output before returning; this is not a constant-time guarantee.
        let (result, plaintext) = py.detach(|| {
            let mut plaintext = vec![0; length];
            let result = self
                .pkey
                .decrypt_into(ciphertext, parameters.native(), &mut plaintext);
            (result, openssl_bridge::secret::SecretBytes::from(plaintext))
        });
        let py_result = pyo3::types::PyBytes::new(
            py,
            &plaintext.as_ref()[..*result.as_ref().unwrap_or(&length)],
        );
        if result.is_err() {
            return Err(pyo3::exceptions::PyValueError::new_err("Decryption failed").into());
        }
        Ok(py_result)
    }

    #[getter]
    fn key_size(&self) -> u32 {
        self.pkey.bits()
    }

    fn public_key(&self) -> CryptographyResult<RsaPublicKey> {
        Ok(RsaPublicKey {
            pkey: self.pkey.public_key()?,
        })
    }

    fn private_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<RsaPrivateNumbers> {
        let export = self.pkey.export_components()?;
        let rsa = export.components();

        let py_p = utils::bytes_to_py_int(py, rsa.p)?;
        let py_q = utils::bytes_to_py_int(py, rsa.q)?;
        let py_d = utils::bytes_to_py_int(py, rsa.d)?;
        let py_dmp1 = utils::bytes_to_py_int(py, rsa.dmp1)?;
        let py_dmq1 = utils::bytes_to_py_int(py, rsa.dmq1)?;
        let py_iqmp = utils::bytes_to_py_int(py, rsa.iqmp)?;
        let py_e = utils::bytes_to_py_int(py, rsa.e)?;
        let py_n = utils::bytes_to_py_int(py, rsa.n)?;

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
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PrivateFormat,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_private_bytes(
            py,
            slf,
            &cryptography_key_parsing::PrivateKeyRef::Rsa(
                slf.borrow().serialization_key()?.components(),
            ),
            encoding,
            format,
            encryption_algorithm,
            true,
            false,
        )
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
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
        let (data, algorithm) = {
            if algorithm.is_instance(&types::NO_DIGEST_INFO.get(py)?)? {
                (
                    utils::BytesOrPyBytes::Bytes(data.as_bytes()),
                    pyo3::types::PyNone::get(py).to_owned().into_any(),
                )
            } else {
                utils::calculate_digest_and_algorithm(py, data.as_bytes(), algorithm)?
            }
        };

        let padding = signature_padding(
            py,
            padding,
            &algorithm,
            (self.pkey.bits() as usize).div_ceil(8),
            false,
        )?;
        let digest = signature_digest(py, &algorithm)?;
        if let Some(digest) = digest {
            if !self.pkey.signature_digest_supported(digest)? {
                unsupported_signature_digest(py, &algorithm)?;
            }
        }
        let data = data.as_bytes();
        let signature = signature.as_bytes();
        let valid = py
            .detach(|| match digest {
                Some(digest) => self.pkey.verify_digest(digest, data, signature, padding),
                None => self.pkey.verify_pkcs1v15_block(data, signature),
            })
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
        let parameters = encryption_parameters(py, padding)?;
        let ciphertext = py
            .detach(|| self.pkey.encrypt(plaintext, parameters.native()))
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Encryption failed"))?;
        Ok(pyo3::types::PyBytes::new(py, &ciphertext))
    }

    fn recover_data_from_signature<'p>(
        &self,
        py: pyo3::Python<'p>,
        signature: &[u8],
        padding: &pyo3::Bound<'_, pyo3::PyAny>,
        algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let algorithm = if algorithm.is_instance(&types::NO_DIGEST_INFO.get(py)?)? {
            &pyo3::types::PyNone::get(py).to_owned().into_any()
        } else {
            algorithm
        };
        if algorithm.is_instance(&types::PREHASHED.get(py)?)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "Prehashed is only supported in the sign and verify methods. It cannot be used with recover_data_from_signature.",
                ),
            ));
        }

        let padding = signature_padding(
            py,
            padding,
            algorithm,
            (self.pkey.bits() as usize).div_ceil(8),
            false,
        )?;
        if !matches!(padding, openssl_bridge::rsa::VerificationPadding::Pkcs1v15) {
            return Err(exceptions::UnsupportedAlgorithm::new_err((
                "PSS is not supported for the RSA signature operation",
                exceptions::Reasons::UNSUPPORTED_PADDING,
            ))
            .into());
        }
        let digest = signature_digest(py, algorithm)?;
        if let Some(digest) = digest {
            if !self.pkey.signature_digest_supported(digest)? {
                unsupported_signature_digest(py, algorithm)?;
            }
        }
        let recovered = self
            .pkey
            .recover_pkcs1v15(signature, digest)
            .map_err(|_| exceptions::InvalidSignature::new_err(()))?;
        Ok(pyo3::types::PyBytes::new(py, &recovered))
    }

    #[getter]
    fn key_size(&self) -> u32 {
        self.pkey.bits()
    }

    fn public_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<RsaPublicNumbers> {
        let rsa = self.pkey.export_components()?;

        let py_e = utils::bytes_to_py_int(py, &rsa.e)?;
        let py_n = utils::bytes_to_py_int(py, &rsa.n)?;

        Ok(RsaPublicNumbers {
            e: py_e.extract()?,
            n: py_n.extract()?,
        })
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_public_bytes(
            py,
            slf,
            &slf.borrow().serialization_key()?,
            encoding,
            format,
            true,
            false,
        )
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> CryptographyResult<bool> {
        let a = self.pkey.export_components()?;
        let b = other.pkey.export_components()?;
        Ok(a.n == b.n && a.e == b.e)
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
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
        let n = utils::py_int_to_bytes(py, public_numbers.n.bind(py))?;
        let e = utils::py_int_to_bytes(py, public_numbers.e.bind(py))?;
        let d = utils::py_int_to_bytes(py, self.d.bind(py))?;
        let p = utils::py_int_to_bytes(py, self.p.bind(py))?;
        let q = utils::py_int_to_bytes(py, self.q.bind(py))?;
        let dmp1 = utils::py_int_to_bytes(py, self.dmp1.bind(py))?;
        let dmq1 = utils::py_int_to_bytes(py, self.dmq1.bind(py))?;
        let iqmp = utils::py_int_to_bytes(py, self.iqmp.bind(py))?;
        private_key_from_components(
            openssl_bridge::rsa::PrivateComponents {
                n: n.as_ref(),
                e: e.as_ref(),
                d: d.as_ref(),
                p: p.as_ref(),
                q: q.as_ref(),
                dmp1: dmp1.as_ref(),
                dmq1: dmq1.as_ref(),
                iqmp: iqmp.as_ref(),
            },
            unsafe_skip_rsa_key_validation,
        )
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

fn check_public_key_components(e: &[u8], n: &[u8]) -> CryptographyResult<()> {
    let normalize = |v: &[u8]| v.iter().position(|&b| b != 0).unwrap_or(v.len());
    let e = &e[normalize(e)..];
    let n = &n[normalize(n)..];
    if n.is_empty() || (n.len() == 1 && n[0] < 3) {
        return Err(pyo3::exceptions::PyValueError::new_err("n must be >= 3.").into());
    }
    if e.is_empty()
        || (e.len() == 1 && e[0] < 3)
        || e.len().cmp(&n.len()).then_with(|| e.cmp(n)).is_ge()
    {
        return Err(pyo3::exceptions::PyValueError::new_err("e must be >= 3 and < n.").into());
    }
    if e.last().unwrap() & 1 == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err("e must be odd.").into());
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

        let n = utils::py_int_to_bytes(py, self.n.bind(py))?;
        let e = utils::py_int_to_bytes(py, self.e.bind(py))?;
        check_public_key_components(e.as_ref(), n.as_ref())?;

        public_key_from_key(openssl_bridge::rsa::PublicKey::from_components(
            n.as_ref(),
            e.as_ref(),
        )?)
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

    fn __repr__<'py>(
        &self,
        py: pyo3::Python<'py>,
    ) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::types::PyString>> {
        let e = self.e.bind(py);
        let n = self.n.bind(py);
        pyo3::types::PyString::from_fmt(py, format_args!("<RSAPublicNumbers(e={e}, n={n})>"))
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod rsa {
    #[pymodule_export]
    use super::{
        generate_private_key, RsaPrivateKey, RsaPrivateNumbers, RsaPublicKey, RsaPublicNumbers,
    };
}
