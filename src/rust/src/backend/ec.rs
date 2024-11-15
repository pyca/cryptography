// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use pyo3::types::{PyAnyMethods, PyDictMethods};

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::x509::common::cstr_from_literal;
use crate::{exceptions, types};

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ec")]
pub(crate) struct ECPrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
    #[pyo3(get)]
    curve: pyo3::Py<pyo3::PyAny>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ec")]
pub(crate) struct ECPublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
    #[pyo3(get)]
    curve: pyo3::Py<pyo3::PyAny>,
}

fn curve_from_py_curve(
    py: pyo3::Python<'_>,
    py_curve: pyo3::Bound<'_, pyo3::PyAny>,
    allow_curve_class: bool,
) -> CryptographyResult<openssl::ec::EcGroup> {
    if !py_curve.is_instance(&types::ELLIPTIC_CURVE.get(py)?)? {
        if allow_curve_class {
            let warning_cls = types::DEPRECATED_IN_42.get(py)?;
            let message = cstr_from_literal!("Curve argument must be an instance of an EllipticCurve class. Did you pass a class by mistake? This will be an exception in a future version of cryptography");
            pyo3::PyErr::warn(py, &warning_cls, message, 1)?;
        } else {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err("curve must be an EllipticCurve instance"),
            ));
        }
    }

    let py_curve_name = py_curve.getattr(pyo3::intern!(py, "name"))?;
    let nid = match &*py_curve_name.extract::<pyo3::pybacked::PyBackedStr>()? {
        "secp192r1" => openssl::nid::Nid::X9_62_PRIME192V1,
        "secp224r1" => openssl::nid::Nid::SECP224R1,
        "secp256r1" => openssl::nid::Nid::X9_62_PRIME256V1,
        "secp384r1" => openssl::nid::Nid::SECP384R1,
        "secp521r1" => openssl::nid::Nid::SECP521R1,

        "secp256k1" => openssl::nid::Nid::SECP256K1,

        "sect233r1" => openssl::nid::Nid::SECT233R1,
        "sect283r1" => openssl::nid::Nid::SECT283R1,
        "sect409r1" => openssl::nid::Nid::SECT409R1,
        "sect571r1" => openssl::nid::Nid::SECT571R1,

        "sect163r2" => openssl::nid::Nid::SECT163R2,

        "sect163k1" => openssl::nid::Nid::SECT163K1,
        "sect233k1" => openssl::nid::Nid::SECT233K1,
        "sect283k1" => openssl::nid::Nid::SECT283K1,
        "sect409k1" => openssl::nid::Nid::SECT409K1,
        "sect571k1" => openssl::nid::Nid::SECT571K1,

        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        "brainpoolP256r1" => openssl::nid::Nid::BRAINPOOL_P256R1,
        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        "brainpoolP384r1" => openssl::nid::Nid::BRAINPOOL_P384R1,
        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        "brainpoolP512r1" => openssl::nid::Nid::BRAINPOOL_P512R1,

        curve_name => {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    format!("Curve {curve_name} is not supported"),
                    exceptions::Reasons::UNSUPPORTED_ELLIPTIC_CURVE,
                )),
            ));
        }
    };

    Ok(openssl::ec::EcGroup::from_curve_name(nid)?)
}

fn py_curve_from_curve<'p>(
    py: pyo3::Python<'p>,
    curve: &openssl::ec::EcGroupRef,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    if curve.asn1_flag() == openssl::ec::Asn1Flag::EXPLICIT_CURVE {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "ECDSA keys with explicit parameters are unsupported at this time",
            ),
        ));
    }

    let name = curve.curve_name().unwrap().short_name()?;

    types::CURVE_TYPES
        .get(py)?
        .extract::<pyo3::Bound<'_, pyo3::types::PyDict>>()?
        .get_item(name)?
        .ok_or_else(|| {
            CryptographyError::from(exceptions::UnsupportedAlgorithm::new_err((
                format!("{name} is not a supported elliptic curve"),
                exceptions::Reasons::UNSUPPORTED_ELLIPTIC_CURVE,
            )))
        })
}

fn check_key_infinity(
    ec: &openssl::ec::EcKeyRef<impl openssl::pkey::HasPublic>,
) -> CryptographyResult<()> {
    if ec.public_key().is_infinity(ec.group()) {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "Cannot load an EC public key where the point is at infinity",
            ),
        ));
    }
    Ok(())
}

#[pyo3::pyfunction]
fn curve_supported(py: pyo3::Python<'_>, py_curve: pyo3::Bound<'_, pyo3::PyAny>) -> bool {
    curve_from_py_curve(py, py_curve, false).is_ok()
}

pub(crate) fn private_key_from_pkey(
    py: pyo3::Python<'_>,
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> CryptographyResult<ECPrivateKey> {
    let curve = py_curve_from_curve(py, pkey.ec_key().unwrap().group())?;
    check_key_infinity(&pkey.ec_key().unwrap())?;
    Ok(ECPrivateKey {
        pkey: pkey.to_owned(),
        curve: curve.into(),
    })
}

pub(crate) fn public_key_from_pkey(
    py: pyo3::Python<'_>,
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> CryptographyResult<ECPublicKey> {
    let ec = pkey.ec_key()?;
    let curve = py_curve_from_curve(py, ec.group())?;
    check_key_infinity(&ec)?;
    Ok(ECPublicKey {
        pkey: pkey.to_owned(),
        curve: curve.into(),
    })
}
#[pyo3::pyfunction]
#[pyo3(signature = (curve, backend=None))]
fn generate_private_key(
    py: pyo3::Python<'_>,
    curve: pyo3::Bound<'_, pyo3::PyAny>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<ECPrivateKey> {
    let _ = backend;

    let ossl_curve = curve_from_py_curve(py, curve, true)?;
    let key = openssl::ec::EcKey::generate(&ossl_curve)?;

    Ok(ECPrivateKey {
        pkey: openssl::pkey::PKey::from_ec_key(key)?,
        curve: py_curve_from_curve(py, &ossl_curve)?.into(),
    })
}

#[pyo3::pyfunction]
fn derive_private_key(
    py: pyo3::Python<'_>,
    py_private_value: &pyo3::Bound<'_, pyo3::types::PyInt>,
    py_curve: pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<ECPrivateKey> {
    let curve = curve_from_py_curve(py, py_curve.clone(), false)?;
    let private_value = utils::py_int_to_bn(py, py_private_value)?;

    let mut point = openssl::ec::EcPoint::new(&curve)?;
    let bn_ctx = openssl::bn::BigNumContext::new()?;
    point.mul_generator(&curve, &private_value, &bn_ctx)?;
    let ec = openssl::ec::EcKey::from_private_components(&curve, &private_value, &point)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid EC key"))?;
    ec.check_key().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("Invalid EC key (key out of range, infinity, etc.)")
    })?;
    let pkey = openssl::pkey::PKey::from_ec_key(ec)?;

    Ok(ECPrivateKey {
        pkey,
        curve: py_curve.into(),
    })
}

#[pyo3::pyfunction]
fn from_public_bytes(
    py: pyo3::Python<'_>,
    py_curve: pyo3::Bound<'_, pyo3::PyAny>,
    data: &[u8],
) -> CryptographyResult<ECPublicKey> {
    let curve = curve_from_py_curve(py, py_curve.clone(), false)?;

    let mut bn_ctx = openssl::bn::BigNumContext::new()?;
    let point = openssl::ec::EcPoint::from_bytes(&curve, data, &mut bn_ctx)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid EC key."))?;
    let ec = openssl::ec::EcKey::from_public_key(&curve, &point)?;
    let pkey = openssl::pkey::PKey::from_ec_key(ec)?;

    Ok(ECPublicKey {
        pkey,
        curve: py_curve.into(),
    })
}

#[pyo3::pymethods]
impl ECPrivateKey {
    #[getter]
    fn key_size<'p>(
        &'p self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        self.curve.bind(py).getattr(pyo3::intern!(py, "key_size"))
    }

    fn exchange<'p>(
        &self,
        py: pyo3::Python<'p>,
        algorithm: pyo3::Bound<'_, pyo3::PyAny>,
        peer_public_key: &ECPublicKey,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if !algorithm.is_instance(&types::ECDH.get(py)?)? {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Unsupported EC exchange algorithm",
                    exceptions::Reasons::UNSUPPORTED_EXCHANGE_ALGORITHM,
                )),
            ));
        }

        let mut deriver = openssl::derive::Deriver::new(&self.pkey)?;
        // If `set_peer_ex` is available, we don't validate the key. This is
        // because we already validated it sufficiently when we created the
        // ECPublicKey object.
        #[cfg(CRYPTOGRAPHY_OPENSSL_300_OR_GREATER)]
        deriver
            .set_peer_ex(&peer_public_key.pkey, false)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Error computing shared key."))?;

        #[cfg(not(CRYPTOGRAPHY_OPENSSL_300_OR_GREATER))]
        deriver
            .set_peer(&peer_public_key.pkey)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Error computing shared key."))?;

        let len = deriver.len()?;
        Ok(pyo3::types::PyBytes::new_with(py, len, |b| {
            let n = deriver.derive(b).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("Error computing shared key.")
            })?;
            assert_eq!(n, b.len());
            Ok(())
        })?)
    }

    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        signature_algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if !signature_algorithm.is_instance(&types::ECDSA.get(py)?)? {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Unsupported elliptic curve signature algorithm",
                    exceptions::Reasons::UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
                )),
            ));
        }
        let bound_algorithm = signature_algorithm.getattr(pyo3::intern!(py, "algorithm"))?;
        let (data, algo) =
            utils::calculate_digest_and_algorithm(py, data.as_bytes(), &bound_algorithm)?;

        let mut signer = openssl::pkey_ctx::PkeyCtx::new(&self.pkey)?;
        signer.sign_init()?;
        cfg_if::cfg_if! {
            if #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]{
                let deterministic: bool = signature_algorithm
                    .getattr(pyo3::intern!(py, "deterministic_signing"))?
                    .extract()?;
                if deterministic {
                    let hash_function_name = algo
                        .getattr(pyo3::intern!(py, "name"))?
                        .extract::<pyo3::pybacked::PyBackedStr>()?;
                    let hash_function = openssl::md::Md::fetch(None, &hash_function_name, None)?;
                    // Setting a deterministic nonce type requires to explicitly set the hash function.
                    // See https://github.com/openssl/openssl/issues/23205
                    signer.set_signature_md(&hash_function)?;
                    signer.set_nonce_type(openssl::pkey_ctx::NonceType::DETERMINISTIC_K)?;
                } else {
                    signer.set_nonce_type(openssl::pkey_ctx::NonceType::RANDOM_K)?;
                }
            } else {
                let _ = algo;
            }
        }

        // TODO: This does an extra allocation and copy. This can't easily use
        // `PyBytes::new_with` because the exact length of the signature isn't
        // easily known a priori (if `r` or `s` has a leading 0, the signature
        // will be a byte or two shorter than the maximum possible length).
        let mut sig = vec![];
        signer.sign_to_vec(data.as_bytes(), &mut sig)?;
        Ok(pyo3::types::PyBytes::new(py, &sig))
    }

    fn public_key(&self, py: pyo3::Python<'_>) -> CryptographyResult<ECPublicKey> {
        let orig_ec = self.pkey.ec_key().unwrap();
        let ec = openssl::ec::EcKey::from_public_key(orig_ec.group(), orig_ec.public_key())?;
        let pkey = openssl::pkey::PKey::from_ec_key(ec)?;

        Ok(ECPublicKey {
            pkey,
            curve: self.curve.clone_ref(py),
        })
    }

    fn private_numbers(
        &self,
        py: pyo3::Python<'_>,
    ) -> CryptographyResult<EllipticCurvePrivateNumbers> {
        let ec = self.pkey.ec_key().unwrap();

        let mut bn_ctx = openssl::bn::BigNumContext::new()?;
        let mut x = openssl::bn::BigNum::new()?;
        let mut y = openssl::bn::BigNum::new()?;
        ec.public_key()
            .affine_coordinates(ec.group(), &mut x, &mut y, &mut bn_ctx)?;
        let py_x = utils::bn_to_py_int(py, &x)?;
        let py_y = utils::bn_to_py_int(py, &y)?;

        let py_private_key = utils::bn_to_py_int(py, ec.private_key())?;

        let public_numbers = EllipticCurvePublicNumbers {
            x: py_x.extract()?,
            y: py_y.extract()?,
            curve: self.curve.clone_ref(py),
        };

        Ok(EllipticCurvePrivateNumbers {
            private_value: py_private_key.extract()?,
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
impl ECPublicKey {
    #[getter]
    fn key_size<'p>(
        &'p self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        self.curve.bind(py).getattr(pyo3::intern!(py, "key_size"))
    }

    fn verify(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        signature_algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<()> {
        if !signature_algorithm.is_instance(&types::ECDSA.get(py)?)? {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Unsupported elliptic curve signature algorithm",
                    exceptions::Reasons::UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
                )),
            ));
        }

        let (data, _) = utils::calculate_digest_and_algorithm(
            py,
            data.as_bytes(),
            &signature_algorithm.getattr(pyo3::intern!(py, "algorithm"))?,
        )?;

        let mut verifier = openssl::pkey_ctx::PkeyCtx::new(&self.pkey)?;
        verifier.verify_init()?;
        let valid = verifier
            .verify(data.as_bytes(), signature.as_bytes())
            .unwrap_or(false);
        if !valid {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err(()),
            ));
        }

        Ok(())
    }

    fn public_numbers(
        &self,
        py: pyo3::Python<'_>,
    ) -> CryptographyResult<EllipticCurvePublicNumbers> {
        let ec = self.pkey.ec_key().unwrap();

        let mut bn_ctx = openssl::bn::BigNumContext::new()?;
        let mut x = openssl::bn::BigNum::new()?;
        let mut y = openssl::bn::BigNum::new()?;
        ec.public_key()
            .affine_coordinates(ec.group(), &mut x, &mut y, &mut bn_ctx)?;
        let py_x = utils::bn_to_py_int(py, &x)?;
        let py_y = utils::bn_to_py_int(py, &y)?;

        Ok(EllipticCurvePublicNumbers {
            x: py_x.extract()?,
            y: py_y.extract()?,
            curve: self.curve.clone_ref(py),
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

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.primitives.asymmetric.ec")]
struct EllipticCurvePrivateNumbers {
    #[pyo3(get)]
    private_value: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    public_numbers: pyo3::Py<EllipticCurvePublicNumbers>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.primitives.asymmetric.ec")]
struct EllipticCurvePublicNumbers {
    #[pyo3(get)]
    x: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    y: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    curve: pyo3::Py<pyo3::PyAny>,
}

fn public_key_from_numbers(
    py: pyo3::Python<'_>,
    numbers: &EllipticCurvePublicNumbers,
    curve: &openssl::ec::EcGroupRef,
) -> CryptographyResult<openssl::ec::EcKey<openssl::pkey::Public>> {
    if numbers.x.bind(py).lt(0)? || numbers.y.bind(py).lt(0)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "Invalid EC key. Both x and y must be non-negative.",
            ),
        ));
    }

    let x = utils::py_int_to_bn(py, numbers.x.bind(py))?;
    let y = utils::py_int_to_bn(py, numbers.y.bind(py))?;

    let mut point = openssl::ec::EcPoint::new(curve)?;
    let mut bn_ctx = openssl::bn::BigNumContext::new()?;
    point
        .set_affine_coordinates_gfp(curve, &x, &y, &mut bn_ctx)
        .map_err(|_| {
            pyo3::exceptions::PyValueError::new_err(
                "Invalid EC key. Point is not on the curve specified.",
            )
        })?;

    Ok(openssl::ec::EcKey::from_public_key(curve, &point)?)
}

#[pyo3::pymethods]
impl EllipticCurvePrivateNumbers {
    #[new]
    fn new(
        private_value: pyo3::Py<pyo3::types::PyInt>,
        public_numbers: pyo3::Py<EllipticCurvePublicNumbers>,
    ) -> EllipticCurvePrivateNumbers {
        EllipticCurvePrivateNumbers {
            private_value,
            public_numbers,
        }
    }

    #[pyo3(signature = (backend=None))]
    fn private_key(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<ECPrivateKey> {
        let _ = backend;

        let curve =
            curve_from_py_curve(py, self.public_numbers.get().curve.bind(py).clone(), false)?;
        let public_key = public_key_from_numbers(py, self.public_numbers.get(), &curve)?;
        let private_value = utils::py_int_to_bn(py, self.private_value.bind(py))?;

        let mut bn_ctx = openssl::bn::BigNumContext::new()?;
        let mut expected_pub = openssl::ec::EcPoint::new(&curve)?;
        expected_pub.mul_generator(&curve, &private_value, &bn_ctx)?;
        if !expected_pub.eq(&curve, public_key.public_key(), &mut bn_ctx)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Invalid EC key."),
            ));
        }

        let private_key = openssl::ec::EcKey::from_private_components(
            &curve,
            &private_value,
            public_key.public_key(),
        )
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid EC key."))?;

        let pkey = openssl::pkey::PKey::from_ec_key(private_key)?;

        Ok(ECPrivateKey {
            pkey,
            curve: self.public_numbers.get().curve.clone_ref(py),
        })
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        Ok(
            (**self.private_value.bind(py)).eq(other.private_value.bind(py))?
                && self
                    .public_numbers
                    .bind(py)
                    .eq(other.public_numbers.bind(py))?,
        )
    }

    fn __hash__(&self, py: pyo3::Python<'_>) -> CryptographyResult<u64> {
        let mut hasher = DefaultHasher::new();
        self.private_value.bind(py).hash()?.hash(&mut hasher);
        self.public_numbers.bind(py).hash()?.hash(&mut hasher);
        Ok(hasher.finish())
    }
}

#[pyo3::pymethods]
impl EllipticCurvePublicNumbers {
    #[new]
    fn new(
        py: pyo3::Python<'_>,
        x: pyo3::Py<pyo3::types::PyInt>,
        y: pyo3::Py<pyo3::types::PyInt>,
        curve: pyo3::Py<pyo3::PyAny>,
    ) -> CryptographyResult<EllipticCurvePublicNumbers> {
        if !curve
            .bind(py)
            .is_instance(&types::ELLIPTIC_CURVE.get(py)?)?
        {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "curve must provide the EllipticCurve interface.",
                ),
            ));
        }

        Ok(EllipticCurvePublicNumbers { x, y, curve })
    }

    #[pyo3(signature = (backend=None))]
    fn public_key(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<ECPublicKey> {
        let _ = backend;

        let curve = curve_from_py_curve(py, self.curve.bind(py).clone(), false)?;
        let public_key = public_key_from_numbers(py, self, &curve)?;

        let pkey = openssl::pkey::PKey::from_ec_key(public_key)?;

        Ok(ECPublicKey {
            pkey,
            curve: self.curve.clone_ref(py),
        })
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        Ok((**self.x.bind(py)).eq(other.x.bind(py))?
            && (**self.y.bind(py)).eq(other.y.bind(py))?
            && self
                .curve
                .bind(py)
                .getattr(pyo3::intern!(py, "name"))?
                .eq(other.curve.bind(py).getattr(pyo3::intern!(py, "name"))?)?
            && self
                .curve
                .bind(py)
                .getattr(pyo3::intern!(py, "key_size"))?
                .eq(other
                    .curve
                    .bind(py)
                    .getattr(pyo3::intern!(py, "key_size"))?)?)
    }

    fn __hash__(&self, py: pyo3::Python<'_>) -> CryptographyResult<u64> {
        let mut hasher = DefaultHasher::new();
        self.x.bind(py).hash()?.hash(&mut hasher);
        self.y.bind(py).hash()?.hash(&mut hasher);
        self.curve
            .bind(py)
            .getattr(pyo3::intern!(py, "name"))?
            .hash()?
            .hash(&mut hasher);
        self.curve
            .bind(py)
            .getattr(pyo3::intern!(py, "key_size"))?
            .hash()?
            .hash(&mut hasher);
        Ok(hasher.finish())
    }

    fn __repr__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<String> {
        let x = self.x.bind(py);
        let y = self.y.bind(py);
        let curve_name = self.curve.bind(py).getattr(pyo3::intern!(py, "name"))?;
        Ok(format!(
            "<EllipticCurvePublicNumbers(curve={curve_name}, x={x}, y={y})>"
        ))
    }
}

#[pyo3::pymodule]
pub(crate) mod ec {
    #[pymodule_export]
    use super::{
        curve_supported, derive_private_key, from_public_bytes, generate_private_key, ECPrivateKey,
        ECPublicKey, EllipticCurvePrivateNumbers, EllipticCurvePublicNumbers,
    };
}
