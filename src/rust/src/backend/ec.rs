// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::utils;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;
use foreign_types_shared::ForeignTypeRef;
use pyo3::basic::CompareOp;
use pyo3::ToPyObject;

#[pyo3::prelude::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ec")]
struct ECPrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
    #[pyo3(get)]
    curve: pyo3::Py<pyo3::PyAny>,
}

#[pyo3::prelude::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ec")]
struct ECPublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
    #[pyo3(get)]
    curve: pyo3::Py<pyo3::PyAny>,
}

fn curve_from_py_curve(
    py: pyo3::Python<'_>,
    py_curve: &pyo3::PyAny,
) -> CryptographyResult<openssl::ec::EcGroup> {
    let curve_name = py_curve.getattr(pyo3::intern!(py, "name"))?.extract()?;
    let nid = match curve_name {
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

        #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
        "brainpoolP256r1" => openssl::nid::Nid::BRAINPOOL_P256R1,
        #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
        "brainpoolP384r1" => openssl::nid::Nid::BRAINPOOL_P384R1,
        #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
        "brainpoolP512r1" => openssl::nid::Nid::BRAINPOOL_P512R1,

        _ => {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    format!("Curve {} is not supported", curve_name),
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
) -> CryptographyResult<&'p pyo3::PyAny> {
    let name = curve
        .curve_name()
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(
                "ECDSA keys with explicit parameters are unsupported at this time",
            )
        })?
        .short_name()?;

    if curve.asn1_flag() == openssl::ec::Asn1Flag::EXPLICIT_CURVE {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "ECDSA keys with explicit parameters are unsupported at this time",
            ),
        ));
    }

    Ok(py
        .import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.ec"
        ))?
        .getattr(pyo3::intern!(py, "_CURVE_TYPES"))?
        .extract::<&pyo3::types::PyDict>()?
        .get_item(name)
        .ok_or_else(|| {
            CryptographyError::from(exceptions::UnsupportedAlgorithm::new_err((
                format!("{} is not a supported elliptic curve", name),
                exceptions::Reasons::UNSUPPORTED_ELLIPTIC_CURVE,
            )))
        })?
        .call0()?)
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

#[pyo3::prelude::pyfunction]
fn curve_supported(py: pyo3::Python<'_>, py_curve: &pyo3::PyAny) -> bool {
    curve_from_py_curve(py, py_curve).is_ok()
}

#[pyo3::prelude::pyfunction]
fn private_key_from_ptr(py: pyo3::Python<'_>, ptr: usize) -> CryptographyResult<ECPrivateKey> {
    let pkey = unsafe { openssl::pkey::PKeyRef::from_ptr(ptr as *mut _) };
    let curve = py_curve_from_curve(py, pkey.ec_key().unwrap().group())?;
    check_key_infinity(&pkey.ec_key().unwrap())?;
    Ok(ECPrivateKey {
        pkey: pkey.to_owned(),
        curve: curve.into(),
    })
}

#[pyo3::prelude::pyfunction]
fn public_key_from_ptr(py: pyo3::Python<'_>, ptr: usize) -> CryptographyResult<ECPublicKey> {
    let pkey = unsafe { openssl::pkey::PKeyRef::from_ptr(ptr as *mut _) };
    let ec = pkey.ec_key().map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Unable to load EC key: {}", e))
    })?;
    let curve = py_curve_from_curve(py, ec.group())?;
    check_key_infinity(&ec)?;
    Ok(ECPublicKey {
        pkey: pkey.to_owned(),
        curve: curve.into(),
    })
}
#[pyo3::prelude::pyfunction]
fn generate_private_key(
    py: pyo3::Python<'_>,
    py_curve: &pyo3::PyAny,
) -> CryptographyResult<ECPrivateKey> {
    let curve = curve_from_py_curve(py, py_curve)?;
    let key = openssl::ec::EcKey::generate(&curve)?;

    Ok(ECPrivateKey {
        pkey: openssl::pkey::PKey::from_ec_key(key)?,
        curve: py_curve.into(),
    })
}

#[pyo3::prelude::pyfunction]
fn derive_private_key(
    py: pyo3::Python<'_>,
    py_private_value: &pyo3::types::PyLong,
    py_curve: &pyo3::PyAny,
) -> CryptographyResult<ECPrivateKey> {
    let curve = curve_from_py_curve(py, py_curve)?;
    let private_value = utils::py_int_to_bn(py, py_private_value)?;

    let mut point = openssl::ec::EcPoint::new(&curve)?;
    let bn_ctx = openssl::bn::BigNumContext::new()?;
    point.mul_generator(&curve, &private_value, &bn_ctx)?;
    let ec = openssl::ec::EcKey::from_private_components(&curve, &private_value, &point)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid EC key"))?;
    check_key_infinity(&ec)?;
    let pkey = openssl::pkey::PKey::from_ec_key(ec)?;

    Ok(ECPrivateKey {
        pkey,
        curve: py_curve.into(),
    })
}

#[pyo3::prelude::pyfunction]
fn from_public_bytes(
    py: pyo3::Python<'_>,
    py_curve: &pyo3::PyAny,
    data: &[u8],
) -> CryptographyResult<ECPublicKey> {
    let curve = curve_from_py_curve(py, py_curve)?;

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

fn public_key_from_numbers(
    py: pyo3::Python<'_>,
    numbers: &pyo3::PyAny,
    curve: &openssl::ec::EcGroupRef,
) -> CryptographyResult<openssl::ec::EcKey<openssl::pkey::Public>> {
    let py_x = numbers.getattr(pyo3::intern!(py, "x"))?;
    let py_y = numbers.getattr(pyo3::intern!(py, "y"))?;

    let zero = (0).to_object(py);
    if py_x.rich_compare(&zero, CompareOp::Lt)?.is_true()?
        || py_y.rich_compare(&zero, CompareOp::Lt)?.is_true()?
    {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "Invalid EC key. Both x and y must be non-negative.",
            ),
        ));
    }

    let x = utils::py_int_to_bn(py, py_x)?;
    let y = utils::py_int_to_bn(py, py_y)?;

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

#[pyo3::prelude::pyfunction]
fn from_private_numbers(
    py: pyo3::Python<'_>,
    numbers: &pyo3::PyAny,
) -> CryptographyResult<ECPrivateKey> {
    let public_numbers = numbers.getattr(pyo3::intern!(py, "public_numbers"))?;
    let py_curve = public_numbers.getattr(pyo3::intern!(py, "curve"))?;

    let curve = curve_from_py_curve(py, py_curve)?;
    let public_key = public_key_from_numbers(py, public_numbers, &curve)?;
    let private_value =
        utils::py_int_to_bn(py, numbers.getattr(pyo3::intern!(py, "private_value"))?)?;

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
        curve: py_curve.into(),
    })
}

#[pyo3::prelude::pyfunction]
fn from_public_numbers(
    py: pyo3::Python<'_>,
    numbers: &pyo3::PyAny,
) -> CryptographyResult<ECPublicKey> {
    let py_curve = numbers.getattr(pyo3::intern!(py, "curve"))?;

    let curve = curve_from_py_curve(py, py_curve)?;
    let public_key = public_key_from_numbers(py, numbers, &curve)?;

    let pkey = openssl::pkey::PKey::from_ec_key(public_key)?;

    Ok(ECPublicKey {
        pkey,
        curve: py_curve.into(),
    })
}

#[pyo3::prelude::pymethods]
impl ECPrivateKey {
    #[getter]
    fn key_size<'p>(&'p self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        self.curve.as_ref(py).getattr(pyo3::intern!(py, "key_size"))
    }

    fn exchange<'p>(
        &self,
        py: pyo3::Python<'p>,
        algorithm: &pyo3::PyAny,
        public_key: &ECPublicKey,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let ecdh_class: &pyo3::types::PyType = py
            .import(pyo3::intern!(
                py,
                "cryptography.hazmat.primitives.asymmetric.ec"
            ))?
            .getattr(pyo3::intern!(py, "ECDH"))?
            .extract()?;

        if !algorithm.is_instance(ecdh_class)? {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Unsupported EC exchange algorithm",
                    exceptions::Reasons::UNSUPPORTED_EXCHANGE_ALGORITHM,
                )),
            ));
        }

        let mut deriver = openssl::derive::Deriver::new(&self.pkey)?;
        // If `set_peer_ex` is available, we don't valid the key. This is
        // because we already validated it sufficiently when we created the
        // ECPublicKey object.
        #[cfg(CRYPTOGRAPHY_OPENSSL_300_OR_GREATER)]
        deriver
            .set_peer_ex(&public_key.pkey, false)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Error computing shared key."))?;

        #[cfg(not(CRYPTOGRAPHY_OPENSSL_300_OR_GREATER))]
        deriver
            .set_peer(&public_key.pkey)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Error computing shared key."))?;

        Ok(pyo3::types::PyBytes::new_with(py, deriver.len()?, |b| {
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
        data: &pyo3::types::PyBytes,
        algorithm: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let ecdsa_class: &pyo3::types::PyType = py
            .import(pyo3::intern!(
                py,
                "cryptography.hazmat.primitives.asymmetric.ec"
            ))?
            .getattr(pyo3::intern!(py, "ECDSA"))?
            .extract()?;

        if !algorithm.is_instance(ecdsa_class)? {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Unsupported elliptic curve signature algorithm",
                    exceptions::Reasons::UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
                )),
            ));
        }

        let (data, _): (&[u8], &pyo3::PyAny) = py
            .import(pyo3::intern!(
                py,
                "cryptography.hazmat.backends.openssl.utils"
            ))?
            .call_method1(
                pyo3::intern!(py, "_calculate_digest_and_algorithm"),
                (data, algorithm.getattr(pyo3::intern!(py, "algorithm"))?),
            )?
            .extract()?;

        let mut signer = openssl::pkey_ctx::PkeyCtx::new(&self.pkey)?;
        signer.sign_init()?;
        // TODO: This does an extra allocation and copy. This can't easily use
        // `PyBytes::new_with` because the exact length of the signature isn't
        // easily known a priori (if `r` or `s` has a leading 0, the signature
        // will be a byte or two shorter than the maximum possible length).
        let mut sig = vec![];
        signer.sign_to_vec(data, &mut sig)?;
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

    fn private_numbers<'p>(&self, py: pyo3::Python<'p>) -> CryptographyResult<&'p pyo3::PyAny> {
        let ec = self.pkey.ec_key().unwrap();

        let mut bn_ctx = openssl::bn::BigNumContext::new()?;
        let mut x = openssl::bn::BigNum::new()?;
        let mut y = openssl::bn::BigNum::new()?;
        ec.public_key()
            .affine_coordinates(ec.group(), &mut x, &mut y, &mut bn_ctx)?;
        let py_x = utils::bn_to_py_int(py, &x)?;
        let py_y = utils::bn_to_py_int(py, &y)?;

        let py_private_key = utils::bn_to_py_int(py, ec.private_key())?;

        let ec_mod = py.import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.ec"
        ))?;

        let public_numbers = ec_mod.call_method1(
            pyo3::intern!(py, "EllipticCurvePublicNumbers"),
            (py_x, py_y, self.curve.clone_ref(py)),
        )?;

        Ok(ec_mod.call_method1(
            pyo3::intern!(py, "EllipticCurvePrivateNumbers"),
            (py_private_key, public_numbers),
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
impl ECPublicKey {
    #[getter]
    fn key_size<'p>(&'p self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        self.curve.as_ref(py).getattr(pyo3::intern!(py, "key_size"))
    }

    fn verify(
        &self,
        py: pyo3::Python<'_>,
        signature: &[u8],
        data: &pyo3::types::PyBytes,
        signature_algorithm: &pyo3::PyAny,
    ) -> CryptographyResult<()> {
        let ecdsa_class: &pyo3::types::PyType = py
            .import(pyo3::intern!(
                py,
                "cryptography.hazmat.primitives.asymmetric.ec"
            ))?
            .getattr(pyo3::intern!(py, "ECDSA"))?
            .extract()?;

        if !signature_algorithm.is_instance(ecdsa_class)? {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Unsupported elliptic curve signature algorithm",
                    exceptions::Reasons::UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
                )),
            ));
        }

        let (data, _): (&[u8], &pyo3::PyAny) = py
            .import(pyo3::intern!(
                py,
                "cryptography.hazmat.backends.openssl.utils"
            ))?
            .call_method1(
                pyo3::intern!(py, "_calculate_digest_and_algorithm"),
                (
                    data,
                    signature_algorithm.getattr(pyo3::intern!(py, "algorithm"))?,
                ),
            )?
            .extract()?;

        let mut verifier = openssl::pkey_ctx::PkeyCtx::new(&self.pkey)?;
        verifier.verify_init()?;
        let valid = verifier.verify(data, signature).unwrap_or(false);
        if !valid {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err(()),
            ));
        }

        Ok(())
    }

    fn public_numbers<'p>(&self, py: pyo3::Python<'p>) -> CryptographyResult<&'p pyo3::PyAny> {
        let ec = self.pkey.ec_key().unwrap();

        let mut bn_ctx = openssl::bn::BigNumContext::new()?;
        let mut x = openssl::bn::BigNum::new()?;
        let mut y = openssl::bn::BigNum::new()?;
        ec.public_key()
            .affine_coordinates(ec.group(), &mut x, &mut y, &mut bn_ctx)?;
        let py_x = utils::bn_to_py_int(py, &x)?;
        let py_y = utils::bn_to_py_int(py, &y)?;

        let ec_mod = py.import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.ec"
        ))?;

        Ok(ec_mod.call_method1(
            pyo3::intern!(py, "EllipticCurvePublicNumbers"),
            (py_x, py_y, self.curve.clone_ref(py)),
        )?)
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
        other: pyo3::PyRef<'_, ECPublicKey>,
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
    let m = pyo3::prelude::PyModule::new(py, "ec")?;
    m.add_function(pyo3::wrap_pyfunction!(curve_supported, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(private_key_from_ptr, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(public_key_from_ptr, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(generate_private_key, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(derive_private_key, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(from_public_bytes, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(from_private_numbers, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(from_public_numbers, m)?)?;

    m.add_class::<ECPrivateKey>()?;
    m.add_class::<ECPublicKey>()?;

    Ok(m)
}
