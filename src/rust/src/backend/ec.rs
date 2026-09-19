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
use openssl_bridge::ec::{Curve, Nonce, PointEncoding, PrivateKey, PublicKey};

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ec")]
pub(crate) struct ECPrivateKey {
    pkey: PrivateKey,
    #[pyo3(get)]
    curve: pyo3::Py<pyo3::PyAny>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ec")]
pub(crate) struct ECPublicKey {
    pkey: PublicKey,
    #[pyo3(get)]
    curve: pyo3::Py<pyo3::PyAny>,
}

fn bytes_to_int(
    py: pyo3::Python<'_>,
    bytes: &[u8],
) -> CryptographyResult<pyo3::Py<pyo3::types::PyInt>> {
    Ok(py
        .get_type::<pyo3::types::PyInt>()
        .call_method1(
            pyo3::intern!(py, "from_bytes"),
            (
                pyo3::types::PyBytes::new(py, bytes),
                pyo3::intern!(py, "big"),
            ),
        )?
        .extract()?)
}

fn curve_from_py_curve(
    py: pyo3::Python<'_>,
    py_curve: pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<Curve> {
    if !py_curve.is_instance(&types::ELLIPTIC_CURVE.get(py)?)? {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "curve must be an EllipticCurve instance",
        )
        .into());
    }
    let name = py_curve
        .getattr(pyo3::intern!(py, "name"))?
        .extract::<pyo3::pybacked::PyBackedStr>()?;
    let unsupported = || {
        exceptions::UnsupportedAlgorithm::new_err((
            format!("Curve {name} is not supported"),
            exceptions::Reasons::UNSUPPORTED_ELLIPTIC_CURVE,
        ))
    };
    let curve = Curve::from_name(&name).map_err(|_| unsupported())?;
    // Preserve the existing Python capability set while the shared codecs
    // retain their backend-specific curve support.
    #[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))]
    if matches!(
        curve,
        Curve::BrainpoolP256r1 | Curve::BrainpoolP384r1 | Curve::BrainpoolP512r1
    ) {
        return Err(unsupported().into());
    }

    if !curve.is_available() {
        return Err(unsupported().into());
    }
    Ok(curve)
}

fn py_curve_from_curve(
    py: pyo3::Python<'_>,
    curve: Curve,
) -> CryptographyResult<pyo3::Bound<'_, pyo3::PyAny>> {
    Ok(types::CURVE_TYPES.get(py)?.get_item(curve.name())?)
}

#[pyo3::pyfunction]
fn curve_supported(py: pyo3::Python<'_>, py_curve: pyo3::Bound<'_, pyo3::PyAny>) -> bool {
    curve_from_py_curve(py, py_curve).is_ok()
}

pub(crate) fn private_key_from_key(
    py: pyo3::Python<'_>,
    pkey: PrivateKey,
) -> CryptographyResult<ECPrivateKey> {
    let curve = py_curve_from_curve(py, pkey.curve())?;
    Ok(ECPrivateKey {
        pkey,
        curve: curve.into(),
    })
}

pub(crate) fn public_key_from_key(
    py: pyo3::Python<'_>,
    pkey: PublicKey,
) -> CryptographyResult<ECPublicKey> {
    let curve = py_curve_from_curve(py, pkey.curve())?;
    Ok(ECPublicKey {
        pkey,
        curve: curve.into(),
    })
}

#[pyo3::pyfunction]
#[pyo3(signature = (curve, backend=None))]
pub(crate) fn generate_private_key(
    py: pyo3::Python<'_>,
    curve: pyo3::Bound<'_, pyo3::PyAny>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<ECPrivateKey> {
    let _ = backend;

    let native_curve = curve_from_py_curve(py, curve)?;
    let pkey = py.detach(|| PrivateKey::generate(native_curve))?;
    Ok(ECPrivateKey {
        pkey,
        curve: types::CURVE_TYPES
            .get(py)?
            .get_item(native_curve.name())?
            .into(),
    })
}

#[pyo3::pyfunction]
fn derive_private_key(
    py: pyo3::Python<'_>,
    py_private_value: &pyo3::Bound<'_, pyo3::types::PyInt>,
    py_curve: pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<ECPrivateKey> {
    let curve = curve_from_py_curve(py, py_curve.clone())?;
    let private_value = utils::py_int_to_bytes(py, py_private_value)?;

    let scalar = private_value;
    let pkey = PrivateKey::from_scalar(curve, scalar.as_ref()).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("Invalid EC key (key out of range, infinity, etc.)")
    })?;
    Ok(ECPrivateKey {
        pkey,
        curve: py_curve.into(),
    })
}

#[pyo3::pyfunction]
pub(crate) fn from_public_bytes(
    py: pyo3::Python<'_>,
    py_curve: pyo3::Bound<'_, pyo3::PyAny>,
    data: &[u8],
) -> CryptographyResult<ECPublicKey> {
    let curve = curve_from_py_curve(py, py_curve.clone())?;

    let pkey = PublicKey::from_encoded(curve, data)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid EC key."))?;
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

        let secret = py
            .detach(|| self.pkey.exchange(&peer_public_key.pkey))
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Error computing shared key."))?;
        Ok(pyo3::types::PyBytes::new(py, secret.as_ref()))
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

        let md = hashes::bridge_digest_from_algorithm(py, &algo)?;
        let deterministic: bool = signature_algorithm
            .getattr(pyo3::intern!(py, "deterministic_signing"))?
            .extract()?;
        let nonce = if deterministic {
            Nonce::Deterministic
        } else {
            Nonce::Random
        };
        let bytes = data.as_bytes();
        let signature = py.detach(|| self.pkey.sign_digest(md, bytes, nonce))?;
        Ok(pyo3::types::PyBytes::new(py, &signature))
    }

    fn public_key(&self, py: pyo3::Python<'_>) -> CryptographyResult<ECPublicKey> {
        Ok(ECPublicKey {
            pkey: self.pkey.public_key()?,
            curve: self.curve.clone_ref(py),
        })
    }

    fn private_numbers(
        &self,
        py: pyo3::Python<'_>,
    ) -> CryptographyResult<EllipticCurvePrivateNumbers> {
        let public_numbers = self.public_key(py)?.public_numbers(py)?;
        let scalar = self.pkey.scalar()?;
        let private_value = bytes_to_int(py, scalar.as_ref())?;
        Ok(EllipticCurvePrivateNumbers {
            private_value,
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
            &slf.borrow().serialization_key()?,
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

// Temporary conversion for the shared legacy parser/serializer.

impl ECPublicKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PublicKeyRef<'_>> {
        Ok(cryptography_key_parsing::PublicKeyRef::Ec(&self.pkey))
    }
}

impl ECPrivateKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PrivateKeyRef<'_>> {
        Ok(cryptography_key_parsing::PrivateKeyRef::Ec(&self.pkey))
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

        let (data, algo) = utils::calculate_digest_and_algorithm(
            py,
            data.as_bytes(),
            &signature_algorithm.getattr(pyo3::intern!(py, "algorithm"))?,
        )?;

        let md = hashes::bridge_digest_from_algorithm(py, &algo)?;
        let data_bytes = data.as_bytes();
        let sig_bytes = signature.as_bytes();
        let valid = py.detach(|| self.pkey.verify_digest(md, data_bytes, sig_bytes))?;
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
        let (x, y) = self.pkey.coordinates()?;
        Ok(EllipticCurvePublicNumbers {
            x: bytes_to_int(py, &x)?,
            y: bytes_to_int(py, &y)?,
            curve: self.curve.clone_ref(py),
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
        Ok(self.pkey.curve() == other.pkey.curve()
            && self.pkey.to_encoded(PointEncoding::Compressed)?
                == other.pkey.to_encoded(PointEncoding::Compressed)?)
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
    curve: Curve,
) -> CryptographyResult<PublicKey> {
    if numbers.x.bind(py).lt(0)? || numbers.y.bind(py).lt(0)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "Invalid EC key. Both x and y must be non-negative.",
            ),
        ));
    }

    let x = utils::py_int_to_bytes(py, numbers.x.bind(py))?;
    let y = utils::py_int_to_bytes(py, numbers.y.bind(py))?;

    Ok(
        PublicKey::from_coordinates(curve, x.as_ref(), y.as_ref()).map_err(|_| {
            pyo3::exceptions::PyValueError::new_err(
                "Invalid EC key. Point is not on the curve specified.",
            )
        })?,
    )
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

        let curve = curve_from_py_curve(py, self.public_numbers.get().curve.bind(py).clone())?;
        let public_key = public_key_from_numbers(py, self.public_numbers.get(), curve)?;
        let private_value = utils::py_int_to_bytes(py, self.private_value.bind(py))?;

        let scalar = private_value;
        let pkey = PrivateKey::from_scalar(curve, scalar.as_ref())
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid EC key."))?;
        if pkey.public_key()?.to_encoded(PointEncoding::Uncompressed)?
            != public_key.to_encoded(PointEncoding::Uncompressed)?
        {
            return Err(pyo3::exceptions::PyValueError::new_err("Invalid EC key.").into());
        }
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

        let curve = curve_from_py_curve(py, self.curve.bind(py).clone())?;
        let public_key = public_key_from_numbers(py, self, curve)?;

        Ok(ECPublicKey {
            pkey: public_key,
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

    fn __repr__<'py>(
        &self,
        py: pyo3::Python<'py>,
    ) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::types::PyString>> {
        let x = self.x.bind(py);
        let y = self.y.bind(py);
        let curve_name = self.curve.bind(py).getattr(pyo3::intern!(py, "name"))?;
        pyo3::types::PyString::from_fmt(
            py,
            format_args!("<EllipticCurvePublicNumbers(curve={curve_name}, x={x}, y={y})>"),
        )
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod ec {
    #[pymodule_export]
    use super::{
        curve_supported, derive_private_key, from_public_bytes, generate_private_key, ECPrivateKey,
        ECPublicKey, EllipticCurvePrivateNumbers, EllipticCurvePublicNumbers,
    };
}
