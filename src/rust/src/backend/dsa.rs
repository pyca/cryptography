// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyAnyMethods;

use crate::backend::{hashes, utils};
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{error, exceptions, types};
use openssl_bridge::dsa::{
    Components, ParameterMaterial, Parameters, PrivateKeyMaterial, PublicKeyMaterial,
};

fn warn_dsa_deprecated(py: pyo3::Python<'_>) -> pyo3::PyResult<()> {
    let warning_cls = types::DEPRECATED_IN_51.get(py)?;
    let message = c"DSA is deprecated and support will be removed in a future release. Use a more modern signature algorithm.";
    pyo3::PyErr::warn(py, &warning_cls, message, 1)
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.dsa",
    name = "DSAPrivateKey"
)]
pub(crate) struct DsaPrivateKey {
    pkey: PrivateKeyMaterial,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.dsa",
    name = "DSAPublicKey"
)]
pub(crate) struct DsaPublicKey {
    pkey: PublicKeyMaterial,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.dsa",
    name = "DSAParameters"
)]
struct DsaParameters {
    dsa: ParameterMaterial,
}

pub(crate) fn private_key_from_key(
    py: pyo3::Python<'_>,
    pkey: PrivateKeyMaterial,
) -> CryptographyResult<DsaPrivateKey> {
    warn_dsa_deprecated(py)?;
    Ok(DsaPrivateKey { pkey })
}

pub(crate) fn public_key_from_key(
    py: pyo3::Python<'_>,
    pkey: PublicKeyMaterial,
) -> CryptographyResult<DsaPublicKey> {
    warn_dsa_deprecated(py)?;
    Ok(DsaPublicKey { pkey })
}

#[pyo3::pyfunction]
fn generate_parameters(py: pyo3::Python<'_>, key_size: u32) -> CryptographyResult<DsaParameters> {
    let dsa = py.detach(|| Parameters::generate(key_size))?.into();
    Ok(DsaParameters { dsa })
}

fn parameters_from_numbers(
    py: pyo3::Python<'_>,
    numbers: &DsaParameterNumbers,
) -> CryptographyResult<ParameterMaterial> {
    let p = utils::py_int_to_bytes(py, numbers.p.bind(py))?;
    let q = utils::py_int_to_bytes(py, numbers.q.bind(py))?;
    let g = utils::py_int_to_bytes(py, numbers.g.bind(py))?;
    Ok(ParameterMaterial::from_components(Components {
        p: p.as_ref(),
        q: q.as_ref(),
        g: g.as_ref(),
    })?)
}
// Temporary component conversion for the shared parser/serializer.
impl DsaPrivateKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PrivateKeyRef<'_>> {
        Ok(cryptography_key_parsing::PrivateKeyRef::Dsa(&self.pkey))
    }
}
impl DsaPublicKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PublicKeyRef<'_>> {
        Ok(cryptography_key_parsing::PublicKeyRef::Dsa(&self.pkey))
    }
}

#[pyo3::pymethods]
impl DsaPrivateKey {
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let (data, algo) = utils::calculate_digest_and_algorithm(py, data.as_bytes(), &algorithm)?;

        let digest = hashes::bridge_digest_from_algorithm(py, &algo)?;
        let bytes = data.as_bytes();
        let sig = match py.detach(|| self.pkey.validate()?.sign_digest(digest, bytes)) {
            Ok(signature) => signature,
            Err(e) => {
                return Err(pyo3::exceptions::PyValueError::new_err((
                    "DSA signing failed. This generally indicates an invalid key.",
                    error::list_from_bridge_error(py, &e)?.unbind(),
                ))
                .into())
            }
        };
        Ok(pyo3::types::PyBytes::new(py, &sig))
    }

    #[getter]
    fn key_size(&self) -> i32 {
        self.pkey.parameters().bits() as i32
    }

    fn public_key(&self) -> CryptographyResult<DsaPublicKey> {
        Ok(DsaPublicKey {
            pkey: self.pkey.public_key(),
        })
    }

    fn parameters(&self) -> CryptographyResult<DsaParameters> {
        let dsa = self.pkey.parameters().clone();
        Ok(DsaParameters { dsa })
    }

    fn private_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DsaPrivateNumbers> {
        let parts = self.pkey.parameters().components();

        let py_p = utils::bytes_to_py_int(py, parts.p)?;
        let py_q = utils::bytes_to_py_int(py, parts.q)?;
        let py_g = utils::bytes_to_py_int(py, parts.g)?;

        let py_pub_key = utils::bytes_to_py_int(py, self.pkey.public_key().public_value())?;
        let py_private_key = utils::bytes_to_py_int(py, self.pkey.scalar())?;

        let parameter_numbers = DsaParameterNumbers {
            p: py_p.extract()?,
            q: py_q.extract()?,
            g: py_g.extract()?,
        };
        let public_numbers = DsaPublicNumbers {
            y: py_pub_key.extract()?,
            parameter_numbers: pyo3::Py::new(py, parameter_numbers)?,
        };
        Ok(DsaPrivateNumbers {
            x: py_private_key.extract()?,
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

#[pyo3::pymethods]
impl DsaPublicKey {
    fn verify(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<()> {
        let (data, algo) = utils::calculate_digest_and_algorithm(py, data.as_bytes(), &algorithm)?;

        let digest = hashes::bridge_digest_from_algorithm(py, &algo)?;
        let data_bytes = data.as_bytes();
        let signature = signature.as_bytes();
        let valid = py
            .detach(|| {
                self.pkey
                    .validate()?
                    .verify_digest(digest, data_bytes, signature)
            })
            .unwrap_or(false);
        if !valid {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err(()),
            ));
        }

        Ok(())
    }

    #[getter]
    fn key_size(&self) -> i32 {
        self.pkey.parameters().bits() as i32
    }

    fn parameters(&self) -> CryptographyResult<DsaParameters> {
        let dsa = self.pkey.parameters().clone();
        Ok(DsaParameters { dsa })
    }

    fn public_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DsaPublicNumbers> {
        let parts = self.pkey.parameters().components();

        let py_p = utils::bytes_to_py_int(py, parts.p)?;
        let py_q = utils::bytes_to_py_int(py, parts.q)?;
        let py_g = utils::bytes_to_py_int(py, parts.g)?;

        let py_pub_key = utils::bytes_to_py_int(py, self.pkey.public_value())?;

        let parameter_numbers = DsaParameterNumbers {
            p: py_p.extract()?,
            q: py_q.extract()?,
            g: py_g.extract()?,
        };
        Ok(DsaPublicNumbers {
            y: py_pub_key.extract()?,
            parameter_numbers: pyo3::Py::new(py, parameter_numbers)?,
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

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        let a = self.pkey.parameters().components();
        let b = other.pkey.parameters().components();
        a.p == b.p
            && a.q == b.q
            && a.g == b.g
            && self.pkey.public_value() == other.pkey.public_value()
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
impl DsaParameters {
    fn generate_private_key(&self) -> CryptographyResult<DsaPrivateKey> {
        Ok(DsaPrivateKey {
            pkey: self.dsa.validate()?.generate_key()?.into(),
        })
    }

    fn parameter_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DsaParameterNumbers> {
        let parts = self.dsa.components();
        let py_p = utils::bytes_to_py_int(py, parts.p)?;
        let py_q = utils::bytes_to_py_int(py, parts.q)?;
        let py_g = utils::bytes_to_py_int(py, parts.g)?;

        Ok(DsaParameterNumbers {
            p: py_p.extract()?,
            q: py_q.extract()?,
            g: py_g.extract()?,
        })
    }
}

fn check_dsa_parameters(
    py: pyo3::Python<'_>,
    parameters: &DsaParameterNumbers,
) -> CryptographyResult<()> {
    if ![1024, 2048, 3072, 4096].contains(
        &parameters
            .p
            .bind(py)
            .call_method0("bit_length")?
            .extract::<usize>()?,
    ) {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "p must be exactly 1024, 2048, 3072, or 4096 bits long",
            ),
        ));
    }

    if ![160, 224, 256].contains(
        &parameters
            .q
            .bind(py)
            .call_method0("bit_length")?
            .extract::<usize>()?,
    ) {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("q must be exactly 160, 224, or 256 bits long"),
        ));
    }

    if parameters.g.bind(py).le(1)? || parameters.g.bind(py).ge(parameters.p.bind(py))? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("g, p don't satisfy 1 < g < p."),
        ));
    }

    Ok(())
}

fn check_dsa_private_numbers(
    py: pyo3::Python<'_>,
    numbers: &DsaPrivateNumbers,
) -> CryptographyResult<()> {
    let params = numbers.public_numbers.get().parameter_numbers.get();
    check_dsa_parameters(py, params)?;

    if numbers.x.bind(py).le(0)? || numbers.x.bind(py).ge(params.q.bind(py))? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("x must be > 0 and < q."),
        ));
    }

    if (**numbers.public_numbers.get().y.bind(py)).ne(params
        .g
        .bind(py)
        .pow(numbers.x.bind(py), Some(params.p.bind(py)))?)?
    {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("y must be equal to (g ** x % p)."),
        ));
    }

    Ok(())
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.primitives.asymmetric.dsa",
    name = "DSAPrivateNumbers"
)]
struct DsaPrivateNumbers {
    #[pyo3(get)]
    x: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    public_numbers: pyo3::Py<DsaPublicNumbers>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.primitives.asymmetric.dsa",
    name = "DSAPublicNumbers"
)]
struct DsaPublicNumbers {
    #[pyo3(get)]
    y: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    parameter_numbers: pyo3::Py<DsaParameterNumbers>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.primitives.asymmetric.dsa",
    name = "DSAParameterNumbers"
)]
struct DsaParameterNumbers {
    #[pyo3(get)]
    p: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    q: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    g: pyo3::Py<pyo3::types::PyInt>,
}

#[pyo3::pymethods]
impl DsaPrivateNumbers {
    #[new]
    fn new(
        x: pyo3::Py<pyo3::types::PyInt>,
        public_numbers: pyo3::Py<DsaPublicNumbers>,
    ) -> DsaPrivateNumbers {
        DsaPrivateNumbers { x, public_numbers }
    }

    #[pyo3(signature = (backend=None))]
    fn private_key(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<DsaPrivateKey> {
        let _ = backend;

        let public_numbers = self.public_numbers.get();
        let parameter_numbers = public_numbers.parameter_numbers.get();

        check_dsa_private_numbers(py, self)?;

        let params = parameters_from_numbers(py, parameter_numbers)?;
        let x = utils::py_int_to_bytes(py, self.x.bind(py))?;
        let y = utils::py_int_to_bytes(py, public_numbers.y.bind(py))?;
        Ok(DsaPrivateKey {
            pkey: PrivateKeyMaterial::from_components(params, x.as_ref(), y.as_ref())?,
        })
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        Ok((**self.x.bind(py)).eq(other.x.bind(py))?
            && self
                .public_numbers
                .bind(py)
                .eq(other.public_numbers.bind(py))?)
    }
}

#[pyo3::pymethods]
impl DsaPublicNumbers {
    #[new]
    fn new(
        y: pyo3::Py<pyo3::types::PyInt>,
        parameter_numbers: pyo3::Py<DsaParameterNumbers>,
    ) -> DsaPublicNumbers {
        DsaPublicNumbers {
            y,
            parameter_numbers,
        }
    }

    #[pyo3(signature = (backend=None))]
    fn public_key(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<DsaPublicKey> {
        let _ = backend;

        let parameter_numbers = self.parameter_numbers.get();

        check_dsa_parameters(py, parameter_numbers)?;

        let params = parameters_from_numbers(py, parameter_numbers)?;
        let y = utils::py_int_to_bytes(py, self.y.bind(py))?;
        Ok(DsaPublicKey {
            pkey: PublicKeyMaterial::from_components(params, y.as_ref())?,
        })
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        Ok((**self.y.bind(py)).eq(other.y.bind(py))?
            && self
                .parameter_numbers
                .bind(py)
                .eq(other.parameter_numbers.bind(py))?)
    }

    fn __repr__<'py>(
        &self,
        py: pyo3::Python<'py>,
    ) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::types::PyString>> {
        let y = self.y.bind(py);
        let parameter_numbers = self.parameter_numbers.bind(py).repr()?;
        pyo3::types::PyString::from_fmt(
            py,
            format_args!("<DSAPublicNumbers(y={y}, parameter_numbers={parameter_numbers})>"),
        )
    }
}

#[pyo3::pymethods]
impl DsaParameterNumbers {
    #[new]
    fn new(
        p: pyo3::Py<pyo3::types::PyInt>,
        q: pyo3::Py<pyo3::types::PyInt>,
        g: pyo3::Py<pyo3::types::PyInt>,
    ) -> DsaParameterNumbers {
        DsaParameterNumbers { p, q, g }
    }

    #[pyo3(signature = (backend=None))]
    fn parameters(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<DsaParameters> {
        let _ = backend;

        check_dsa_parameters(py, self)?;

        Ok(DsaParameters {
            dsa: parameters_from_numbers(py, self)?,
        })
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        Ok((**self.p.bind(py)).eq(other.p.bind(py))?
            && (**self.q.bind(py)).eq(other.q.bind(py))?
            && (**self.g.bind(py)).eq(other.g.bind(py))?)
    }

    fn __repr__<'py>(
        &self,
        py: pyo3::Python<'py>,
    ) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::types::PyString>> {
        let p = self.p.bind(py);
        let q = self.q.bind(py);
        let g = self.g.bind(py);
        pyo3::types::PyString::from_fmt(
            py,
            format_args!("<DSAParameterNumbers(p={p}, q={q}, g={g})>"),
        )
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod dsa {
    #[pymodule_export]
    use super::{
        generate_parameters, DsaParameterNumbers, DsaParameters, DsaPrivateKey, DsaPrivateNumbers,
        DsaPublicKey, DsaPublicNumbers,
    };
}
