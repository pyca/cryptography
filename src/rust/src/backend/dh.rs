// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::common;
use pyo3::types::PyAnyMethods;

use crate::asn1::encode_der_data;
use crate::backend::utils;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{types, x509};
use openssl_bridge::dh::{
    Components, Parameters, PrivateKeyMaterial as PrivateKey, PublicKeyMaterial as PublicKey,
};

fn warn_ffdh_deprecated(py: pyo3::Python<'_>) -> pyo3::PyResult<()> {
    let warning_cls = types::DEPRECATED_IN_50.get(py)?;
    let message = c"Diffie-Hellman over finite fields (FFDH) is deprecated and support will be removed in a future release. Use a more modern key exchange algorithm.";
    pyo3::PyErr::warn(py, &warning_cls, message, 1)
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.dh")]
pub(crate) struct DHPrivateKey {
    pkey: PrivateKey,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.dh")]
pub(crate) struct DHPublicKey {
    pkey: PublicKey,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.dh")]
struct DHParameters {
    dh: Parameters,
}

#[pyo3::pyfunction]
#[pyo3(signature = (generator, key_size, backend=None))]
fn generate_parameters(
    py: pyo3::Python<'_>,
    generator: u32,
    key_size: u32,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<DHParameters> {
    let _ = backend;

    if key_size < cryptography_key_parsing::MIN_DH_MODULUS_SIZE {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(format!(
                "DH key_size must be at least {} bits",
                cryptography_key_parsing::MIN_DH_MODULUS_SIZE
            )),
        ));
    }
    if generator != 2 && generator != 5 {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("DH generator must be 2 or 5"),
        ));
    }

    let dh = py
        .detach(|| Parameters::generate(key_size, generator))
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Unable to generate DH parameters"))?;
    Ok(DHParameters { dh })
}

pub(crate) fn private_key_from_key(
    py: pyo3::Python<'_>,
    pkey: PrivateKey,
) -> CryptographyResult<DHPrivateKey> {
    warn_ffdh_deprecated(py)?;
    Ok(DHPrivateKey { pkey })
}

pub(crate) fn public_key_from_key(
    py: pyo3::Python<'_>,
    pkey: PublicKey,
) -> CryptographyResult<DHPublicKey> {
    warn_ffdh_deprecated(py)?;
    Ok(DHPublicKey { pkey })
}

// Build DHParameters from the DER encoding of a parameter structure. When
// `x942` is true the optional trailing INTEGER is the X9.42 subprime `q`;
// otherwise the structure is PKCS#3 and the optional trailing INTEGER is
// `privateValueLength`, which we ignore.
fn load_dh_parameters(data: &[u8], x942: bool) -> CryptographyResult<DHParameters> {
    let parts = if x942 {
        let params = asn1::parse_single::<common::DHParams<'_>>(data)?;
        Components {
            p: params.p.as_bytes(),
            q: params.q.map(|q| q.as_bytes()),
            g: params.g.as_bytes(),
        }
    } else {
        let params = asn1::parse_single::<common::BasicDHParams<'_>>(data)?;
        Components {
            p: params.p.as_bytes(),
            q: None,
            g: params.g.as_bytes(),
        }
    };
    Ok(DHParameters {
        dh: Parameters::from_components(parts)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid DH parameters"))?,
    })
}

#[pyo3::pyfunction]
#[pyo3(signature = (data, backend=None))]
fn from_der_parameters(
    data: &[u8],
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<DHParameters> {
    let _ = backend;
    // DER carries no tag distinguishing PKCS#3 from X9.42, so we permissively
    // accept an optional trailing `q` for backwards compatibility.
    load_dh_parameters(data, true)
}

#[pyo3::pyfunction]
#[pyo3(signature = (data, backend=None))]
fn from_pem_parameters(
    data: &[u8],
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<DHParameters> {
    let _ = backend;
    let parsed = x509::find_in_pem(
        data,
        |p| p.tag() == "DH PARAMETERS" || p.tag() == "X9.42 DH PARAMETERS",
        "Valid PEM but no BEGIN DH PARAMETERS/END DH PARAMETERS delimiters. Are you sure this is a DH parameters?",
    )?;

    load_dh_parameters(parsed.contents(), parsed.tag() == "X9.42 DH PARAMETERS")
}

fn dh_parameters_from_numbers(
    py: pyo3::Python<'_>,
    numbers: &DHParameterNumbers,
) -> CryptographyResult<Parameters> {
    let p = utils::py_int_to_bytes(py, numbers.p.bind(py))?;
    let q = numbers
        .q
        .as_ref()
        .map(|q| utils::py_int_to_bytes(py, q.bind(py)))
        .transpose()?;
    let g = utils::py_int_to_bytes(py, numbers.g.bind(py))?;
    Ok(Parameters::from_components(Components {
        p: p.as_ref(),
        q: q.as_ref().map(|q| q.as_ref()),
        g: g.as_ref(),
    })
    .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid DH parameters"))?)
}
impl DHPrivateKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PrivateKeyRef<'_>> {
        Ok(cryptography_key_parsing::PrivateKeyRef::Dh(&self.pkey))
    }
}
impl DHPublicKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PublicKeyRef<'_>> {
        Ok(cryptography_key_parsing::PublicKeyRef::Dh(&self.pkey))
    }
}

#[pyo3::pymethods]
impl DHPrivateKey {
    #[getter]
    fn key_size(&self) -> i32 {
        self.pkey.parameters().bits() as i32
    }

    fn exchange<'p>(
        &self,
        py: pyo3::Python<'p>,
        peer_public_key: &DHPublicKey,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let secret = py
            .detach(|| {
                // Legacy components may contain an unrelated cached public value.
                // Agreement uses a validated key derived from the private exponent.
                openssl_bridge::dh::PrivateKey::from_scalar(
                    self.pkey.parameters().clone(),
                    self.pkey.scalar(),
                )?
                .exchange(&peer_public_key.pkey.validate()?)
            })
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Error computing shared key."))?;
        Ok(pyo3::types::PyBytes::new(py, secret.as_ref()))
    }

    fn private_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DHPrivateNumbers> {
        let parts = self.pkey.parameters().components();

        let py_p = utils::bytes_to_py_int(py, parts.p)?;
        let py_q = parts.q.map(|q| utils::bytes_to_py_int(py, q)).transpose()?;
        let py_g = utils::bytes_to_py_int(py, parts.g)?;

        let py_pub_key = utils::bytes_to_py_int(py, self.pkey.public_key().public_value())?;
        let py_private_key = utils::bytes_to_py_int(py, self.pkey.scalar())?;

        let parameter_numbers = DHParameterNumbers {
            p: py_p.extract()?,
            q: py_q
                .map(|q| q.extract().map_err(CryptographyError::from))
                .transpose()?,
            g: py_g.extract()?,
        };
        let public_numbers = DHPublicNumbers {
            y: py_pub_key.extract()?,
            parameter_numbers: pyo3::Py::new(py, parameter_numbers)?,
        };

        Ok(DHPrivateNumbers {
            x: py_private_key.extract()?,
            public_numbers: pyo3::Py::new(py, public_numbers)?,
        })
    }

    #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
    fn public_key(&self) -> CryptographyResult<DHPublicKey> {
        Ok(DHPublicKey {
            pkey: self.pkey.public_key(),
        })
    }

    fn parameters(&self) -> CryptographyResult<DHParameters> {
        Ok(DHParameters {
            dh: self.pkey.parameters().clone(),
        })
    }

    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PrivateFormat,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if format != crate::serialization::PrivateFormat::PKCS8 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "DH private keys support only PKCS8 serialization",
                ),
            ));
        }

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
impl DHPublicKey {
    #[getter]
    fn key_size(&self) -> i32 {
        self.pkey.parameters().bits() as i32
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if format != crate::serialization::PublicFormat::SubjectPublicKeyInfo {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "DH public keys support only SubjectPublicKeyInfo serialization",
                ),
            ));
        }

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

    fn parameters(&self) -> CryptographyResult<DHParameters> {
        Ok(DHParameters {
            dh: self.pkey.parameters().clone(),
        })
    }

    fn public_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DHPublicNumbers> {
        let parts = self.pkey.parameters().components();

        let py_p = utils::bytes_to_py_int(py, parts.p)?;
        let py_q = parts.q.map(|q| utils::bytes_to_py_int(py, q)).transpose()?;
        let py_g = utils::bytes_to_py_int(py, parts.g)?;

        let py_pub_key = utils::bytes_to_py_int(py, self.pkey.public_value())?;

        let parameter_numbers = DHParameterNumbers {
            p: py_p.extract()?,
            q: py_q
                .map(|q| q.extract().map_err(CryptographyError::from))
                .transpose()?,
            g: py_g.extract()?,
        };

        Ok(DHPublicNumbers {
            y: py_pub_key.extract()?,
            parameter_numbers: pyo3::Py::new(py, parameter_numbers)?,
        })
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
        _memo: &pyo3::Bound<'p, pyo3::types::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }
}

#[pyo3::pymethods]
impl DHParameters {
    #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
    fn generate_private_key(&self) -> CryptographyResult<DHPrivateKey> {
        Ok(DHPrivateKey {
            pkey: self.dh.generate_key()?.into(),
        })
    }

    fn parameter_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DHParameterNumbers> {
        let parts = self.dh.components();

        let py_p = utils::bytes_to_py_int(py, parts.p)?;
        let py_q = parts.q.map(|q| utils::bytes_to_py_int(py, q)).transpose()?;
        let py_g = utils::bytes_to_py_int(py, parts.g)?;

        Ok(DHParameterNumbers {
            p: py_p.extract()?,
            q: py_q
                .map(|q| q.extract().map_err(CryptographyError::from))
                .transpose()?,
            g: py_g.extract()?,
        })
    }

    fn parameter_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::ParameterFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let parts = self.dh.components();

        match format {
            crate::serialization::ParameterFormat::PKCS3 => {}
        }

        let p_bytes = cryptography_key_parsing::utils::integer_bytes(parts.p);
        let q_bytes = parts.q.map(cryptography_key_parsing::utils::integer_bytes);
        let g_bytes = cryptography_key_parsing::utils::integer_bytes(parts.g);
        let asn1dh_params = common::DHParams {
            p: asn1::BigUint::new(p_bytes.as_ref()).unwrap(),
            q: q_bytes
                .as_ref()
                .map(|q| asn1::BigUint::new(q.as_ref()).unwrap()),
            g: asn1::BigUint::new(g_bytes.as_ref()).unwrap(),
        };
        let data = asn1::write_single(&asn1dh_params)?;
        let tag = if q_bytes.is_none() {
            "DH PARAMETERS"
        } else {
            "X9.42 DH PARAMETERS"
        };
        encode_der_data(py, tag.to_string(), data, encoding)
    }
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.primitives.asymmetric.dh")]
struct DHPrivateNumbers {
    #[pyo3(get)]
    x: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    public_numbers: pyo3::Py<DHPublicNumbers>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.primitives.asymmetric.dh")]
struct DHPublicNumbers {
    #[pyo3(get)]
    y: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    parameter_numbers: pyo3::Py<DHParameterNumbers>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.primitives.asymmetric.dh")]
struct DHParameterNumbers {
    #[pyo3(get)]
    p: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    g: pyo3::Py<pyo3::types::PyInt>,
    #[pyo3(get)]
    q: Option<pyo3::Py<pyo3::types::PyInt>>,
}

#[pyo3::pymethods]
impl DHPrivateNumbers {
    #[new]
    fn new(
        x: pyo3::Py<pyo3::types::PyInt>,
        public_numbers: pyo3::Py<DHPublicNumbers>,
    ) -> DHPrivateNumbers {
        DHPrivateNumbers { x, public_numbers }
    }

    #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
    #[pyo3(signature = (backend=None))]
    fn private_key(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<DHPrivateKey> {
        let _ = backend;

        let dh = dh_parameters_from_numbers(py, self.public_numbers.get().parameter_numbers.get())?;

        let pub_key = utils::py_int_to_bytes(py, self.public_numbers.get().y.bind(py))?;
        let priv_key = utils::py_int_to_bytes(py, self.x.bind(py))?;

        let secret = priv_key;
        let pkey = PrivateKey::from_components(dh, secret.as_ref(), pub_key.as_ref())
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid DH key"))?;
        Ok(DHPrivateKey { pkey })
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
impl DHPublicNumbers {
    #[new]
    fn new(
        y: pyo3::Py<pyo3::types::PyInt>,
        parameter_numbers: pyo3::Py<DHParameterNumbers>,
    ) -> DHPublicNumbers {
        DHPublicNumbers {
            y,
            parameter_numbers,
        }
    }

    #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
    #[pyo3(signature = (backend=None))]
    fn public_key(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<DHPublicKey> {
        let _ = backend;

        let dh = dh_parameters_from_numbers(py, self.parameter_numbers.get())?;

        let pub_key = utils::py_int_to_bytes(py, self.y.bind(py))?;

        let pkey = PublicKey::from_components(dh, pub_key.as_ref())
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid DH key"))?;

        Ok(DHPublicKey { pkey })
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
}

#[pyo3::pymethods]
impl DHParameterNumbers {
    #[new]
    #[pyo3(signature = (p, g, q=None))]
    fn new(
        py: pyo3::Python<'_>,
        p: pyo3::Py<pyo3::types::PyInt>,
        g: pyo3::Py<pyo3::types::PyInt>,
        q: Option<pyo3::Py<pyo3::types::PyInt>>,
    ) -> CryptographyResult<DHParameterNumbers> {
        if g.bind(py).lt(2)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("DH generator must be 2 or greater"),
            ));
        }

        if p.bind(py)
            .call_method0("bit_length")?
            .lt(cryptography_key_parsing::MIN_DH_MODULUS_SIZE)?
        {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "p (modulus) must be at least {}-bit",
                    cryptography_key_parsing::MIN_DH_MODULUS_SIZE
                )),
            ));
        }

        Ok(DHParameterNumbers { p, g, q })
    }

    #[pyo3(signature = (backend=None))]
    fn parameters(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<DHParameters> {
        let _ = backend;

        let dh = dh_parameters_from_numbers(py, self)?;
        Ok(DHParameters { dh })
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        let q_equal = match (self.q.as_ref(), other.q.as_ref()) {
            (Some(self_q), Some(other_q)) => (**self_q.bind(py)).eq(other_q.bind(py))?,
            (None, None) => true,
            _ => false,
        };
        Ok((**self.p.bind(py)).eq(other.p.bind(py))?
            && (**self.g.bind(py)).eq(other.g.bind(py))?
            && q_equal)
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod dh {
    #[pymodule_export]
    use super::{
        from_der_parameters, from_pem_parameters, generate_parameters, DHParameterNumbers,
        DHParameters, DHPrivateKey, DHPrivateNumbers, DHPublicKey, DHPublicNumbers,
    };
}
