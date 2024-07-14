// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::common;

use crate::asn1::encode_der_data;
use crate::backend::utils;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{types, x509};
use pyo3::types::PyAnyMethods;

const MIN_MODULUS_SIZE: u32 = 512;

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.dh")]
pub(crate) struct DHPrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.dh")]
pub(crate) struct DHPublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.dh")]
struct DHParameters {
    dh: openssl::dh::Dh<openssl::pkey::Params>,
}

#[pyo3::pyfunction]
#[pyo3(signature = (generator, key_size, backend=None))]
fn generate_parameters(
    generator: u32,
    key_size: u32,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<DHParameters> {
    let _ = backend;

    if key_size < MIN_MODULUS_SIZE {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(format!(
                "DH key_size must be at least {MIN_MODULUS_SIZE} bits"
            )),
        ));
    }
    if generator != 2 && generator != 5 {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("DH generator must be 2 or 5"),
        ));
    }

    let dh = openssl::dh::Dh::generate_params(key_size, generator)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Unable to generate DH parameters"))?;
    Ok(DHParameters { dh })
}

pub(crate) fn private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> DHPrivateKey {
    DHPrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> DHPublicKey {
    DHPublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
#[pyo3(signature = (data, backend=None))]
fn from_der_parameters(
    data: &[u8],
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<DHParameters> {
    let _ = backend;
    let asn1_params = asn1::parse_single::<common::DHParams<'_>>(data)?;

    let p = openssl::bn::BigNum::from_slice(asn1_params.p.as_bytes())?;
    let q = asn1_params
        .q
        .map(|q| openssl::bn::BigNum::from_slice(q.as_bytes()))
        .transpose()?;
    let g = openssl::bn::BigNum::from_slice(asn1_params.g.as_bytes())?;

    Ok(DHParameters {
        dh: openssl::dh::Dh::from_pqg(p, q, g)?,
    })
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

    from_der_parameters(parsed.contents(), None)
}

fn dh_parameters_from_numbers(
    py: pyo3::Python<'_>,
    numbers: &DHParameterNumbers,
) -> CryptographyResult<openssl::dh::Dh<openssl::pkey::Params>> {
    let p = utils::py_int_to_bn(py, numbers.p.bind(py))?;
    let q = numbers
        .q
        .as_ref()
        .map(|v| utils::py_int_to_bn(py, v.bind(py)))
        .transpose()?;
    let g = utils::py_int_to_bn(py, numbers.g.bind(py))?;

    Ok(openssl::dh::Dh::from_pqg(p, q, g)?)
}

fn clone_dh<T: openssl::pkey::HasParams>(
    dh: &openssl::dh::Dh<T>,
) -> CryptographyResult<openssl::dh::Dh<openssl::pkey::Params>> {
    let p = dh.prime_p().to_owned()?;
    let q = dh.prime_q().map(|q| q.to_owned()).transpose()?;
    let g = dh.generator().to_owned()?;
    Ok(openssl::dh::Dh::from_pqg(p, q, g)?)
}

#[pyo3::pymethods]
impl DHPrivateKey {
    #[getter]
    fn key_size(&self) -> i32 {
        self.pkey.dh().unwrap().prime_p().num_bits()
    }

    fn exchange<'p>(
        &self,
        py: pyo3::Python<'p>,
        peer_public_key: &DHPublicKey,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut deriver = openssl::derive::Deriver::new(&self.pkey)?;
        deriver
            .set_peer(&peer_public_key.pkey)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Error computing shared key."))?;

        let len = deriver.len()?;
        Ok(pyo3::types::PyBytes::new_bound_with(py, len, |b| {
            let n = deriver.derive(b).unwrap();

            let pad = b.len() - n;
            if pad > 0 {
                b.copy_within(0..n, pad);
                for c in b.iter_mut().take(pad) {
                    *c = 0;
                }
            }
            Ok(())
        })?)
    }

    fn private_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DHPrivateNumbers> {
        let dh = self.pkey.dh().unwrap();

        let py_p = utils::bn_to_py_int(py, dh.prime_p())?;
        let py_q = dh
            .prime_q()
            .map(|q| utils::bn_to_py_int(py, q))
            .transpose()?;
        let py_g = utils::bn_to_py_int(py, dh.generator())?;

        let py_pub_key = utils::bn_to_py_int(py, dh.public_key())?;
        let py_private_key = utils::bn_to_py_int(py, dh.private_key())?;

        let parameter_numbers = DHParameterNumbers {
            p: py_p.extract()?,
            q: py_q.map(|q| q.extract()).transpose()?,
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
        let orig_dh = self.pkey.dh().unwrap();
        let dh = clone_dh(&orig_dh)?;

        let pkey =
            openssl::pkey::PKey::from_dh(dh.set_public_key(orig_dh.public_key().to_owned()?)?)?;

        Ok(DHPublicKey { pkey })
    }

    fn parameters(&self) -> CryptographyResult<DHParameters> {
        Ok(DHParameters {
            dh: clone_dh(&self.pkey.dh().unwrap())?,
        })
    }

    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: &pyo3::Bound<'p, pyo3::PyAny>,
        format: &pyo3::Bound<'p, pyo3::PyAny>,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if !format.is(&types::PRIVATE_FORMAT_PKCS8.get(py)?) {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "DH private keys support only PKCS8 serialization",
                ),
            ));
        }

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
impl DHPublicKey {
    #[getter]
    fn key_size(&self) -> i32 {
        self.pkey.dh().unwrap().prime_p().num_bits()
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: &pyo3::Bound<'p, pyo3::PyAny>,
        format: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if !format.is(&types::PUBLIC_FORMAT_SUBJECT_PUBLIC_KEY_INFO.get(py)?) {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "DH public keys support only SubjectPublicKeyInfo serialization",
                ),
            ));
        }

        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, true, false)
    }

    fn parameters(&self) -> CryptographyResult<DHParameters> {
        Ok(DHParameters {
            dh: clone_dh(&self.pkey.dh().unwrap())?,
        })
    }

    fn public_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DHPublicNumbers> {
        let dh = self.pkey.dh().unwrap();

        let py_p = utils::bn_to_py_int(py, dh.prime_p())?;
        let py_q = dh
            .prime_q()
            .map(|q| utils::bn_to_py_int(py, q))
            .transpose()?;
        let py_g = utils::bn_to_py_int(py, dh.generator())?;

        let py_pub_key = utils::bn_to_py_int(py, dh.public_key())?;

        let parameter_numbers = DHParameterNumbers {
            p: py_p.extract()?,
            q: py_q.map(|q| q.extract()).transpose()?,
            g: py_g.extract()?,
        };

        Ok(DHPublicNumbers {
            y: py_pub_key.extract()?,
            parameter_numbers: pyo3::Py::new(py, parameter_numbers)?,
        })
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.pkey.public_eq(&other.pkey)
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }
}

#[pyo3::pymethods]
impl DHParameters {
    #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
    fn generate_private_key(&self) -> CryptographyResult<DHPrivateKey> {
        let dh = clone_dh(&self.dh)?.generate_key()?;
        Ok(DHPrivateKey {
            pkey: openssl::pkey::PKey::from_dh(dh)?,
        })
    }

    fn parameter_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DHParameterNumbers> {
        let py_p = utils::bn_to_py_int(py, self.dh.prime_p())?;
        let py_q = self
            .dh
            .prime_q()
            .map(|q| utils::bn_to_py_int(py, q))
            .transpose()?;
        let py_g = utils::bn_to_py_int(py, self.dh.generator())?;

        Ok(DHParameterNumbers {
            p: py_p.extract()?,
            q: py_q.map(|q| q.extract()).transpose()?,
            g: py_g.extract()?,
        })
    }

    fn parameter_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: pyo3::Bound<'p, pyo3::PyAny>,
        format: pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if !format.is(&types::PARAMETER_FORMAT_PKCS3.get(py)?) {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Only PKCS3 serialization is supported"),
            ));
        }

        let p_bytes = utils::bn_to_big_endian_bytes(self.dh.prime_p())?;
        let q_bytes = self
            .dh
            .prime_q()
            .map(utils::bn_to_big_endian_bytes)
            .transpose()?;
        let g_bytes = utils::bn_to_big_endian_bytes(self.dh.generator())?;
        let asn1dh_params = common::DHParams {
            p: asn1::BigUint::new(&p_bytes).unwrap(),
            q: q_bytes.as_ref().map(|q| asn1::BigUint::new(q).unwrap()),
            g: asn1::BigUint::new(&g_bytes).unwrap(),
        };
        let data = asn1::write_single(&asn1dh_params)?;
        let tag = if q_bytes.is_none() {
            "DH PARAMETERS"
        } else {
            "X9.42 DH PARAMETERS"
        };
        encode_der_data(py, tag.to_string(), data, &encoding)
    }
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.primitives.asymmetric.dh")]
struct DHPrivateNumbers {
    #[pyo3(get)]
    x: pyo3::Py<pyo3::types::PyLong>,
    #[pyo3(get)]
    public_numbers: pyo3::Py<DHPublicNumbers>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.primitives.asymmetric.dh")]
struct DHPublicNumbers {
    #[pyo3(get)]
    y: pyo3::Py<pyo3::types::PyLong>,
    #[pyo3(get)]
    parameter_numbers: pyo3::Py<DHParameterNumbers>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.primitives.asymmetric.dh")]
struct DHParameterNumbers {
    #[pyo3(get)]
    p: pyo3::Py<pyo3::types::PyLong>,
    #[pyo3(get)]
    g: pyo3::Py<pyo3::types::PyLong>,
    #[pyo3(get)]
    q: Option<pyo3::Py<pyo3::types::PyLong>>,
}

#[pyo3::pymethods]
impl DHPrivateNumbers {
    #[new]
    fn new(
        x: pyo3::Py<pyo3::types::PyLong>,
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

        let pub_key = utils::py_int_to_bn(py, self.public_numbers.get().y.bind(py))?;
        let priv_key = utils::py_int_to_bn(py, self.x.bind(py))?;

        let dh = dh.set_key(pub_key, priv_key)?;
        if !dh.check_key()? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "DH private numbers did not pass safety checks.",
                ),
            ));
        }

        let pkey = openssl::pkey::PKey::from_dh(dh)?;
        Ok(DHPrivateKey { pkey })
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        Ok(self.x.bind(py).eq(other.x.bind(py))?
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
        y: pyo3::Py<pyo3::types::PyLong>,
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

        let pub_key = utils::py_int_to_bn(py, self.y.bind(py))?;

        let pkey = openssl::pkey::PKey::from_dh(dh.set_public_key(pub_key)?)?;

        Ok(DHPublicKey { pkey })
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        Ok(self.y.bind(py).eq(other.y.bind(py))?
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
        p: pyo3::Py<pyo3::types::PyLong>,
        g: pyo3::Py<pyo3::types::PyLong>,
        q: Option<pyo3::Py<pyo3::types::PyLong>>,
    ) -> CryptographyResult<DHParameterNumbers> {
        if g.bind(py).lt(2)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("DH generator must be 2 or greater"),
            ));
        }

        if p.bind(py)
            .call_method0("bit_length")?
            .lt(MIN_MODULUS_SIZE)?
        {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "p (modulus) must be at least {MIN_MODULUS_SIZE}-bit"
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
            (Some(self_q), Some(other_q)) => self_q.bind(py).eq(other_q.bind(py))?,
            (None, None) => true,
            _ => false,
        };
        Ok(self.p.bind(py).eq(other.p.bind(py))?
            && self.g.bind(py).eq(other.g.bind(py))?
            && q_equal)
    }
}

#[pyo3::pymodule]
pub(crate) mod dh {
    #[pymodule_export]
    use super::{
        from_der_parameters, from_pem_parameters, generate_parameters, DHParameterNumbers,
        DHParameters, DHPrivateKey, DHPrivateNumbers, DHPublicKey, DHPublicNumbers,
    };
}
