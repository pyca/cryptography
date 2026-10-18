// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Finite-field Diffie-Hellman on verified-garbage. Its parameter checks
//! are structural and algebraic (an odd `p` of 512 to 8192 bits,
//! `1 < g < p - 1`, and with `q`: `q | p - 1` and `g^q mod p = 1`); unlike
//! OpenSSL's `DH_check`, it does not test `p` (or `q`) for primality.

use cryptography_key_parsing::raw;
use cryptography_x509::common;
use pyo3::types::PyAnyMethods;
use verified_garbage::ffdh;

use crate::asn1::encode_der_data;
use crate::backend::dsa::y_from_x;
use crate::backend::ec::{trim_zeros, wipe};
use crate::backend::utils;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{types, x509};

fn warn_ffdh_deprecated(py: pyo3::Python<'_>) -> pyo3::PyResult<()> {
    let warning_cls = types::DEPRECATED_IN_50.get(py)?;
    let message = c"Diffie-Hellman over finite fields (FFDH) is deprecated and support will be removed in a future release. Use a more modern key exchange algorithm.";
    pyo3::PyErr::warn(py, &warning_cls, message, 1)
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.dh")]
pub(crate) struct DHPrivateKey {
    key: ffdh::PrivateKey,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.dh")]
pub(crate) struct DHPublicKey {
    key: ffdh::PublicKey,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.dh")]
struct DHParameters {
    params: ffdh::Parameters,
}

fn invalid_parameters() -> CryptographyError {
    CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
        "Invalid DH parameters",
    ))
}

fn invalid_key() -> CryptographyError {
    CryptographyError::from(pyo3::exceptions::PyValueError::new_err("Invalid DH key"))
}

/// Checked parameters: the modulus minimum cryptography enforces on every
/// path, then verified-garbage's checks.
fn check_dh_parameters(
    p: &[u8],
    g: &[u8],
    q: Option<&[u8]>,
) -> CryptographyResult<ffdh::Parameters> {
    let p = trim_zeros(p);
    let bits = p
        .first()
        .map_or(0, |&b| 8 * p.len() - b.leading_zeros() as usize);
    if bits < cryptography_key_parsing::MIN_DH_MODULUS_SIZE as usize {
        return Err(invalid_parameters());
    }
    ffdh::Parameters::from_components(p, g, q).map_err(|_| invalid_parameters())
}

fn raw_parameters(params: &ffdh::Parameters) -> raw::DhParameters {
    let (p, g, q) = params.components();
    raw::DhParameters {
        p: p.to_vec(),
        g: g.to_vec(),
        q: q.map(<[u8]>::to_vec),
    }
}

/// The key object of a parsed DH private key, whose `y` (which PKCS #8
/// omits) is computed (`y_from_x`) and checked by verified-garbage.
pub(crate) fn private_key_from_raw(
    py: pyo3::Python<'_>,
    key: &raw::DhPrivateKey,
) -> CryptographyResult<DHPrivateKey> {
    let params = check_dh_parameters(&key.params.p, &key.params.g, key.params.q.as_deref())?;
    let (p, g, _) = params.components();
    let y = y_from_x(py, p, g, &key.x)?;
    let key = ffdh::PrivateKey::from_components(&params, &y, &key.x).map_err(|_| invalid_key())?;
    warn_ffdh_deprecated(py)?;
    Ok(DHPrivateKey { key })
}

/// The key object of a parsed DH public key.
pub(crate) fn public_key_from_raw(
    py: pyo3::Python<'_>,
    key: &raw::DhPublicKey,
) -> CryptographyResult<DHPublicKey> {
    let params = check_dh_parameters(&key.params.p, &key.params.g, key.params.q.as_deref())?;
    let key = ffdh::PublicKey::from_components(&params, &key.y).map_err(|_| invalid_key())?;
    warn_ffdh_deprecated(py)?;
    Ok(DHPublicKey { key })
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

    let params = py
        .detach(|| ffdh::Parameters::generate(key_size as usize, generator))
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Unable to generate DH parameters"))?;
    Ok(DHParameters { params })
}

// Build DHParameters from the DER encoding of a parameter structure. When
// `x942` is true the optional trailing INTEGER is the X9.42 subprime `q`;
// otherwise the structure is PKCS#3 and the optional trailing INTEGER is
// `privateValueLength`, which we ignore.
fn load_dh_parameters(data: &[u8], x942: bool) -> CryptographyResult<DHParameters> {
    let params = if x942 {
        let asn1_params = asn1::parse_single::<common::DHParams<'_>>(data)?;
        check_dh_parameters(
            asn1_params.p.as_bytes(),
            asn1_params.g.as_bytes(),
            asn1_params.q.as_ref().map(|q| q.as_bytes()),
        )?
    } else {
        let asn1_params = asn1::parse_single::<common::BasicDHParams<'_>>(data)?;
        check_dh_parameters(asn1_params.p.as_bytes(), asn1_params.g.as_bytes(), None)?
    };
    Ok(DHParameters { params })
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
) -> CryptographyResult<ffdh::Parameters> {
    let p = utils::py_int_to_be_bytes(py, numbers.p.bind(py))?;
    let q = numbers
        .q
        .as_ref()
        .map(|v| utils::py_int_to_be_bytes(py, v.bind(py)))
        .transpose()?;
    let g = utils::py_int_to_be_bytes(py, numbers.g.bind(py))?;

    check_dh_parameters(&p, &g, q.as_deref())
}

fn parameter_numbers(
    py: pyo3::Python<'_>,
    params: &ffdh::Parameters,
) -> CryptographyResult<DHParameterNumbers> {
    let (p, g, q) = params.components();
    Ok(DHParameterNumbers {
        p: utils::be_bytes_to_py_int(py, p)?.extract()?,
        q: q.map(|q| -> CryptographyResult<pyo3::Py<pyo3::types::PyInt>> {
            Ok(utils::be_bytes_to_py_int(py, q)?.extract()?)
        })
        .transpose()?,
        g: utils::be_bytes_to_py_int(py, g)?.extract()?,
    })
}

#[pyo3::pymethods]
impl DHPrivateKey {
    #[getter]
    fn key_size(&self) -> usize {
        self.key.public_key().parameters().key_size()
    }

    fn exchange<'p>(
        &self,
        py: pyo3::Python<'p>,
        peer_public_key: &DHPublicKey,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        // The secret is as long as the modulus, with its leading zeros.
        let mut z = self
            .key
            .exchange(&peer_public_key.key)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Error computing shared key."))?;
        let result = pyo3::types::PyBytes::new(py, &z);
        wipe(&mut z);
        Ok(result)
    }

    fn private_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DHPrivateNumbers> {
        let public = self.key.public_key();
        let public_numbers = DHPublicNumbers {
            y: utils::be_bytes_to_py_int(py, public.component())?.extract()?,
            parameter_numbers: pyo3::Py::new(py, parameter_numbers(py, public.parameters())?)?,
        };

        Ok(DHPrivateNumbers {
            x: utils::be_bytes_to_py_int(py, self.key.private_component())?.extract()?,
            public_numbers: pyo3::Py::new(py, public_numbers)?,
        })
    }

    fn public_key(&self) -> DHPublicKey {
        DHPublicKey {
            key: self.key.public_key().clone(),
        }
    }

    fn parameters(&self) -> DHParameters {
        DHParameters {
            params: self.key.public_key().parameters().clone(),
        }
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

        let key = &slf.get().key;
        let raw_key = raw::PrivateKey::Dh(raw::DhPrivateKey {
            params: raw_parameters(key.public_key().parameters()),
            x: trim_zeros(key.private_component()).to_vec(),
        });
        utils::raw_private_bytes(
            py,
            slf,
            &raw_key,
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
    fn key_size(&self) -> usize {
        self.key.parameters().key_size()
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

        let key = &slf.get().key;
        let raw_key = raw::PublicKey::Dh(raw::DhPublicKey {
            params: raw_parameters(key.parameters()),
            y: key.component().to_vec(),
        });
        utils::raw_public_bytes(py, slf, &raw_key, encoding, format, true, false)
    }

    fn parameters(&self) -> DHParameters {
        DHParameters {
            params: self.key.parameters().clone(),
        }
    }

    fn public_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DHPublicNumbers> {
        Ok(DHPublicNumbers {
            y: utils::be_bytes_to_py_int(py, self.key.component())?.extract()?,
            parameter_numbers: pyo3::Py::new(py, parameter_numbers(py, self.key.parameters())?)?,
        })
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.key == other.key
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
    fn generate_private_key(&self) -> CryptographyResult<DHPrivateKey> {
        let key = self
            .params
            .generate_private_key()
            .map_err(|_| CryptographyError::VerifiedGarbage("DH key generation failed"))?;
        Ok(DHPrivateKey { key })
    }

    fn parameter_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DHParameterNumbers> {
        parameter_numbers(py, &self.params)
    }

    fn parameter_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::ParameterFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        match format {
            crate::serialization::ParameterFormat::PKCS3 => {}
        }

        let (p, g, q) = self.params.components();
        let asn1dh_params = common::DHParams {
            p: asn1::BigUint::new(p).unwrap(),
            q: q.map(|q| asn1::BigUint::new(q).unwrap()),
            g: asn1::BigUint::new(g).unwrap(),
        };
        let data = asn1::write_single(&asn1dh_params)?;
        let tag = if q.is_none() {
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

    #[pyo3(signature = (backend=None))]
    fn private_key(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<DHPrivateKey> {
        let _ = backend;

        let public_numbers = self.public_numbers.get();
        let params = dh_parameters_from_numbers(py, public_numbers.parameter_numbers.get())?;
        if public_numbers.y.bind(py).lt(0)? || self.x.bind(py).lt(0)? {
            return Err(invalid_key());
        }

        let y = utils::py_int_to_be_bytes(py, public_numbers.y.bind(py))?;
        let mut x = utils::py_int_to_be_bytes(py, self.x.bind(py))?;
        // verified-garbage checks that `y = g^x mod p`.
        let key = ffdh::PrivateKey::from_components(&params, &y, &x);
        wipe(&mut x);
        Ok(DHPrivateKey {
            key: key.map_err(|_| invalid_key())?,
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

    #[pyo3(signature = (backend=None))]
    fn public_key(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<DHPublicKey> {
        let _ = backend;

        let params = dh_parameters_from_numbers(py, self.parameter_numbers.get())?;
        if self.y.bind(py).lt(0)? {
            return Err(invalid_key());
        }
        let y = utils::py_int_to_be_bytes(py, self.y.bind(py))?;
        let key = ffdh::PublicKey::from_components(&params, &y).map_err(|_| invalid_key())?;
        Ok(DHPublicKey { key })
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

        let params = dh_parameters_from_numbers(py, self)?;
        Ok(DHParameters { params })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s = if s.len() % 2 == 1 {
            format!("0{s}")
        } else {
            s.to_string()
        };
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5114's groups with their subgroup orders: the keys load, `y` is
    /// what `y_from_x` computes, and both exchanges give `Z`.
    #[test]
    fn rfc5114_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/cryptography_vectors/asymmetric/DH/RFC5114.txt"
        );
        let text = std::fs::read_to_string(path).unwrap();
        let mut records = vec![];
        let mut cur = std::collections::HashMap::new();
        for line in text.lines().map(str::trim) {
            if line.starts_with("COUNT") && !cur.is_empty() {
                records.push(std::mem::take(&mut cur));
            } else if let Some((k, v)) = line.split_once(" = ") {
                cur.insert(k.to_string(), v.to_string());
            }
        }
        records.push(cur);
        assert_eq!(records.len(), 3);

        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            for r in records {
                let h = |k: &str| hex(&r[k]);
                let Ok(params) = check_dh_parameters(&h("P"), &h("G"), Some(&h("Q"))) else {
                    panic!("parameters refused");
                };
                let y = y_from_x(py, &h("P"), &h("G"), &h("XstatCAVS"))
                    .ok()
                    .unwrap();
                assert_eq!(trim_zeros(&y), trim_zeros(&h("YstatCAVS")));
                let cavs =
                    ffdh::PrivateKey::from_components(&params, &h("YstatCAVS"), &h("XstatCAVS"))
                        .unwrap();
                let iut =
                    ffdh::PrivateKey::from_components(&params, &h("YstatIUT"), &h("XstatIUT"))
                        .unwrap();
                let z = cavs.exchange(iut.public_key()).unwrap();
                assert_eq!(z.len(), h("P").len());
                assert_eq!(trim_zeros(&z), trim_zeros(&h("Z")));
                assert_eq!(iut.exchange(cavs.public_key()).unwrap(), z);
                // A wrong y is refused.
                let mut bad_y = h("YstatCAVS");
                *bad_y.last_mut().unwrap() ^= 1;
                assert!(
                    ffdh::PrivateKey::from_components(&params, &bad_y, &h("XstatCAVS")).is_err()
                );
            }
        });
        // An undersized modulus is refused.
        assert!(check_dh_parameters(&[0xfb; 32], &[2], None).is_err());
    }
}
