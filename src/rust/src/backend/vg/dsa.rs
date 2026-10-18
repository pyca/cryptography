// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! DSA keys on verified-garbage.
//!
//! verified-garbage signs and verifies with the `(p, q)` sizes
//! `(1024, 160)`, `(2048, 224)`, `(2048, 256)` and `(3072, 256)` bits. It
//! does not generate DSA parameters. Keys are generated, and `y = g^x mod
//! p` is checked, with verified-garbage's finite-field Diffie-Hellman over
//! the DSA domain (whose key generation with a subgroup order `q` is DSA's:
//! `x` uniform in `[1, q)` and `y = g^x mod p`).

use pyo3::types::PyAnyMethods;
use verified_garbage::dsa as vg_dsa;
use verified_garbage::ffdh;

use crate::backend::ec::{der_signature, left_pad, parse_der_signature, trim_zeros, SecretBytes};
use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types};
use cryptography_key_parsing::raw;

fn warn_dsa_deprecated(py: pyo3::Python<'_>) -> pyo3::PyResult<()> {
    let warning_cls = types::DEPRECATED_IN_51.get(py)?;
    let message = c"DSA is deprecated and support will be removed in a future release. Use a more modern signature algorithm.";
    pyo3::PyErr::warn(py, &warning_cls, message, 1)
}

/// `g^x mod p`, computed by Python's `pow` (variable time in `x`), for a
/// private key whose encoding omits `y` (PKCS #8 DSA and DH keys).
/// verified-garbage has no operation that computes it from `x` alone; the
/// result is not trusted: the caller checks it in verified code
/// (`ffdh::PrivateKey::from_components` checks `y = g^x mod p`).
pub(crate) fn y_from_x(
    py: pyo3::Python<'_>,
    p: &[u8],
    g: &[u8],
    x: &[u8],
) -> CryptographyResult<Vec<u8>> {
    let p = utils::be_bytes_to_py_int(py, p)?;
    let g = utils::be_bytes_to_py_int(py, g)?;
    let x = utils::be_bytes_to_py_int(py, x)?;
    let y = g.pow(x, Some(p))?;
    utils::py_int_to_be_bytes(py, &y)
}

/// DSA domain parameters, without leading zeros.
#[derive(Clone, PartialEq, Eq)]
struct Params {
    p: Vec<u8>,
    q: Vec<u8>,
    g: Vec<u8>,
}

impl Params {
    fn new(p: &[u8], q: &[u8], g: &[u8]) -> CryptographyResult<Params> {
        let params = Params {
            p: trim_zeros(p).to_vec(),
            q: trim_zeros(q).to_vec(),
            g: trim_zeros(g).to_vec(),
        };
        // Malformed parameters are invalid, not unsupported: p and q odd
        // and nonzero, and 1 < g < p.
        let odd = |v: &[u8]| v.last().is_some_and(|b| b & 1 == 1);
        let g_ok = params.g.len() > 1 || params.g.first().is_some_and(|&b| b > 1);
        let g_below_p = params.g.len() < params.p.len()
            || (params.g.len() == params.p.len() && params.g < params.p);
        if !odd(&params.p) || !odd(&params.q) || !g_ok || !g_below_p {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Invalid DSA parameters"),
            ));
        }
        params.widths()?;
        Ok(params)
    }

    /// The encoding widths of `p` and `q` that verified-garbage takes, if
    /// it supports their sizes.
    fn widths(&self) -> CryptographyResult<(usize, usize)> {
        let bits = |v: &[u8]| match v.first() {
            Some(&b) => 8 * v.len() - b.leading_zeros() as usize,
            None => 0,
        };
        match (bits(&self.p), bits(&self.q)) {
            (1024, 160) => Ok((128, 20)),
            (2048, 224) => Ok((256, 28)),
            (2048, 256) => Ok((256, 32)),
            (3072, 256) => Ok((384, 32)),
            (p, q) => Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    format!(
                        "DSA with a {p}-bit p and a {q}-bit q is not supported by this backend"
                    ),
                    exceptions::Reasons::UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
                )),
            )),
        }
    }

    fn key_size(&self) -> i32 {
        (8 * self.p.len() - self.p[0].leading_zeros() as usize) as i32
    }

    fn raw(&self) -> raw::DsaParameters {
        raw::DsaParameters {
            p: self.p.clone(),
            q: self.q.clone(),
            g: self.g.clone(),
        }
    }

    fn numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DsaParameterNumbers> {
        Ok(DsaParameterNumbers {
            p: utils::be_bytes_to_py_int(py, &self.p)?.extract()?,
            q: utils::be_bytes_to_py_int(py, &self.q)?.extract()?,
            g: utils::be_bytes_to_py_int(py, &self.g)?.extract()?,
        })
    }

    /// The domain as a finite-field Diffie-Hellman domain with the
    /// subgroup order `q`: verified-garbage checks `1 < g < p - 1`, that `q`
    /// divides `p - 1` and that `g^q mod p = 1`.
    fn ffdh(&self) -> Option<ffdh::Parameters> {
        ffdh::Parameters::from_components(&self.p, &self.g, Some(&self.q)).ok()
    }

    /// verified-garbage's public key, with `g` and `y` at `p`'s width.
    fn public_key(&self, y: &[u8]) -> CryptographyResult<vg_dsa::PublicKey> {
        let (p_len, q_len) = self.widths()?;
        let invalid =
            || CryptographyError::from(pyo3::exceptions::PyValueError::new_err("Invalid DSA key"));
        let (Some(p), Some(q), Some(g), Some(y)) = (
            left_pad(&self.p, p_len),
            left_pad(&self.q, q_len),
            left_pad(&self.g, p_len),
            left_pad(y, p_len),
        ) else {
            return Err(invalid());
        };
        vg_dsa::PublicKey::from_components(&p, &q, &g, &y).map_err(|_| invalid())
    }
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.dsa",
    name = "DSAPrivateKey"
)]
pub(crate) struct DsaPrivateKey {
    key: vg_dsa::PrivateKey,
    params: Params,
    y: Vec<u8>,
    /// `x`, without leading zeros.
    x: SecretBytes,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.dsa",
    name = "DSAPublicKey"
)]
pub(crate) struct DsaPublicKey {
    key: vg_dsa::PublicKey,
    params: Params,
    y: Vec<u8>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.dsa",
    name = "DSAParameters"
)]
struct DsaParameters {
    params: Params,
}

impl DsaPrivateKey {
    /// The key `(x, y)` over `params`, once verified-garbage has checked
    /// that `y = g^x mod p` (and the domain: see `Params::ffdh`).
    fn new(params: Params, y: &[u8], x: &[u8]) -> CryptographyResult<DsaPrivateKey> {
        let (_, q_len) = params.widths()?;
        let y = trim_zeros(y).to_vec();
        let x = SecretBytes(trim_zeros(x).to_vec());
        let consistent = params
            .ffdh()
            .is_some_and(|domain| ffdh::PrivateKey::from_components(&domain, &y, &x.0).is_ok());
        if !consistent {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("y must be equal to (g ** x % p)."),
            ));
        }
        // `g` and `y` fit `p`'s width.
        params.public_key(&y)?;
        let (p_len, _) = params.widths()?;
        let x_padded =
            SecretBytes(left_pad(&x.0, q_len).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("x must be > 0 and < q.")
            })?);
        let key = vg_dsa::PrivateKey::from_components(
            &left_pad(&params.p, p_len).unwrap(),
            &left_pad(&params.q, q_len).unwrap(),
            &left_pad(&params.g, p_len).unwrap(),
            &left_pad(&y, p_len).unwrap(),
            &x_padded.0,
        )
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid DSA key"))?;
        Ok(DsaPrivateKey { key, params, y, x })
    }
}

/// The key object of a parsed DSA private key. If the encoding omits `y`
/// (PKCS #8), it is computed (`y_from_x`) and checked like a given one.
pub(crate) fn private_key_from_raw(
    py: pyo3::Python<'_>,
    key: &raw::DsaPrivateKey,
) -> CryptographyResult<DsaPrivateKey> {
    let params = Params::new(&key.params.p, &key.params.q, &key.params.g)?;
    let y = match &key.y {
        Some(y) => y.clone(),
        None => y_from_x(py, &params.p, &params.g, &key.x)?,
    };
    let private_key = DsaPrivateKey::new(params, &y, &key.x)?;
    warn_dsa_deprecated(py)?;
    Ok(private_key)
}

/// The key object of a parsed DSA public key.
pub(crate) fn public_key_from_raw(
    py: pyo3::Python<'_>,
    key: &raw::DsaPublicKey,
) -> CryptographyResult<DsaPublicKey> {
    let params = Params::new(&key.params.p, &key.params.q, &key.params.g)?;
    let public_key = DsaPublicKey {
        key: params.public_key(&key.y)?,
        y: trim_zeros(&key.y).to_vec(),
        params,
    };
    warn_dsa_deprecated(py)?;
    Ok(public_key)
}

#[pyo3::pyfunction]
fn generate_parameters(key_size: u32) -> CryptographyResult<DsaParameters> {
    let _ = key_size;
    Err(CryptographyError::from(
        exceptions::UnsupportedAlgorithm::new_err((
            "DSA parameter generation is not supported by this backend",
            exceptions::Reasons::UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
        )),
    ))
}

#[pyo3::pymethods]
impl DsaPrivateKey {
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let (data, _) = utils::calculate_digest_and_algorithm(py, data.as_bytes(), &algorithm)?;

        let rs = self.key.sign(data.as_bytes()).map_err(|_| {
            pyo3::exceptions::PyValueError::new_err(
                "DSA signing failed. This generally indicates an invalid key.",
            )
        })?;
        Ok(pyo3::types::PyBytes::new(py, &der_signature(&rs)?))
    }

    #[getter]
    fn key_size(&self) -> i32 {
        self.params.key_size()
    }

    fn public_key(&self) -> DsaPublicKey {
        DsaPublicKey {
            key: self.key.public_key().clone(),
            params: self.params.clone(),
            y: self.y.clone(),
        }
    }

    fn parameters(&self) -> DsaParameters {
        DsaParameters {
            params: self.params.clone(),
        }
    }

    fn private_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DsaPrivateNumbers> {
        let public_numbers = DsaPublicNumbers {
            y: utils::be_bytes_to_py_int(py, &self.y)?.extract()?,
            parameter_numbers: pyo3::Py::new(py, self.params.numbers(py)?)?,
        };
        Ok(DsaPrivateNumbers {
            x: utils::be_bytes_to_py_int(py, &self.x.0)?.extract()?,
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
        let key = slf.get();
        let raw_key = raw::PrivateKey::Dsa(raw::DsaPrivateKey {
            params: key.params.raw(),
            x: key.x.0.clone(),
            y: Some(key.y.clone()),
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
impl DsaPublicKey {
    fn verify(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<()> {
        let (data, _) = utils::calculate_digest_and_algorithm(py, data.as_bytes(), &algorithm)?;

        let (_, q_len) = self.params.widths()?;
        let valid = parse_der_signature(signature.as_bytes(), q_len)
            .is_some_and(|rs| self.key.verify(data.as_bytes(), &rs));
        if !valid {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err(()),
            ));
        }

        Ok(())
    }

    #[getter]
    fn key_size(&self) -> i32 {
        self.params.key_size()
    }

    fn parameters(&self) -> DsaParameters {
        DsaParameters {
            params: self.params.clone(),
        }
    }

    fn public_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DsaPublicNumbers> {
        Ok(DsaPublicNumbers {
            y: utils::be_bytes_to_py_int(py, &self.y)?.extract()?,
            parameter_numbers: pyo3::Py::new(py, self.params.numbers(py)?)?,
        })
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let key = slf.get();
        let raw_key = raw::PublicKey::Dsa(raw::DsaPublicKey {
            params: key.params.raw(),
            y: key.y.clone(),
        });
        utils::raw_public_bytes(py, slf, &raw_key, encoding, format, true, false)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.params == other.params && self.y == other.y
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
        // DSA key generation (FIPS 186-4 B.1.2) is FFDH key generation over
        // the domain with its subgroup order: x uniform in [1, q) and
        // y = g^x mod p, in verified code.
        let domain = self
            .params
            .ffdh()
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Invalid DSA parameters"))?;
        let generated = domain
            .generate_private_key()
            .map_err(|_| CryptographyError::VerifiedGarbage("DSA key generation failed"))?;
        DsaPrivateKey::new(
            self.params.clone(),
            generated.public_key().component(),
            generated.private_component(),
        )
    }

    fn parameter_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DsaParameterNumbers> {
        self.params.numbers(py)
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

fn params_from_numbers(
    py: pyo3::Python<'_>,
    numbers: &DsaParameterNumbers,
) -> CryptographyResult<Params> {
    check_dsa_parameters(py, numbers)?;
    Params::new(
        &utils::py_int_to_be_bytes(py, numbers.p.bind(py))?,
        &utils::py_int_to_be_bytes(py, numbers.q.bind(py))?,
        &utils::py_int_to_be_bytes(py, numbers.g.bind(py))?,
    )
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
        let params = params_from_numbers(py, parameter_numbers)?;

        if self.x.bind(py).le(0)? || self.x.bind(py).ge(parameter_numbers.q.bind(py))? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("x must be > 0 and < q."),
            ));
        }
        if public_numbers.y.bind(py).lt(0)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("y must be equal to (g ** x % p)."),
            ));
        }

        let x = SecretBytes(utils::py_int_to_be_bytes(py, self.x.bind(py))?);
        let y = utils::py_int_to_be_bytes(py, public_numbers.y.bind(py))?;
        DsaPrivateKey::new(params, &y, &x.0)
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

        let params = params_from_numbers(py, self.parameter_numbers.get())?;
        if self.y.bind(py).lt(0)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Invalid DSA key"),
            ));
        }
        let y = trim_zeros(&utils::py_int_to_be_bytes(py, self.y.bind(py))?).to_vec();
        Ok(DsaPublicKey {
            key: params.public_key(&y)?,
            params,
            y,
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

        Ok(DsaParameters {
            params: params_from_numbers(py, self)?,
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

    /// FIPS 186-3 SigGen vectors of the sizes verified-garbage supports:
    /// each key loads (verified-garbage checks `y = g^x mod p`), its
    /// signature verifies, ours verifies, and a wrong `y` is refused.
    #[test]
    fn siggen_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/cryptography_vectors/asymmetric/DSA/FIPS_186-3/SigGen.txt"
        );
        let text = std::fs::read_to_string(path).unwrap();
        let mut hash = String::new();
        let mut fields = std::collections::HashMap::new();
        let mut checked = 0;
        let mut run = |hash: &str, f: &std::collections::HashMap<String, Vec<u8>>| {
            let Ok(params) = Params::new(&f["P"], &f["Q"], &f["G"]) else {
                return;
            };
            let md = cryptography_crypto::hash::MessageDigest::from_name(hash).unwrap();
            let digest = cryptography_crypto::hash::hash(md, &f["Msg"]).unwrap();
            let Ok(key) = DsaPrivateKey::new(params.clone(), &f["Y"], &f["X"]) else {
                panic!("key refused");
            };
            let (_, q_len) = params.widths().ok().unwrap();
            let mut rs = left_pad(&f["R"], q_len).unwrap();
            rs.extend(left_pad(&f["S"], q_len).unwrap());
            let public = key.key.public_key();
            assert!(public.verify(&digest, &rs));
            let ours = key.key.sign(&digest).unwrap();
            assert!(public.verify(&digest, &ours));
            let der = der_signature(&ours).ok().unwrap();
            assert_eq!(parse_der_signature(&der, q_len).unwrap(), ours);
            let mut bad_y = f["Y"].clone();
            *bad_y.last_mut().unwrap() ^= 1;
            assert!(DsaPrivateKey::new(params, &bad_y, &f["X"]).is_err());
            checked += 1;
        };
        for line in text.lines().map(str::trim) {
            if let Some(section) = line.strip_prefix("[mod = ") {
                if fields.contains_key("Msg") {
                    run(&hash, &fields);
                    fields.remove("Msg");
                }
                hash = section
                    .trim_end_matches(']')
                    .rsplit(", ")
                    .next()
                    .unwrap()
                    .to_lowercase()
                    .replace("sha-", "sha")
                    .replace("sha512/", "sha512-");
            } else if let Some((k, v)) = line.split_once(" = ") {
                if k == "Msg" && fields.contains_key("Msg") {
                    run(&hash, &fields);
                }
                fields.insert(k.to_string(), hex(v));
            }
        }
        run(&hash, &fields);
        assert!(checked > 100);
        // A size verified-garbage lacks is refused as unsupported.
        assert!(Params::new(&[0xff; 512], &[0xff; 32], &[2]).is_err());
    }
}
