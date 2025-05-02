// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyAnyMethods;

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{error, exceptions};

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.dsa",
    name = "DSAPrivateKey"
)]
pub(crate) struct DsaPrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.dsa",
    name = "DSAPublicKey"
)]
pub(crate) struct DsaPublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.dsa",
    name = "DSAParameters"
)]
struct DsaParameters {
    dsa: openssl::dsa::Dsa<openssl::pkey::Params>,
}

pub(crate) fn private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> DsaPrivateKey {
    DsaPrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> DsaPublicKey {
    DsaPublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
fn generate_parameters(key_size: u32) -> CryptographyResult<DsaParameters> {
    let dsa = openssl::dsa::Dsa::generate_params(key_size)?;
    Ok(DsaParameters { dsa })
}

fn clone_dsa_params<T: openssl::pkey::HasParams>(
    d: &openssl::dsa::Dsa<T>,
) -> Result<openssl::dsa::Dsa<openssl::pkey::Params>, openssl::error::ErrorStack> {
    openssl::dsa::Dsa::from_pqg(d.p().to_owned()?, d.q().to_owned()?, d.g().to_owned()?)
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

        let mut signer = openssl::pkey_ctx::PkeyCtx::new(&self.pkey)?;
        signer.sign_init()?;
        let mut sig = vec![];
        signer.sign_to_vec(data.as_bytes(), &mut sig).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err((
                "DSA signing failed. This generally indicates an invalid key.",
                error::list_from_openssl_error(py, &e).unbind(),
            ))
        })?;
        Ok(pyo3::types::PyBytes::new(py, &sig))
    }

    #[getter]
    fn key_size(&self) -> i32 {
        self.pkey.dsa().unwrap().p().num_bits()
    }

    fn public_key(&self) -> CryptographyResult<DsaPublicKey> {
        let priv_dsa = self.pkey.dsa()?;
        let pub_dsa = openssl::dsa::Dsa::from_public_components(
            priv_dsa.p().to_owned()?,
            priv_dsa.q().to_owned()?,
            priv_dsa.g().to_owned()?,
            priv_dsa.pub_key().to_owned()?,
        )
        .unwrap();
        let pkey = openssl::pkey::PKey::from_dsa(pub_dsa)?;
        Ok(DsaPublicKey { pkey })
    }

    fn parameters(&self) -> CryptographyResult<DsaParameters> {
        let dsa = clone_dsa_params(&self.pkey.dsa().unwrap())?;
        Ok(DsaParameters { dsa })
    }

    fn private_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DsaPrivateNumbers> {
        let dsa = self.pkey.dsa().unwrap();

        let py_p = utils::bn_to_py_int(py, dsa.p())?;
        let py_q = utils::bn_to_py_int(py, dsa.q())?;
        let py_g = utils::bn_to_py_int(py, dsa.g())?;

        let py_pub_key = utils::bn_to_py_int(py, dsa.pub_key())?;
        let py_private_key = utils::bn_to_py_int(py, dsa.priv_key())?;

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
impl DsaPublicKey {
    fn verify(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<()> {
        let (data, _) = utils::calculate_digest_and_algorithm(py, data.as_bytes(), &algorithm)?;

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

    #[getter]
    fn key_size(&self) -> i32 {
        self.pkey.dsa().unwrap().p().num_bits()
    }

    fn parameters(&self) -> CryptographyResult<DsaParameters> {
        let dsa = clone_dsa_params(&self.pkey.dsa().unwrap())?;
        Ok(DsaParameters { dsa })
    }

    fn public_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DsaPublicNumbers> {
        let dsa = self.pkey.dsa().unwrap();

        let py_p = utils::bn_to_py_int(py, dsa.p())?;
        let py_q = utils::bn_to_py_int(py, dsa.q())?;
        let py_g = utils::bn_to_py_int(py, dsa.g())?;

        let py_pub_key = utils::bn_to_py_int(py, dsa.pub_key())?;

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

#[pyo3::pymethods]
impl DsaParameters {
    fn generate_private_key(&self) -> CryptographyResult<DsaPrivateKey> {
        let dsa = clone_dsa_params(&self.dsa)?.generate_key()?;
        let pkey = openssl::pkey::PKey::from_dsa(dsa)?;
        Ok(DsaPrivateKey { pkey })
    }

    fn parameter_numbers(&self, py: pyo3::Python<'_>) -> CryptographyResult<DsaParameterNumbers> {
        let py_p = utils::bn_to_py_int(py, self.dsa.p())?;
        let py_q = utils::bn_to_py_int(py, self.dsa.q())?;
        let py_g = utils::bn_to_py_int(py, self.dsa.g())?;

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

        let dsa = openssl::dsa::Dsa::from_private_components(
            utils::py_int_to_bn(py, parameter_numbers.p.bind(py))?,
            utils::py_int_to_bn(py, parameter_numbers.q.bind(py))?,
            utils::py_int_to_bn(py, parameter_numbers.g.bind(py))?,
            utils::py_int_to_bn(py, self.x.bind(py))?,
            utils::py_int_to_bn(py, public_numbers.y.bind(py))?,
        )
        .unwrap();
        let pkey = openssl::pkey::PKey::from_dsa(dsa)?;
        Ok(DsaPrivateKey { pkey })
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

        let dsa = openssl::dsa::Dsa::from_public_components(
            utils::py_int_to_bn(py, parameter_numbers.p.bind(py))?,
            utils::py_int_to_bn(py, parameter_numbers.q.bind(py))?,
            utils::py_int_to_bn(py, parameter_numbers.g.bind(py))?,
            utils::py_int_to_bn(py, self.y.bind(py))?,
        )
        .unwrap();
        let pkey = openssl::pkey::PKey::from_dsa(dsa)?;
        Ok(DsaPublicKey { pkey })
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

    fn __repr__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<String> {
        let y = self.y.bind(py);
        let parameter_numbers = self.parameter_numbers.bind(py).repr()?;
        Ok(format!(
            "<DSAPublicNumbers(y={y}, parameter_numbers={parameter_numbers})>"
        ))
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

        let dsa = openssl::dsa::Dsa::from_pqg(
            utils::py_int_to_bn(py, self.p.bind(py))?,
            utils::py_int_to_bn(py, self.q.bind(py))?,
            utils::py_int_to_bn(py, self.g.bind(py))?,
        )
        .unwrap();
        Ok(DsaParameters { dsa })
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

    fn __repr__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<String> {
        let p = self.p.bind(py);
        let q = self.q.bind(py);
        let g = self.g.bind(py);
        Ok(format!("<DSAParameterNumbers(p={p}, q={q}, g={g})>"))
    }
}

#[pyo3::pymodule]
pub(crate) mod dsa {
    #[pymodule_export]
    use super::{
        generate_parameters, DsaParameterNumbers, DsaParameters, DsaPrivateKey, DsaPrivateNumbers,
        DsaPublicKey, DsaPublicNumbers,
    };
}
