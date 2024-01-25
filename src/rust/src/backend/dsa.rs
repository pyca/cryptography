// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

#[pyo3::prelude::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.dsa",
    name = "DSAPrivateKey"
)]
pub(crate) struct DsaPrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::prelude::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.dsa",
    name = "DSAPublicKey"
)]
pub(crate) struct DsaPublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[pyo3::prelude::pyclass(
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

#[pyo3::prelude::pyfunction]
fn generate_parameters(key_size: u32) -> CryptographyResult<DsaParameters> {
    let dsa = openssl::dsa::Dsa::generate_params(key_size)?;
    Ok(DsaParameters { dsa })
}

fn clone_dsa_params<T: openssl::pkey::HasParams>(
    d: &openssl::dsa::Dsa<T>,
) -> Result<openssl::dsa::Dsa<openssl::pkey::Params>, openssl::error::ErrorStack> {
    openssl::dsa::Dsa::from_pqg(d.p().to_owned()?, d.q().to_owned()?, d.g().to_owned()?)
}

#[pyo3::prelude::pymethods]
impl DsaPrivateKey {
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        algorithm: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let (data, _) = utils::calculate_digest_and_algorithm(py, data.as_bytes(), algorithm)?;

        let mut signer = openssl::pkey_ctx::PkeyCtx::new(&self.pkey)?;
        signer.sign_init()?;
        let mut sig = vec![];
        signer.sign_to_vec(data, &mut sig)?;
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
impl DsaPublicKey {
    fn verify(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        algorithm: &pyo3::PyAny,
    ) -> CryptographyResult<()> {
        let (data, _) = utils::calculate_digest_and_algorithm(py, data.as_bytes(), algorithm)?;

        let mut verifier = openssl::pkey_ctx::PkeyCtx::new(&self.pkey)?;
        verifier.verify_init()?;
        let valid = verifier.verify(data, signature.as_bytes()).unwrap_or(false);
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
        slf: &pyo3::PyCell<Self>,
        py: pyo3::Python<'p>,
        encoding: &pyo3::PyAny,
        format: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, true, false)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.pkey.public_eq(&other.pkey)
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }
}

#[pyo3::prelude::pymethods]
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
            .as_ref(py)
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
            .as_ref(py)
            .call_method0("bit_length")?
            .extract::<usize>()?,
    ) {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("q must be exactly 160, 224, or 256 bits long"),
        ));
    }

    if parameters.g.as_ref(py).le(1)? || parameters.g.as_ref(py).ge(parameters.p.as_ref(py))? {
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

    if numbers.x.as_ref(py).le(0)? || numbers.x.as_ref(py).ge(params.q.as_ref(py))? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("x must be > 0 and < q."),
        ));
    }

    if numbers
        .public_numbers
        .get()
        .y
        .as_ref(py)
        .ne(params.g.as_ref(py).call_method1(
            pyo3::intern!(py, "__pow__"),
            (numbers.x.as_ref(py), params.p.as_ref(py)),
        )?)?
    {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("y must be equal to (g ** x % p)."),
        ));
    }

    Ok(())
}

#[pyo3::prelude::pyclass(
    frozen,
    module = "cryptography.hazmat.primitives.asymmetric.dsa",
    name = "DSAPrivateNumbers"
)]
struct DsaPrivateNumbers {
    #[pyo3(get)]
    x: pyo3::Py<pyo3::types::PyLong>,
    #[pyo3(get)]
    public_numbers: pyo3::Py<DsaPublicNumbers>,
}

#[pyo3::prelude::pyclass(
    frozen,
    module = "cryptography.hazmat.primitives.asymmetric.dsa",
    name = "DSAPublicNumbers"
)]
struct DsaPublicNumbers {
    #[pyo3(get)]
    y: pyo3::Py<pyo3::types::PyLong>,
    #[pyo3(get)]
    parameter_numbers: pyo3::Py<DsaParameterNumbers>,
}

#[pyo3::prelude::pyclass(
    frozen,
    module = "cryptography.hazmat.primitives.asymmetric.dsa",
    name = "DSAParameterNumbers"
)]
struct DsaParameterNumbers {
    #[pyo3(get)]
    p: pyo3::Py<pyo3::types::PyLong>,
    #[pyo3(get)]
    q: pyo3::Py<pyo3::types::PyLong>,
    #[pyo3(get)]
    g: pyo3::Py<pyo3::types::PyLong>,
}

#[pyo3::prelude::pymethods]
impl DsaPrivateNumbers {
    #[new]
    fn new(
        x: pyo3::Py<pyo3::types::PyLong>,
        public_numbers: pyo3::Py<DsaPublicNumbers>,
    ) -> DsaPrivateNumbers {
        DsaPrivateNumbers { x, public_numbers }
    }

    fn private_key(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<&pyo3::PyAny>,
    ) -> CryptographyResult<DsaPrivateKey> {
        let _ = backend;

        let public_numbers = self.public_numbers.get();
        let parameter_numbers = public_numbers.parameter_numbers.get();

        check_dsa_private_numbers(py, self)?;

        let dsa = openssl::dsa::Dsa::from_private_components(
            utils::py_int_to_bn(py, parameter_numbers.p.as_ref(py))?,
            utils::py_int_to_bn(py, parameter_numbers.q.as_ref(py))?,
            utils::py_int_to_bn(py, parameter_numbers.g.as_ref(py))?,
            utils::py_int_to_bn(py, self.x.as_ref(py))?,
            utils::py_int_to_bn(py, public_numbers.y.as_ref(py))?,
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
        Ok(self.x.as_ref(py).eq(other.x.as_ref(py))?
            && self
                .public_numbers
                .as_ref(py)
                .eq(other.public_numbers.as_ref(py))?)
    }
}

#[pyo3::prelude::pymethods]
impl DsaPublicNumbers {
    #[new]
    fn new(
        y: pyo3::Py<pyo3::types::PyLong>,
        parameter_numbers: pyo3::Py<DsaParameterNumbers>,
    ) -> DsaPublicNumbers {
        DsaPublicNumbers {
            y,
            parameter_numbers,
        }
    }

    fn public_key(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<&pyo3::PyAny>,
    ) -> CryptographyResult<DsaPublicKey> {
        let _ = backend;

        let parameter_numbers = self.parameter_numbers.get();

        check_dsa_parameters(py, parameter_numbers)?;

        let dsa = openssl::dsa::Dsa::from_public_components(
            utils::py_int_to_bn(py, parameter_numbers.p.as_ref(py))?,
            utils::py_int_to_bn(py, parameter_numbers.q.as_ref(py))?,
            utils::py_int_to_bn(py, parameter_numbers.g.as_ref(py))?,
            utils::py_int_to_bn(py, self.y.as_ref(py))?,
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
        Ok(self.y.as_ref(py).eq(other.y.as_ref(py))?
            && self
                .parameter_numbers
                .as_ref(py)
                .eq(other.parameter_numbers.as_ref(py))?)
    }

    fn __repr__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<String> {
        let y = self.y.as_ref(py);
        let parameter_numbers = self.parameter_numbers.as_ref(py).repr()?;
        Ok(format!(
            "<DSAPublicNumbers(y={y}, parameter_numbers={parameter_numbers})>"
        ))
    }
}

#[pyo3::prelude::pymethods]
impl DsaParameterNumbers {
    #[new]
    fn new(
        p: pyo3::Py<pyo3::types::PyLong>,
        q: pyo3::Py<pyo3::types::PyLong>,
        g: pyo3::Py<pyo3::types::PyLong>,
    ) -> DsaParameterNumbers {
        DsaParameterNumbers { p, q, g }
    }

    fn parameters(
        &self,
        py: pyo3::Python<'_>,
        backend: Option<&pyo3::PyAny>,
    ) -> CryptographyResult<DsaParameters> {
        let _ = backend;

        check_dsa_parameters(py, self)?;

        let dsa = openssl::dsa::Dsa::from_pqg(
            utils::py_int_to_bn(py, self.p.as_ref(py))?,
            utils::py_int_to_bn(py, self.q.as_ref(py))?,
            utils::py_int_to_bn(py, self.g.as_ref(py))?,
        )
        .unwrap();
        Ok(DsaParameters { dsa })
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        Ok(self.p.as_ref(py).eq(other.p.as_ref(py))?
            && self.q.as_ref(py).eq(other.q.as_ref(py))?
            && self.g.as_ref(py).eq(other.g.as_ref(py))?)
    }

    fn __repr__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<String> {
        let p = self.p.as_ref(py);
        let q = self.q.as_ref(py);
        let g = self.g.as_ref(py);
        Ok(format!("<DSAParameterNumbers(p={p}, q={q}, g={g})>"))
    }
}

pub(crate) fn create_module(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let m = pyo3::prelude::PyModule::new(py, "dsa")?;
    m.add_function(pyo3::wrap_pyfunction!(generate_parameters, m)?)?;

    m.add_class::<DsaPrivateKey>()?;
    m.add_class::<DsaPublicKey>()?;
    m.add_class::<DsaParameters>()?;
    m.add_class::<DsaPrivateNumbers>()?;
    m.add_class::<DsaPublicNumbers>()?;
    m.add_class::<DsaParameterNumbers>()?;

    Ok(m)
}
