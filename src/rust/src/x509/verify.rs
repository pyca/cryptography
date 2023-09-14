// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::certificate::Certificate;
use cryptography_x509_validation::ops::CryptoOps;

use crate::x509::sign;
use crate::{
    error::{CryptographyError, CryptographyResult},
    types,
    x509::certificate::Certificate as PyCertificate,
};

pub(crate) struct PyCryptoOps {}

impl CryptoOps for PyCryptoOps {
    type Key = pyo3::Py<pyo3::PyAny>;
    type Err = CryptographyError;

    fn public_key(&self, cert: &Certificate<'_>) -> Result<Self::Key, Self::Err> {
        pyo3::Python::with_gil(|py| -> Result<Self::Key, Self::Err> {
            // This makes an unnecessary copy. It'd be nice to get rid of it.
            let spki_der = pyo3::types::PyBytes::new(py, &asn1::write_single(&cert.tbs_cert.spki)?);

            Ok(types::LOAD_DER_PUBLIC_KEY
                .get(py)?
                .call1((spki_der,))?
                .into())
        })
    }

    fn is_signed_by(&self, cert: &Certificate<'_>, key: Self::Key) -> Result<(), Self::Err> {
        pyo3::Python::with_gil(|py| -> CryptographyResult<()> {
            sign::verify_signature_with_signature_algorithm(
                py,
                key.as_ref(py),
                &cert.signature_alg,
                cert.signature.as_bytes(),
                &asn1::write_single(&cert.tbs_cert)?,
            )
        })
    }
}

#[pyo3::pyclass(
    frozen,
    name = "Store",
    module = "cryptography.hazmat.bindings._rust.x509"
)]
struct PyStore(Vec<pyo3::Py<PyCertificate>>);

#[pyo3::pymethods]
impl PyStore {
    #[new]
    fn new(certs: Vec<pyo3::Py<PyCertificate>>) -> pyo3::PyResult<Self> {
        if certs.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "can't create an empty store",
            ));
        }
        Ok(Self(certs))
    }
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_class::<PyStore>()?;

    Ok(())
}
