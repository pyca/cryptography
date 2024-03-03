// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::keys;
use crate::buf::CffiBuf;
use crate::error::CryptographyResult;
use crate::x509::certificate::Certificate;
use crate::{types, x509};
use pyo3::IntoPy;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[pyo3::prelude::pyclass]
struct PKCS12Certificate {
    #[pyo3(get)]
    certificate: pyo3::Py<Certificate>,
    #[pyo3(get)]
    friendly_name: Option<pyo3::Py<pyo3::types::PyBytes>>,
}

#[pyo3::prelude::pymethods]
impl PKCS12Certificate {
    #[new]
    fn new(
        cert: pyo3::Py<Certificate>,
        friendly_name: Option<pyo3::Py<pyo3::types::PyBytes>>,
    ) -> PKCS12Certificate {
        PKCS12Certificate {
            certificate: cert,
            friendly_name,
        }
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        let friendly_name_eq = match (&self.friendly_name, &other.friendly_name) {
            (Some(a), Some(b)) => a.as_ref(py).eq(b.as_ref(py))?,
            (None, None) => true,
            _ => false,
        };
        Ok(friendly_name_eq
            && self
                .certificate
                .as_ref(py)
                .eq(other.certificate.as_ref(py))?)
    }

    fn __hash__(&self, py: pyo3::Python<'_>) -> CryptographyResult<u64> {
        let mut hasher = DefaultHasher::new();
        self.certificate.as_ref(py).hash()?.hash(&mut hasher);
        match &self.friendly_name {
            Some(v) => v.as_ref(py).hash()?.hash(&mut hasher),
            None => None::<u32>.hash(&mut hasher),
        };
        Ok(hasher.finish())
    }

    fn __repr__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<String> {
        let friendly_name_repr = match &self.friendly_name {
            Some(v) => v.as_ref(py).repr()?.extract()?,
            None => "None",
        };
        Ok(format!(
            "<PKCS12Certificate({}, friendly_name={})>",
            self.certificate.as_ref(py).str()?,
            friendly_name_repr
        ))
    }
}

fn decode_p12(
    data: CffiBuf<'_>,
    password: Option<CffiBuf<'_>>,
) -> CryptographyResult<openssl::pkcs12::ParsedPkcs12_2> {
    let p12 = openssl::pkcs12::Pkcs12::from_der(data.as_bytes()).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("Could not deserialize PKCS12 data")
    })?;

    let password = if let Some(p) = password.as_ref() {
        std::str::from_utf8(p.as_bytes())
            .map_err(|_| pyo3::exceptions::PyUnicodeDecodeError::new_err(()))?
    } else {
        // Treat `password=None` the same as empty string. They're actually
        // not the same in PKCS#12, but OpenSSL transparently handles them the
        // same.
        ""
    };
    let parsed = p12
        .parse2(password)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid password or PKCS12 data"))?;

    Ok(parsed)
}

#[pyo3::prelude::pyfunction]
fn load_key_and_certificates<'p>(
    py: pyo3::Python<'p>,
    data: CffiBuf<'_>,
    password: Option<CffiBuf<'_>>,
    backend: Option<&pyo3::PyAny>,
) -> CryptographyResult<(
    pyo3::PyObject,
    Option<x509::certificate::Certificate>,
    &'p pyo3::types::PyList,
)> {
    let _ = backend;

    let p12 = decode_p12(data, password)?;

    let private_key = if let Some(pkey) = p12.pkey {
        keys::private_key_from_pkey(py, &pkey, false)?
    } else {
        py.None()
    };
    let cert = if let Some(ossl_cert) = p12.cert {
        let cert_der = pyo3::types::PyBytes::new(py, &ossl_cert.to_der()?).into_py(py);
        Some(x509::certificate::load_der_x509_certificate(
            py, cert_der, None,
        )?)
    } else {
        None
    };
    let additional_certs = pyo3::types::PyList::empty(py);
    if let Some(ossl_certs) = p12.ca {
        cfg_if::cfg_if! {
            if #[cfg(any(
                CRYPTOGRAPHY_OPENSSL_300_OR_GREATER, CRYPTOGRAPHY_IS_BORINGSSL
            ))] {
                let it = ossl_certs.iter();
            } else {
                let it = ossl_certs.iter().rev();
            }
        };

        for ossl_cert in it {
            let cert_der = pyo3::types::PyBytes::new(py, &ossl_cert.to_der()?).into_py(py);
            let cert = x509::certificate::load_der_x509_certificate(py, cert_der, None)?;
            additional_certs.append(cert.into_py(py))?;
        }
    }

    Ok((private_key, cert, additional_certs))
}

#[pyo3::prelude::pyfunction]
fn load_pkcs12<'p>(
    py: pyo3::Python<'p>,
    data: CffiBuf<'_>,
    password: Option<CffiBuf<'_>>,
    backend: Option<&pyo3::PyAny>,
) -> CryptographyResult<&'p pyo3::PyAny> {
    let _ = backend;

    let p12 = decode_p12(data, password)?;

    let private_key = if let Some(pkey) = p12.pkey {
        keys::private_key_from_pkey(py, &pkey, false)?
    } else {
        py.None()
    };
    let cert = if let Some(ossl_cert) = p12.cert {
        let cert_der = pyo3::types::PyBytes::new(py, &ossl_cert.to_der()?).into_py(py);
        let cert = x509::certificate::load_der_x509_certificate(py, cert_der, None)?;
        let alias = ossl_cert
            .alias()
            .map(|a| pyo3::types::PyBytes::new(py, a).into_py(py));

        PKCS12Certificate::new(pyo3::Py::new(py, cert)?, alias).into_py(py)
    } else {
        py.None()
    };
    let additional_certs = pyo3::types::PyList::empty(py);
    if let Some(ossl_certs) = p12.ca {
        cfg_if::cfg_if! {
            if #[cfg(any(
                CRYPTOGRAPHY_OPENSSL_300_OR_GREATER, CRYPTOGRAPHY_IS_BORINGSSL
            ))] {
                let it = ossl_certs.iter();
            } else {
                let it = ossl_certs.iter().rev();
            }
        };

        for ossl_cert in it {
            let cert_der = pyo3::types::PyBytes::new(py, &ossl_cert.to_der()?).into_py(py);
            let cert = x509::certificate::load_der_x509_certificate(py, cert_der, None)?;
            let alias = ossl_cert
                .alias()
                .map(|a| pyo3::types::PyBytes::new(py, a).into_py(py));

            let p12_cert = PKCS12Certificate::new(pyo3::Py::new(py, cert)?, alias).into_py(py);
            additional_certs.append(p12_cert)?;
        }
    }

    Ok(types::PKCS12KEYANDCERTIFICATES
        .get(py)?
        .call1((private_key, cert, additional_certs))?)
}

pub(crate) fn create_submodule(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let submod = pyo3::prelude::PyModule::new(py, "pkcs12")?;

    submod.add_function(pyo3::wrap_pyfunction!(load_key_and_certificates, submod)?)?;
    submod.add_function(pyo3::wrap_pyfunction!(load_pkcs12, submod)?)?;

    submod.add_class::<PKCS12Certificate>()?;

    Ok(submod)
}
