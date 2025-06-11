// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyAnyMethods;

use crate::pyopenssl::error::{PyOpenSslError, PyOpenSslResult};
use crate::types;

pub(crate) const SSLV23_METHOD: u32 = 3;
pub(crate) const TLSV1_METHOD: u32 = 4;
pub(crate) const TLSV1_1_METHOD: u32 = 5;
pub(crate) const TLSV1_2_METHOD: u32 = 6;
pub(crate) const TLS_METHOD: u32 = 7;
pub(crate) const TLS_SERVER_METHOD: u32 = 8;
pub(crate) const TLS_CLIENT_METHOD: u32 = 9;
pub(crate) const DTLS_METHOD: u32 = 10;
pub(crate) const DTLS_SERVER_METHOD: u32 = 11;
pub(crate) const DTLS_CLIENT_METHOD: u32 = 12;

#[pyo3::pyclass(subclass, module = "OpenSSL.SSL")]
pub(crate) struct Context {
    ssl_ctx: openssl::ssl::SslContextBuilder,
}

#[pyo3::pymethods]
impl Context {
    #[new]
    fn new(method: u32) -> PyOpenSslResult<Self> {
        let (ssl_method, version) = match method {
            SSLV23_METHOD => (openssl::ssl::SslMethod::tls(), None),
            TLSV1_METHOD => (
                openssl::ssl::SslMethod::tls(),
                Some(openssl::ssl::SslVersion::TLS1),
            ),
            TLSV1_1_METHOD => (
                openssl::ssl::SslMethod::tls(),
                Some(openssl::ssl::SslVersion::TLS1_1),
            ),
            TLSV1_2_METHOD => (
                openssl::ssl::SslMethod::tls(),
                Some(openssl::ssl::SslVersion::TLS1_2),
            ),
            TLS_METHOD => (openssl::ssl::SslMethod::tls(), None),
            TLS_SERVER_METHOD => (openssl::ssl::SslMethod::tls_server(), None),
            TLS_CLIENT_METHOD => (openssl::ssl::SslMethod::tls_client(), None),
            DTLS_METHOD => (openssl::ssl::SslMethod::dtls(), None),
            DTLS_SERVER_METHOD => (openssl::ssl::SslMethod::dtls_server(), None),
            DTLS_CLIENT_METHOD => (openssl::ssl::SslMethod::dtls_client(), None),
            _ => {
                return Err(PyOpenSslError::from(
                    pyo3::exceptions::PyValueError::new_err("No such protocol"),
                ))
            }
        };
        let mut ssl_ctx = openssl::ssl::SslContext::builder(ssl_method)?;
        if let Some(version) = version {
            ssl_ctx.set_min_proto_version(Some(version))?;
            ssl_ctx.set_max_proto_version(Some(version))?;
        }

        Ok(Context { ssl_ctx })
    }

    #[getter]
    fn _context<'p>(&self, py: pyo3::Python<'p>) -> PyOpenSslResult<pyo3::Bound<'p, pyo3::PyAny>> {
        Ok(types::FFI.get(py)?.call_method1(
            pyo3::intern!(py, "cast"),
            (
                pyo3::intern!(py, "SSL_CTX *"),
                self.ssl_ctx.as_ptr() as usize,
            ),
        )?)
    }
}
