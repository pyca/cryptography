// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#![deny(rust_2018_idioms, clippy::undocumented_unsafe_blocks)]

mod asn1;
mod backend;
mod buf;
mod error;
mod exceptions;
pub(crate) mod oid;
mod padding;
mod pkcs7;
pub(crate) mod types;
mod x509;

#[pyo3::prelude::pyfunction]
fn openssl_version() -> i64 {
    openssl::version::number()
}

#[pyo3::prelude::pyfunction]
fn is_fips_enabled() -> bool {
    cryptography_openssl::fips::is_enabled()
}

#[pyo3::prelude::pymodule]
fn _rust(py: pyo3::Python<'_>, m: &pyo3::types::PyModule) -> pyo3::PyResult<()> {
    m.add_function(pyo3::wrap_pyfunction!(padding::check_pkcs7_padding, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(padding::check_ansix923_padding, m)?)?;
    m.add_class::<oid::ObjectIdentifier>()?;

    m.add_submodule(asn1::create_submodule(py)?)?;
    m.add_submodule(pkcs7::create_submodule(py)?)?;
    m.add_submodule(exceptions::create_submodule(py)?)?;

    let x509_mod = pyo3::prelude::PyModule::new(py, "x509")?;
    crate::x509::certificate::add_to_module(x509_mod)?;
    crate::x509::common::add_to_module(x509_mod)?;
    crate::x509::crl::add_to_module(x509_mod)?;
    crate::x509::csr::add_to_module(x509_mod)?;
    crate::x509::sct::add_to_module(x509_mod)?;
    crate::x509::verify::add_to_module(x509_mod)?;
    m.add_submodule(x509_mod)?;

    let ocsp_mod = pyo3::prelude::PyModule::new(py, "ocsp")?;
    crate::x509::ocsp_req::add_to_module(ocsp_mod)?;
    crate::x509::ocsp_resp::add_to_module(ocsp_mod)?;
    m.add_submodule(ocsp_mod)?;

    m.add_submodule(cryptography_cffi::create_module(py)?)?;

    let openssl_mod = pyo3::prelude::PyModule::new(py, "openssl")?;
    openssl_mod.add_function(pyo3::wrap_pyfunction!(openssl_version, m)?)?;
    openssl_mod.add_function(pyo3::wrap_pyfunction!(error::raise_openssl_error, m)?)?;
    openssl_mod.add_function(pyo3::wrap_pyfunction!(error::capture_error_stack, m)?)?;
    openssl_mod.add_function(pyo3::wrap_pyfunction!(is_fips_enabled, m)?)?;
    openssl_mod.add_class::<error::OpenSSLError>()?;
    crate::backend::add_to_module(openssl_mod)?;
    m.add_submodule(openssl_mod)?;

    Ok(())
}
