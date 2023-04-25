// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#![deny(rust_2018_idioms)]

mod asn1;
mod backend;
mod buf;
mod error;
mod exceptions;
pub(crate) mod oid;
mod pkcs7;
mod pool;
mod x509;

/// Returns the value of the input with the most-significant-bit copied to all
/// of the bits.
fn duplicate_msb_to_all(a: u8) -> u8 {
    0u8.wrapping_sub(a >> 7)
}

/// This returns 0xFF if a < b else 0x00, but does so in a constant time
/// fashion.
fn constant_time_lt(a: u8, b: u8) -> u8 {
    // Derived from:
    // https://github.com/openssl/openssl/blob/OpenSSL_1_1_1i/include/internal/constant_time.h#L120
    duplicate_msb_to_all(a ^ ((a ^ b) | (a.wrapping_sub(b) ^ b)))
}

#[pyo3::prelude::pyfunction]
fn check_pkcs7_padding(data: &[u8]) -> bool {
    let mut mismatch = 0;
    let pad_size = *data.last().unwrap();
    let len: u8 = data.len().try_into().expect("data too long");
    for (i, b) in (0..len).zip(data.iter().rev()) {
        let mask = constant_time_lt(i, pad_size);
        mismatch |= mask & (pad_size ^ b);
    }

    // Check to make sure the pad_size was within the valid range.
    mismatch |= !constant_time_lt(0, pad_size);
    mismatch |= constant_time_lt(len, pad_size);

    // Make sure any bits set are copied to the lowest bit
    mismatch |= mismatch >> 4;
    mismatch |= mismatch >> 2;
    mismatch |= mismatch >> 1;

    // Now check the low bit to see if it's set
    (mismatch & 1) == 0
}

#[pyo3::prelude::pyfunction]
fn check_ansix923_padding(data: &[u8]) -> bool {
    let mut mismatch = 0;
    let pad_size = *data.last().unwrap();
    let len: u8 = data.len().try_into().expect("data too long");
    // Skip the first one with the pad size
    for (i, b) in (1..len).zip(data[..data.len() - 1].iter().rev()) {
        let mask = constant_time_lt(i, pad_size);
        mismatch |= mask & b;
    }

    // Check to make sure the pad_size was within the valid range.
    mismatch |= !constant_time_lt(0, pad_size);
    mismatch |= constant_time_lt(len, pad_size);

    // Make sure any bits set are copied to the lowest bit
    mismatch |= mismatch >> 4;
    mismatch |= mismatch >> 2;
    mismatch |= mismatch >> 1;

    // Now check the low bit to see if it's set
    (mismatch & 1) == 0
}

#[pyo3::prelude::pyfunction]
fn openssl_version() -> i64 {
    openssl::version::number()
}

#[pyo3::prelude::pyfunction]
fn raise_openssl_error() -> crate::error::CryptographyResult<()> {
    Err(openssl::error::ErrorStack::get().into())
}

#[pyo3::prelude::pyclass(module = "cryptography.hazmat.bindings._rust.openssl")]
struct OpenSSLError {
    e: openssl::error::Error,
}

#[pyo3::pymethods]
impl OpenSSLError {
    #[getter]
    fn lib(&self) -> i32 {
        self.e.library_code()
    }

    #[getter]
    fn reason(&self) -> i32 {
        self.e.reason_code()
    }

    #[getter]
    fn reason_text(&self) -> &[u8] {
        self.e.reason().unwrap_or("").as_bytes()
    }

    fn _lib_reason_match(&self, lib: i32, reason: i32) -> bool {
        self.e.library_code() == lib && self.e.reason_code() == reason
    }

    fn __repr__(&self) -> pyo3::PyResult<String> {
        Ok(format!(
            "<OpenSSLError(code={}, lib={}, reason={}, reason_text={})>",
            self.e.code(),
            self.e.library_code(),
            self.e.reason_code(),
            self.e.reason().unwrap_or("")
        ))
    }
}

#[pyo3::prelude::pyfunction]
fn capture_error_stack(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::types::PyList> {
    let errs = pyo3::types::PyList::empty(py);
    for e in openssl::error::ErrorStack::get().errors() {
        errs.append(pyo3::PyCell::new(py, OpenSSLError { e: e.clone() })?)?;
    }
    Ok(errs)
}

#[pyo3::prelude::pyfunction]
fn is_fips_enabled() -> bool {
    cryptography_openssl::fips::is_enabled()
}

#[pyo3::prelude::pymodule]
fn _rust(py: pyo3::Python<'_>, m: &pyo3::types::PyModule) -> pyo3::PyResult<()> {
    m.add_function(pyo3::wrap_pyfunction!(check_pkcs7_padding, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(check_ansix923_padding, m)?)?;
    m.add_class::<oid::ObjectIdentifier>()?;
    m.add_class::<pool::FixedPool>()?;

    m.add_submodule(asn1::create_submodule(py)?)?;
    m.add_submodule(pkcs7::create_submodule(py)?)?;
    m.add_submodule(exceptions::create_submodule(py)?)?;

    let x509_mod = pyo3::prelude::PyModule::new(py, "x509")?;
    crate::x509::certificate::add_to_module(x509_mod)?;
    crate::x509::common::add_to_module(x509_mod)?;
    crate::x509::crl::add_to_module(x509_mod)?;
    crate::x509::csr::add_to_module(x509_mod)?;
    crate::x509::sct::add_to_module(x509_mod)?;
    m.add_submodule(x509_mod)?;

    let ocsp_mod = pyo3::prelude::PyModule::new(py, "ocsp")?;
    crate::x509::ocsp_req::add_to_module(ocsp_mod)?;
    crate::x509::ocsp_resp::add_to_module(ocsp_mod)?;
    m.add_submodule(ocsp_mod)?;

    m.add_submodule(cryptography_cffi::create_module(py)?)?;

    let openssl_mod = pyo3::prelude::PyModule::new(py, "openssl")?;
    openssl_mod.add_function(pyo3::wrap_pyfunction!(openssl_version, m)?)?;
    openssl_mod.add_function(pyo3::wrap_pyfunction!(raise_openssl_error, m)?)?;
    openssl_mod.add_function(pyo3::wrap_pyfunction!(capture_error_stack, m)?)?;
    openssl_mod.add_function(pyo3::wrap_pyfunction!(is_fips_enabled, m)?)?;
    openssl_mod.add_class::<OpenSSLError>()?;
    crate::backend::add_to_module(openssl_mod)?;
    m.add_submodule(openssl_mod)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::constant_time_lt;

    #[test]
    fn test_constant_time_lt() {
        for a in 0..=255 {
            for b in 0..=255 {
                let expected = if a < b { 0xff } else { 0 };
                assert_eq!(constant_time_lt(a, b), expected);
            }
        }
    }
}
