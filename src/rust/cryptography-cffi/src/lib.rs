// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#![deny(rust_2018_idioms, clippy::undocumented_unsafe_blocks)]

// This crate never calls into `openssl-sys` directly, but it must depend on
// it: Cargo only exposes a `links` crate's build metadata (here
// `DEP_OPENSSL_INCLUDE`, which `build.rs` uses to compile the CFFI-generated
// C code against the right OpenSSL headers) to its immediate dependents. This
// `use` marks the dependency as intentional so `cargo::unused_dependencies`
// doesn't flag it.
use openssl_sys as _;

#[cfg(python_implementation = "PyPy")]
extern "C" {
    fn Cryptography_make_openssl_module() -> std::os::raw::c_int;
}
#[cfg(not(python_implementation = "PyPy"))]
extern "C" {
    fn PyInit__openssl() -> *mut pyo3::ffi::PyObject;
}

pub fn create_module(
    py: pyo3::Python<'_>,
) -> pyo3::PyResult<pyo3::Bound<'_, pyo3::types::PyModule>> {
    #[cfg(python_implementation = "PyPy")]
    let openssl_mod = unsafe {
        let res = Cryptography_make_openssl_module();
        assert_eq!(res, 0);
        pyo3::types::PyModule::import(py, "_openssl")?.clone()
    };
    #[cfg(not(python_implementation = "PyPy"))]
    // SAFETY: `PyInit__openssl` returns an owned reference.
    let openssl_mod = unsafe {
        let ptr = PyInit__openssl();
        pyo3::Bound::from_owned_ptr_or_err(py, ptr)?.cast_into_unchecked()
    };

    Ok(openssl_mod)
}
