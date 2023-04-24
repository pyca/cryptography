// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#[cfg(not(python_implementation = "PyPy"))]
use pyo3::FromPyPointer;

#[cfg(python_implementation = "PyPy")]
extern "C" {
    fn Cryptography_make_openssl_module() -> std::os::raw::c_int;
}
#[cfg(not(python_implementation = "PyPy"))]
extern "C" {
    fn PyInit__openssl() -> *mut pyo3::ffi::PyObject;
}

pub fn create_module(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::types::PyModule> {
    #[cfg(python_implementation = "PyPy")]
    let openssl_mod = unsafe {
        let res = Cryptography_make_openssl_module();
        assert_eq!(res, 0);
        pyo3::types::PyModule::import(py, "_openssl")?
    };
    #[cfg(not(python_implementation = "PyPy"))]
    let openssl_mod = unsafe {
        let ptr = PyInit__openssl();
        pyo3::types::PyModule::from_owned_ptr(py, ptr)
    };

    Ok(openssl_mod)
}
