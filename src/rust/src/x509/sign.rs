// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::x509;

pub(crate) fn compute_signature_algorithm<'p>(
    private_key: &'p pyo3::PyAny,
    hash_algorithm: &'p pyo3::PyAny,
) -> pyo3::PyResult<x509::AlgorithmIdentifier<'static>> {
    todo!()
}

pub(crate) fn sign_data<'p>(
    private_key: &'p pyo3::PyAny,
    hash_algorithm: &'p pyo3::PyAny,
    data: &[u8],
) -> pyo3::PyResult<&'p [u8]> {
    todo!()
}
