// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::prelude::PyModuleMethods;

#[pyo3::prelude::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.exceptions",
    name = "_Reasons"
)]
#[allow(non_camel_case_types)]
pub(crate) enum Reasons {
    BACKEND_MISSING_INTERFACE,
    UNSUPPORTED_HASH,
    UNSUPPORTED_CIPHER,
    UNSUPPORTED_PADDING,
    UNSUPPORTED_MGF,
    UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
    UNSUPPORTED_ELLIPTIC_CURVE,
    UNSUPPORTED_SERIALIZATION,
    UNSUPPORTED_X509,
    UNSUPPORTED_EXCHANGE_ALGORITHM,
    UNSUPPORTED_DIFFIE_HELLMAN,
    UNSUPPORTED_MAC,
}

pyo3::import_exception_bound!(cryptography.exceptions, AlreadyUpdated);
pyo3::import_exception_bound!(cryptography.exceptions, AlreadyFinalized);
pyo3::import_exception_bound!(cryptography.exceptions, InternalError);
pyo3::import_exception_bound!(cryptography.exceptions, InvalidSignature);
pyo3::import_exception_bound!(cryptography.exceptions, InvalidTag);
pyo3::import_exception_bound!(cryptography.exceptions, NotYetFinalized);
pyo3::import_exception_bound!(cryptography.exceptions, UnsupportedAlgorithm);
pyo3::import_exception_bound!(cryptography.x509, AttributeNotFound);
pyo3::import_exception_bound!(cryptography.x509, DuplicateExtension);
pyo3::import_exception_bound!(cryptography.x509, UnsupportedGeneralNameType);
pyo3::import_exception_bound!(cryptography.x509, InvalidVersion);

pub(crate) fn create_submodule(
    py: pyo3::Python<'_>,
) -> pyo3::PyResult<pyo3::Bound<'_, pyo3::prelude::PyModule>> {
    let submod = pyo3::prelude::PyModule::new_bound(py, "exceptions")?;

    submod.add_class::<Reasons>()?;

    Ok(submod)
}
