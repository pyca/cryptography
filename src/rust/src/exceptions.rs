// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::error::CryptographyError;

#[pyo3::pyclass(
    frozen,
    eq,
    module = "cryptography.hazmat.bindings._rust.exceptions",
    name = "_Reasons"
)]
#[allow(non_camel_case_types)]
#[derive(PartialEq)]
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
pyo3::import_exception_bound!(cryptography.exceptions, InvalidKey);
pyo3::import_exception_bound!(cryptography.exceptions, InvalidSignature);
pyo3::import_exception_bound!(cryptography.exceptions, InvalidTag);
pyo3::import_exception_bound!(cryptography.exceptions, NotYetFinalized);
pyo3::import_exception_bound!(cryptography.exceptions, UnsupportedAlgorithm);
pyo3::import_exception_bound!(cryptography.x509, AttributeNotFound);
pyo3::import_exception_bound!(cryptography.x509, DuplicateExtension);
pyo3::import_exception_bound!(cryptography.x509, UnsupportedGeneralNameType);
pyo3::import_exception_bound!(cryptography.x509, InvalidVersion);

pub(crate) fn already_finalized_error() -> CryptographyError {
    CryptographyError::from(AlreadyFinalized::new_err("Context was already finalized."))
}

#[pyo3::pymodule]
pub(crate) mod exceptions {
    #[pymodule_export]
    use super::Reasons;
}
