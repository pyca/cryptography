// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;
use foreign_types_shared::ForeignTypeRef;
use pyo3::IntoPy;

#[pyo3::prelude::pyfunction]
fn private_key_from_ptr(
    py: pyo3::Python<'_>,
    ptr: usize,
    unsafe_skip_rsa_key_validation: bool,
) -> CryptographyResult<pyo3::PyObject> {
    // SAFETY: Caller is responsible for passing a valid pointer.
    let pkey = unsafe { openssl::pkey::PKeyRef::from_ptr(ptr as *mut _) };
    match pkey.id() {
        openssl::pkey::Id::RSA => Ok(crate::backend::rsa::private_key_from_pkey(
            pkey,
            unsafe_skip_rsa_key_validation,
        )?
        .into_py(py)),
        #[cfg(any(not(CRYPTOGRAPHY_IS_LIBRESSL), CRYPTOGRAPHY_LIBRESSL_380_OR_GREATER))]
        openssl::pkey::Id::RSA_PSS => {
            // At the moment the way we handle RSA PSS keys is to strip the
            // PSS constraints from them and treat them as normal RSA keys
            // Unfortunately the RSA * itself tracks this data so we need to
            // extract, serialize, and reload it without the constraints.
            let der_bytes = pkey.rsa()?.private_key_to_der()?;
            let rsa = openssl::rsa::Rsa::private_key_from_der(&der_bytes)?;
            let pkey = openssl::pkey::PKey::from_rsa(rsa)?;
            Ok(
                crate::backend::rsa::private_key_from_pkey(&pkey, unsafe_skip_rsa_key_validation)?
                    .into_py(py),
            )
        }
        openssl::pkey::Id::EC => {
            Ok(crate::backend::ec::private_key_from_pkey(py, pkey)?.into_py(py))
        }
        openssl::pkey::Id::X25519 => {
            Ok(crate::backend::x25519::private_key_from_pkey(pkey).into_py(py))
        }

        #[cfg(all(not(CRYPTOGRAPHY_IS_LIBRESSL), not(CRYPTOGRAPHY_IS_BORINGSSL)))]
        openssl::pkey::Id::X448 => {
            Ok(crate::backend::x448::private_key_from_pkey(pkey).into_py(py))
        }

        openssl::pkey::Id::ED25519 => {
            Ok(crate::backend::ed25519::private_key_from_pkey(pkey).into_py(py))
        }

        #[cfg(all(not(CRYPTOGRAPHY_IS_LIBRESSL), not(CRYPTOGRAPHY_IS_BORINGSSL)))]
        openssl::pkey::Id::ED448 => {
            Ok(crate::backend::ed448::private_key_from_pkey(pkey).into_py(py))
        }
        openssl::pkey::Id::DSA => Ok(crate::backend::dsa::private_key_from_pkey(pkey).into_py(py)),
        openssl::pkey::Id::DH => Ok(crate::backend::dh::private_key_from_pkey(pkey).into_py(py)),

        #[cfg(all(not(CRYPTOGRAPHY_IS_LIBRESSL), not(CRYPTOGRAPHY_IS_BORINGSSL)))]
        openssl::pkey::Id::DHX => Ok(crate::backend::dh::private_key_from_pkey(pkey).into_py(py)),
        _ => Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err("Unsupported key type."),
        )),
    }
}

#[pyo3::prelude::pyfunction]
fn public_key_from_ptr(py: pyo3::Python<'_>, ptr: usize) -> CryptographyResult<pyo3::PyObject> {
    // SAFETY: Caller is responsible for passing a valid pointer.
    let pkey = unsafe { openssl::pkey::PKeyRef::from_ptr(ptr as *mut _) };
    match pkey.id() {
        openssl::pkey::Id::RSA => Ok(crate::backend::rsa::public_key_from_pkey(pkey).into_py(py)),
        #[cfg(any(not(CRYPTOGRAPHY_IS_LIBRESSL), CRYPTOGRAPHY_LIBRESSL_380_OR_GREATER))]
        openssl::pkey::Id::RSA_PSS => {
            // At the moment the way we handle RSA PSS keys is to strip the
            // PSS constraints from them and treat them as normal RSA keys
            // Unfortunately the RSA * itself tracks this data so we need to
            // extract, serialize, and reload it without the constraints.
            let der_bytes = pkey.rsa()?.public_key_to_der()?;
            let rsa = openssl::rsa::Rsa::public_key_from_der(&der_bytes)?;
            let pkey = openssl::pkey::PKey::from_rsa(rsa)?;
            Ok(crate::backend::rsa::public_key_from_pkey(&pkey).into_py(py))
        }
        openssl::pkey::Id::EC => {
            Ok(crate::backend::ec::public_key_from_pkey(py, pkey)?.into_py(py))
        }
        openssl::pkey::Id::X25519 => {
            Ok(crate::backend::x25519::public_key_from_pkey(pkey).into_py(py))
        }
        #[cfg(all(not(CRYPTOGRAPHY_IS_LIBRESSL), not(CRYPTOGRAPHY_IS_BORINGSSL)))]
        openssl::pkey::Id::X448 => Ok(crate::backend::x448::public_key_from_pkey(pkey).into_py(py)),

        openssl::pkey::Id::ED25519 => {
            Ok(crate::backend::ed25519::public_key_from_pkey(pkey).into_py(py))
        }
        #[cfg(all(not(CRYPTOGRAPHY_IS_LIBRESSL), not(CRYPTOGRAPHY_IS_BORINGSSL)))]
        openssl::pkey::Id::ED448 => {
            Ok(crate::backend::ed448::public_key_from_pkey(pkey).into_py(py))
        }

        openssl::pkey::Id::DSA => Ok(crate::backend::dsa::public_key_from_pkey(pkey).into_py(py)),
        openssl::pkey::Id::DH => Ok(crate::backend::dh::public_key_from_pkey(pkey).into_py(py)),

        #[cfg(all(not(CRYPTOGRAPHY_IS_LIBRESSL), not(CRYPTOGRAPHY_IS_BORINGSSL)))]
        openssl::pkey::Id::DHX => Ok(crate::backend::dh::public_key_from_pkey(pkey).into_py(py)),

        _ => Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err("Unsupported key type."),
        )),
    }
}

pub(crate) fn create_module(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let m = pyo3::prelude::PyModule::new(py, "keys")?;
    m.add_function(pyo3::wrap_pyfunction!(private_key_from_ptr, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(public_key_from_ptr, m)?)?;

    Ok(m)
}
