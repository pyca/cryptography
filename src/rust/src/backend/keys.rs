// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{error, exceptions, types};
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
fn load_der_public_key(
    py: pyo3::Python<'_>,
    data: CffiBuf<'_>,
) -> CryptographyResult<pyo3::PyObject> {
    load_der_public_key_bytes(py, data.as_bytes())
}

pub(crate) fn load_der_public_key_bytes(
    py: pyo3::Python<'_>,
    data: &[u8],
) -> CryptographyResult<pyo3::PyObject> {
    if let Ok(pkey) = openssl::pkey::PKey::public_key_from_der(data) {
        return public_key_from_pkey(py, &pkey, pkey.id());
    }
    // It's not a (RSA/DSA/ECDSA) subjectPublicKeyInfo, but we still need to
    // check to see if it is a pure PKCS1 RSA public key (not embedded in a
    // subjectPublicKeyInfo)
    let rsa = openssl::rsa::Rsa::public_key_from_der_pkcs1(data).or_else(|e| {
        let errors = error::list_from_openssl_error(py, e);
        Err(types::BACKEND_HANDLE_KEY_LOADING_ERROR
            .get(py)?
            .call1((errors,))
            .unwrap_err())
    })?;
    let pkey = openssl::pkey::PKey::from_rsa(rsa)?;
    public_key_from_pkey(py, &pkey, pkey.id())
}

#[pyo3::prelude::pyfunction]
fn load_pem_public_key(
    py: pyo3::Python<'_>,
    data: CffiBuf<'_>,
) -> CryptographyResult<pyo3::PyObject> {
    let p = pem::parse(data.as_bytes())?;
    let pkey = match p.tag() {
        "RSA PUBLIC KEY" => openssl::rsa::Rsa::public_key_from_der_pkcs1(p.contents())
            .and_then(openssl::pkey::PKey::from_rsa),
        "PUBLIC KEY" => openssl::pkey::PKey::public_key_from_der(p.contents()),
        _ => return Err(CryptographyError::from(pem::PemError::MalformedFraming)),
    }
    .or_else(|e| {
        let errors = error::list_from_openssl_error(py, e);
        Err(types::BACKEND_HANDLE_KEY_LOADING_ERROR
            .get(py)?
            .call1((errors,))
            .unwrap_err())
    })?;
    public_key_from_pkey(py, &pkey, pkey.id())
}

fn public_key_from_pkey(
    py: pyo3::Python<'_>,
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
    id: openssl::pkey::Id,
) -> CryptographyResult<pyo3::PyObject> {
    // `id` is a separate argument so we can test this while passing something
    // unsupported.
    match id {
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

    m.add_function(pyo3::wrap_pyfunction!(load_der_public_key, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(load_pem_public_key, m)?)?;

    m.add_function(pyo3::wrap_pyfunction!(private_key_from_ptr, m)?)?;

    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::public_key_from_pkey;

    #[test]
    fn test_public_key_from_pkey_unknown_key() {
        pyo3::prepare_freethreaded_python();

        pyo3::Python::with_gil(|py| {
            let pkey =
                openssl::pkey::PKey::public_key_from_raw_bytes(&[0; 32], openssl::pkey::Id::X25519)
                    .unwrap();
            // Pass a nonsense id for this key to test the unsupported
            // algorithm path.
            assert!(public_key_from_pkey(py, &pkey, openssl::pkey::Id::CMAC).is_err());
        });
    }
}
