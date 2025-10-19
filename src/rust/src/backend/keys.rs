// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::IntoPyObject;

use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, x509};

#[pyo3::pyfunction]
#[pyo3(signature = (data, password, backend=None, *, unsafe_skip_rsa_key_validation=false))]
fn load_der_private_key<'p>(
    py: pyo3::Python<'p>,
    data: CffiBuf<'_>,
    password: Option<CffiBuf<'_>>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    unsafe_skip_rsa_key_validation: bool,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let _ = backend;

    load_der_private_key_bytes(
        py,
        data.as_bytes(),
        password.as_ref().map(|v| v.as_bytes()),
        unsafe_skip_rsa_key_validation,
    )
}

pub(crate) fn load_der_private_key_bytes<'p>(
    py: pyo3::Python<'p>,
    data: &[u8],
    password: Option<&[u8]>,
    unsafe_skip_rsa_key_validation: bool,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let parsers: [fn(&[u8]) -> cryptography_key_parsing::KeyParsingResult<_>; 4] = [
        cryptography_key_parsing::pkcs8::parse_private_key,
        |d| cryptography_key_parsing::ec::parse_pkcs1_private_key(d, None),
        cryptography_key_parsing::rsa::parse_pkcs1_private_key,
        cryptography_key_parsing::dsa::parse_pkcs1_private_key,
    ];

    let pkey = parsers.iter().find_map(|parser| match parser(data) {
        Ok(key) => Some(Ok(key)),
        // Try next parser
        Err(cryptography_key_parsing::KeyParsingError::Parse(_)) => None,
        // Return non-parse errors immediately
        Err(e) => Some(Err(e)),
    });

    if let Some(Ok(pkey)) = pkey {
        if password.is_some() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "Password was given but private key is not encrypted.",
                ),
            ));
        }
        return private_key_from_pkey(py, &pkey, unsafe_skip_rsa_key_validation);
    } else if let Some(Err(e)) = pkey {
        return Err(e.into());
    }

    let pkey = cryptography_key_parsing::pkcs8::parse_encrypted_private_key(data, password)?;

    private_key_from_pkey(py, &pkey, unsafe_skip_rsa_key_validation)
}

#[pyo3::pyfunction]
#[pyo3(signature = (data, password, backend=None, *, unsafe_skip_rsa_key_validation=false))]
fn load_pem_private_key<'p>(
    py: pyo3::Python<'p>,
    data: CffiBuf<'_>,
    password: Option<CffiBuf<'_>>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    unsafe_skip_rsa_key_validation: bool,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let _ = backend;

    let p = x509::find_in_pem(
        data.as_bytes(),
        |p| ["PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY"].contains(&p.tag()),
        "Valid PEM but no BEGIN/END delimiters for a private key found. Are you sure this is a private key?"
    )?;
    let password = password.as_ref().map(|v| v.as_bytes());
    let (data, mut password_used) = cryptography_key_parsing::pem::decrypt_pem(&p, password)?;

    let pkey = match p.tag() {
        "PRIVATE KEY" => cryptography_key_parsing::pkcs8::parse_private_key(&data)?,
        "RSA PRIVATE KEY" => cryptography_key_parsing::rsa::parse_pkcs1_private_key(&data).map_err(|e| {
            CryptographyError::from(e).add_note(py, "If your key is in PKCS#8 format, you must use BEGIN/END PRIVATE KEY PEM delimiters")
        })?,
        "EC PRIVATE KEY" => cryptography_key_parsing::ec::parse_pkcs1_private_key(&data, None).map_err(|e| {
            CryptographyError::from(e).add_note(py, "If your key is in PKCS#8 format, you must use BEGIN/END PRIVATE KEY PEM delimiters")
        })?,
        "DSA PRIVATE KEY" => cryptography_key_parsing::dsa::parse_pkcs1_private_key(&data).map_err(|e| {
            CryptographyError::from(e).add_note(py, "If your key is in PKCS#8 format, you must use BEGIN/END PRIVATE KEY PEM delimiters")
        })?,
        _ => {
            assert_eq!(p.tag(), "ENCRYPTED PRIVATE KEY");
            password_used = true;
            cryptography_key_parsing::pkcs8::parse_encrypted_private_key(&data, password)?
        }
    };
    if password.is_some() && !password_used {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "Password was given but private key is not encrypted.",
            ),
        ));
    }
    private_key_from_pkey(py, &pkey, unsafe_skip_rsa_key_validation)
}

fn private_key_from_pkey<'p>(
    py: pyo3::Python<'p>,
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    unsafe_skip_rsa_key_validation: bool,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    match pkey.id() {
        openssl::pkey::Id::RSA => Ok(crate::backend::rsa::private_key_from_pkey(
            pkey,
            unsafe_skip_rsa_key_validation,
        )?
        .into_pyobject(py)?
        .into_any()),
        openssl::pkey::Id::EC => Ok(crate::backend::ec::private_key_from_pkey(py, pkey)?
            .into_pyobject(py)?
            .into_any()),
        openssl::pkey::Id::X25519 => Ok(crate::backend::x25519::private_key_from_pkey(pkey)
            .into_pyobject(py)?
            .into_any()),

        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        openssl::pkey::Id::X448 => Ok(crate::backend::x448::private_key_from_pkey(pkey)
            .into_pyobject(py)?
            .into_any()),

        openssl::pkey::Id::ED25519 => Ok(crate::backend::ed25519::private_key_from_pkey(pkey)
            .into_pyobject(py)?
            .into_any()),

        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        openssl::pkey::Id::ED448 => Ok(crate::backend::ed448::private_key_from_pkey(pkey)
            .into_pyobject(py)?
            .into_any()),
        openssl::pkey::Id::DSA => Ok(crate::backend::dsa::private_key_from_pkey(pkey)
            .into_pyobject(py)?
            .into_any()),
        openssl::pkey::Id::DH => Ok(crate::backend::dh::private_key_from_pkey(pkey)
            .into_pyobject(py)?
            .into_any()),

        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        openssl::pkey::Id::DHX => Ok(crate::backend::dh::private_key_from_pkey(pkey)
            .into_pyobject(py)?
            .into_any()),
        _ => Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err("Unsupported key type."),
        )),
    }
}

#[pyo3::pyfunction]
#[pyo3(signature = (data, backend=None))]
fn load_der_public_key<'p>(
    py: pyo3::Python<'p>,
    data: CffiBuf<'_>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let _ = backend;
    load_der_public_key_bytes(py, data.as_bytes())
}

pub(crate) fn load_der_public_key_bytes<'p>(
    py: pyo3::Python<'p>,
    data: &[u8],
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    match cryptography_key_parsing::spki::parse_public_key(data) {
        Ok(pkey) => public_key_from_pkey(py, &pkey, pkey.id()),
        // It's not a (RSA/DSA/ECDSA) subjectPublicKeyInfo, but we still need
        // to check to see if it is a pure PKCS1 RSA public key (not embedded
        // in a subjectPublicKeyInfo)
        Err(e) => {
            // Use the original error.
            let pkey =
                cryptography_key_parsing::rsa::parse_pkcs1_public_key(data).map_err(|_| e)?;
            public_key_from_pkey(py, &pkey, pkey.id())
        }
    }
}

#[pyo3::pyfunction]
#[pyo3(signature = (data, backend=None))]
fn load_pem_public_key<'p>(
    py: pyo3::Python<'p>,
    data: CffiBuf<'_>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let _ = backend;
    let p = pem::parse(data.as_bytes())?;
    let pkey = match p.tag() {
        "RSA PUBLIC KEY" => {
            // We try to parse it as a PKCS1 first since that's the PEM delimiter, and if
            // that fails we try to parse it as an SPKI. This is to match the permissiveness
            // of OpenSSL, which doesn't care about the delimiter.
            match cryptography_key_parsing::rsa::parse_pkcs1_public_key(p.contents()) {
                Ok(pkey) => pkey,
                Err(err) => {
                    let pkey = cryptography_key_parsing::spki::parse_public_key(p.contents())
                        .map_err(|_| err)?;
                    if pkey.id() != openssl::pkey::Id::RSA {
                        return Err(CryptographyError::from(
                            pyo3::exceptions::PyValueError::new_err(
                                "Incorrect PEM delimiter for key type.",
                            ),
                        ));
                    }
                    pkey
                }
            }
        }
        "PUBLIC KEY" => cryptography_key_parsing::spki::parse_public_key(p.contents())?,
        _ => return Err(CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
            "Valid PEM but no BEGIN PUBLIC KEY/END PUBLIC KEY delimiters. Are you sure this is a public key?"
        ))),
    };
    public_key_from_pkey(py, &pkey, pkey.id())
}

fn public_key_from_pkey<'p>(
    py: pyo3::Python<'p>,
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
    id: openssl::pkey::Id,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    // `id` is a separate argument so we can test this while passing something
    // unsupported.
    match id {
        openssl::pkey::Id::RSA => Ok(crate::backend::rsa::public_key_from_pkey(pkey)
            .into_pyobject(py)?
            .into_any()),
        openssl::pkey::Id::EC => Ok(crate::backend::ec::public_key_from_pkey(py, pkey)?
            .into_pyobject(py)?
            .into_any()),
        openssl::pkey::Id::X25519 => Ok(crate::backend::x25519::public_key_from_pkey(pkey)
            .into_pyobject(py)?
            .into_any()),
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        openssl::pkey::Id::X448 => Ok(crate::backend::x448::public_key_from_pkey(pkey)
            .into_pyobject(py)?
            .into_any()),

        openssl::pkey::Id::ED25519 => Ok(crate::backend::ed25519::public_key_from_pkey(pkey)
            .into_pyobject(py)?
            .into_any()),
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        openssl::pkey::Id::ED448 => Ok(crate::backend::ed448::public_key_from_pkey(pkey)
            .into_pyobject(py)?
            .into_any()),

        openssl::pkey::Id::DSA => Ok(crate::backend::dsa::public_key_from_pkey(pkey)
            .into_pyobject(py)?
            .into_any()),
        openssl::pkey::Id::DH => Ok(crate::backend::dh::public_key_from_pkey(pkey)
            .into_pyobject(py)?
            .into_any()),

        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        openssl::pkey::Id::DHX => Ok(crate::backend::dh::public_key_from_pkey(pkey)
            .into_pyobject(py)?
            .into_any()),

        _ => Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err("Unsupported key type."),
        )),
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod keys {
    #[pymodule_export]
    use super::{
        load_der_private_key, load_der_public_key, load_pem_private_key, load_pem_public_key,
    };
}

#[cfg(test)]
mod tests {
    #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
    use super::{private_key_from_pkey, public_key_from_pkey};

    #[test]
    #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
    fn test_public_key_from_pkey_unknown_key() {
        pyo3::Python::initialize();

        pyo3::Python::attach(|py| {
            let pkey =
                openssl::pkey::PKey::public_key_from_raw_bytes(&[0; 32], openssl::pkey::Id::X25519)
                    .unwrap();
            // Pass a nonsense id for this key to test the unsupported
            // algorithm path.
            assert!(public_key_from_pkey(py, &pkey, openssl::pkey::Id::CMAC).is_err());
        });
    }

    #[test]
    #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
    fn test_private_key_from_pkey_unknown_key() {
        pyo3::Python::initialize();

        pyo3::Python::attach(|py| {
            let pkey = openssl::pkey::PKey::hmac(&[0; 32]).unwrap();
            assert!(private_key_from_pkey(py, &pkey, false).is_err());
        });
    }
}
