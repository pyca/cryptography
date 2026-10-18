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
    type Parser = fn(
        &[u8],
    ) -> cryptography_key_parsing::KeyParsingResult<
        cryptography_key_parsing::ParsedPrivateKey,
    >;
    let parsers: [Parser; 4] = [
        cryptography_key_parsing::pkcs8::parse_private_key,
        |d| {
            cryptography_key_parsing::ec::parse_pkcs1_private_key(d, None)
                .map(cryptography_key_parsing::ParsedPrivateKey::from)
        },
        |d| {
            cryptography_key_parsing::rsa::parse_pkcs1_private_key(d)
                .map(cryptography_key_parsing::ParsedPrivateKey::from)
        },
        |d| {
            cryptography_key_parsing::dsa::parse_pkcs1_private_key(d)
                .map(cryptography_key_parsing::ParsedPrivateKey::from)
        },
    ];

    let parsed = parsers.iter().find_map(|parser| match parser(data) {
        Ok(key) => Some(Ok(key)),
        // Try next parser
        Err(cryptography_key_parsing::KeyParsingError::Parse(_)) => None,
        // Return non-parse errors immediately
        Err(e) => Some(Err(e)),
    });

    if let Some(Ok(parsed)) = parsed {
        if password.is_some() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "Password was given but private key is not encrypted.",
                ),
            ));
        }
        return private_key_from_parsed(py, parsed, unsafe_skip_rsa_key_validation);
    } else if let Some(Err(e)) = parsed {
        return Err(e.into());
    }

    let parsed = cryptography_key_parsing::pkcs8::parse_encrypted_private_key(data, password)?;
    private_key_from_parsed(py, parsed, unsafe_skip_rsa_key_validation)
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

    let parsed = match p.tag() {
        "PRIVATE KEY" => cryptography_key_parsing::pkcs8::parse_private_key(&data)?,
        "RSA PRIVATE KEY" => cryptography_key_parsing::rsa::parse_pkcs1_private_key(&data).map(cryptography_key_parsing::ParsedPrivateKey::from).map_err(|e| {
            CryptographyError::from(e).add_note(py, "If your key is in PKCS#8 format, you must use BEGIN/END PRIVATE KEY PEM delimiters")
        })?,
        "EC PRIVATE KEY" => cryptography_key_parsing::ec::parse_pkcs1_private_key(&data, None).map(cryptography_key_parsing::ParsedPrivateKey::from).map_err(|e| {
            CryptographyError::from(e).add_note(py, "If your key is in PKCS#8 format, you must use BEGIN/END PRIVATE KEY PEM delimiters")
        })?,
        "DSA PRIVATE KEY" => cryptography_key_parsing::dsa::parse_pkcs1_private_key(&data).map(cryptography_key_parsing::ParsedPrivateKey::from).map_err(|e| {
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
    private_key_from_parsed(py, parsed, unsafe_skip_rsa_key_validation)
}

#[cfg(feature = "openssl")]
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
        openssl::pkey::Id::DSA => Ok(crate::backend::dsa::private_key_from_pkey(py, pkey)?
            .into_pyobject(py)?
            .into_any()),
        openssl::pkey::Id::DH => Ok(crate::backend::dh::private_key_from_pkey(py, pkey)?
            .into_pyobject(py)?
            .into_any()),

        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        openssl::pkey::Id::DHX => Ok(crate::backend::dh::private_key_from_pkey(py, pkey)?
            .into_pyobject(py)?
            .into_any()),
        #[cfg(any(
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC,
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
        ))]
        _ if cryptography_openssl::mlkem::is_mlkem_pkey(pkey) => {
            match cryptography_openssl::mlkem::MlKemVariant::from_pkey(pkey) {
                cryptography_openssl::mlkem::MlKemVariant::MlKem768 => {
                    Ok(crate::backend::mlkem::mlkem768_private_key_from_pkey(pkey)
                        .into_pyobject(py)?
                        .into_any())
                }
                cryptography_openssl::mlkem::MlKemVariant::MlKem1024 => {
                    Ok(crate::backend::mlkem::mlkem1024_private_key_from_pkey(pkey)
                        .into_pyobject(py)?
                        .into_any())
                }
            }
        }
        #[cfg(any(
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC,
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
        ))]
        _ if cryptography_openssl::mldsa::is_mldsa_pkey(pkey) => {
            match cryptography_openssl::mldsa::MlDsaVariant::from_pkey(pkey) {
                cryptography_openssl::mldsa::MlDsaVariant::MlDsa44 => {
                    Ok(crate::backend::mldsa::mldsa44_private_key_from_pkey(pkey)
                        .into_pyobject(py)?
                        .into_any())
                }
                cryptography_openssl::mldsa::MlDsaVariant::MlDsa65 => {
                    Ok(crate::backend::mldsa::mldsa65_private_key_from_pkey(pkey)
                        .into_pyobject(py)?
                        .into_any())
                }
                cryptography_openssl::mldsa::MlDsaVariant::MlDsa87 => {
                    Ok(crate::backend::mldsa::mldsa87_private_key_from_pkey(pkey)
                        .into_pyobject(py)?
                        .into_any())
                }
            }
        }
        _ => Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err("Unsupported key type."),
        )),
    }
}

fn private_key_from_parsed(
    py: pyo3::Python<'_>,
    parsed: cryptography_key_parsing::ParsedPrivateKey,
    unsafe_skip_rsa_key_validation: bool,
) -> CryptographyResult<pyo3::Bound<'_, pyo3::PyAny>> {
    match parsed {
        #[cfg(feature = "openssl")]
        cryptography_key_parsing::ParsedPrivateKey::Pkey(pkey) => {
            private_key_from_pkey(py, &pkey, unsafe_skip_rsa_key_validation)
        }
        #[cfg(feature = "verified-garbage")]
        cryptography_key_parsing::ParsedPrivateKey::Raw(key) => {
            private_key_from_raw(py, key, unsafe_skip_rsa_key_validation)
        }
    }
}

fn public_key_from_parsed(
    py: pyo3::Python<'_>,
    parsed: cryptography_key_parsing::ParsedPublicKey,
) -> CryptographyResult<pyo3::Bound<'_, pyo3::PyAny>> {
    match parsed {
        #[cfg(feature = "openssl")]
        cryptography_key_parsing::ParsedPublicKey::Pkey(pkey) => {
            public_key_from_pkey(py, &pkey, pkey.id())
        }
        #[cfg(feature = "verified-garbage")]
        cryptography_key_parsing::ParsedPublicKey::Raw(key) => public_key_from_raw(py, key),
    }
}

/// The Python object for a private key parsed into its raw components.
#[cfg(feature = "verified-garbage")]
fn private_key_from_raw(
    py: pyo3::Python<'_>,
    key: cryptography_key_parsing::raw::PrivateKey,
    unsafe_skip_rsa_key_validation: bool,
) -> CryptographyResult<pyo3::Bound<'_, pyo3::PyAny>> {
    use cryptography_key_parsing::raw::PrivateKey;
    // TODO(verified-garbage): dispatch the other key types to their modules.
    let _ = unsafe_skip_rsa_key_validation;
    match key {
        PrivateKey::X25519(k) => Ok(crate::backend::x25519::private_key_from_raw_bytes(&k)
            .into_pyobject(py)?
            .into_any()),
        PrivateKey::X448(k) => Ok(crate::backend::x448::private_key_from_raw_bytes(&k)
            .into_pyobject(py)?
            .into_any()),
        PrivateKey::Ed25519(k) => Ok(crate::backend::ed25519::private_key_from_raw_bytes(&k)
            .into_pyobject(py)?
            .into_any()),
        PrivateKey::Ed448(k) => Ok(crate::backend::ed448::private_key_from_raw_bytes(&k)
            .into_pyobject(py)?
            .into_any()),
        PrivateKey::MlKem768(k) => Ok(crate::backend::mlkem::mlkem768_private_key_from_raw(&k)?
            .into_pyobject(py)?
            .into_any()),
        PrivateKey::MlKem1024(k) => Ok(crate::backend::mlkem::mlkem1024_private_key_from_raw(&k)?
            .into_pyobject(py)?
            .into_any()),
        PrivateKey::MlDsa44(k) => Ok(crate::backend::mldsa::mldsa44_private_key_from_raw(&k)?
            .into_pyobject(py)?
            .into_any()),
        PrivateKey::MlDsa65(k) => Ok(crate::backend::mldsa::mldsa65_private_key_from_raw(&k)?
            .into_pyobject(py)?
            .into_any()),
        PrivateKey::MlDsa87(k) => Ok(crate::backend::mldsa::mldsa87_private_key_from_raw(&k)?
            .into_pyobject(py)?
            .into_any()),
        _ => Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err("Unsupported key type."),
        )),
    }
}

/// The Python object for a public key parsed into its raw components.
#[cfg(feature = "verified-garbage")]
fn public_key_from_raw(
    py: pyo3::Python<'_>,
    key: cryptography_key_parsing::raw::PublicKey,
) -> CryptographyResult<pyo3::Bound<'_, pyo3::PyAny>> {
    use cryptography_key_parsing::raw::PublicKey;
    // TODO(verified-garbage): dispatch the other key types to their modules.
    match key {
        PublicKey::X25519(k) => Ok(crate::backend::x25519::public_key_from_raw_bytes(&k)
            .into_pyobject(py)?
            .into_any()),
        PublicKey::X448(k) => Ok(crate::backend::x448::public_key_from_raw_bytes(&k)
            .into_pyobject(py)?
            .into_any()),
        PublicKey::Ed25519(k) => Ok(crate::backend::ed25519::public_key_from_raw_bytes(&k)
            .into_pyobject(py)?
            .into_any()),
        PublicKey::Ed448(k) => Ok(crate::backend::ed448::public_key_from_raw_bytes(&k)
            .into_pyobject(py)?
            .into_any()),
        PublicKey::MlKem768(k) => Ok(crate::backend::mlkem::mlkem768_public_key_from_raw(&k)?
            .into_pyobject(py)?
            .into_any()),
        PublicKey::MlKem1024(k) => Ok(crate::backend::mlkem::mlkem1024_public_key_from_raw(&k)?
            .into_pyobject(py)?
            .into_any()),
        PublicKey::MlDsa44(k) => Ok(crate::backend::mldsa::mldsa44_public_key_from_raw(&k)?
            .into_pyobject(py)?
            .into_any()),
        PublicKey::MlDsa65(k) => Ok(crate::backend::mldsa::mldsa65_public_key_from_raw(&k)?
            .into_pyobject(py)?
            .into_any()),
        PublicKey::MlDsa87(k) => Ok(crate::backend::mldsa::mldsa87_public_key_from_raw(&k)?
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
        Ok(parsed) => public_key_from_parsed(py, parsed),
        // It's not a (RSA/DSA/ECDSA) subjectPublicKeyInfo, but we still need
        // to check to see if it is a pure PKCS1 RSA public key (not embedded
        // in a subjectPublicKeyInfo)
        Err(e) => {
            // Use the original error.
            let key = cryptography_key_parsing::rsa::parse_pkcs1_public_key(data).map_err(|_| e)?;
            public_key_from_parsed(py, cryptography_key_parsing::ParsedPublicKey::from(key))
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
    let parsed = match p.tag() {
        "RSA PUBLIC KEY" => {
            // We try to parse it as a PKCS1 first since that's the PEM delimiter, and if
            // that fails we try to parse it as an SPKI. This is to match the permissiveness
            // of OpenSSL, which doesn't care about the delimiter.
            match cryptography_key_parsing::rsa::parse_pkcs1_public_key(p.contents()) {
                Ok(key) => cryptography_key_parsing::ParsedPublicKey::from(key),
                Err(err) => {
                    let parsed = cryptography_key_parsing::spki::parse_public_key(p.contents())
                        .map_err(|_| err)?;
                    if !parsed.is_rsa() {
                        return Err(CryptographyError::from(
                            pyo3::exceptions::PyValueError::new_err(
                                "Incorrect PEM delimiter for key type.",
                            ),
                        ));
                    }
                    parsed
                }
            }
        }
        "PUBLIC KEY" => cryptography_key_parsing::spki::parse_public_key(p.contents())?,
        _ => return Err(CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
            "Valid PEM but no BEGIN PUBLIC KEY/END PUBLIC KEY delimiters. Are you sure this is a public key?"
        ))),
    };
    public_key_from_parsed(py, parsed)
}

#[cfg(feature = "openssl")]
fn public_key_from_pkey<'p>(
    py: pyo3::Python<'p>,
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
    id: openssl::pkey::Id,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    // `id` is a separate argument so we can test this while passing something
    // unsupported.
    match id {
        openssl::pkey::Id::RSA => Ok(crate::backend::rsa::public_key_from_pkey(pkey)?
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

        openssl::pkey::Id::DSA => Ok(crate::backend::dsa::public_key_from_pkey(py, pkey)?
            .into_pyobject(py)?
            .into_any()),
        openssl::pkey::Id::DH => Ok(crate::backend::dh::public_key_from_pkey(py, pkey)?
            .into_pyobject(py)?
            .into_any()),

        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        openssl::pkey::Id::DHX => Ok(crate::backend::dh::public_key_from_pkey(py, pkey)?
            .into_pyobject(py)?
            .into_any()),
        #[cfg(any(
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC,
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
        ))]
        _ if cryptography_openssl::mlkem::is_mlkem_pkey(pkey) => {
            match cryptography_openssl::mlkem::MlKemVariant::from_pkey(pkey) {
                cryptography_openssl::mlkem::MlKemVariant::MlKem768 => {
                    Ok(crate::backend::mlkem::mlkem768_public_key_from_pkey(pkey)
                        .into_pyobject(py)?
                        .into_any())
                }
                cryptography_openssl::mlkem::MlKemVariant::MlKem1024 => {
                    Ok(crate::backend::mlkem::mlkem1024_public_key_from_pkey(pkey)
                        .into_pyobject(py)?
                        .into_any())
                }
            }
        }

        #[cfg(any(
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC,
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
        ))]
        _ if cryptography_openssl::mldsa::is_mldsa_pkey(pkey) => {
            match cryptography_openssl::mldsa::MlDsaVariant::from_pkey(pkey) {
                cryptography_openssl::mldsa::MlDsaVariant::MlDsa44 => {
                    Ok(crate::backend::mldsa::mldsa44_public_key_from_pkey(pkey)
                        .into_pyobject(py)?
                        .into_any())
                }
                cryptography_openssl::mldsa::MlDsaVariant::MlDsa65 => {
                    Ok(crate::backend::mldsa::mldsa65_public_key_from_pkey(pkey)
                        .into_pyobject(py)?
                        .into_any())
                }
                cryptography_openssl::mldsa::MlDsaVariant::MlDsa87 => {
                    Ok(crate::backend::mldsa::mldsa87_public_key_from_pkey(pkey)
                        .into_pyobject(py)?
                        .into_any())
                }
            }
        }
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

#[cfg(all(test, feature = "openssl"))]
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

#[cfg(all(test, feature = "verified-garbage"))]
mod vg_tests {
    use cryptography_key_parsing::raw::{PrivateKey, PublicKey};
    use pyo3::types::PyAnyMethods;

    use super::{private_key_from_raw, public_key_from_raw};

    #[test]
    fn test_raw_key_dispatch() {
        pyo3::Python::initialize();

        pyo3::Python::attach(|py| {
            let private_keys = [
                PrivateKey::X25519([1; 32]),
                PrivateKey::X448([1; 56]),
                PrivateKey::Ed25519([1; 32]),
                PrivateKey::Ed448([1; 57]),
                PrivateKey::MlKem768([1; 64]),
                PrivateKey::MlKem1024([1; 64]),
                PrivateKey::MlDsa44([1; 32]),
                PrivateKey::MlDsa65([1; 32]),
                PrivateKey::MlDsa87([1; 32]),
            ];
            for key in private_keys {
                let obj = private_key_from_raw(py, key.clone(), false)
                    .ok()
                    .expect("a key object");
                // The object's public key serializes to the derived public
                // key's raw bytes, which load back as a public key object.
                let public = obj.call_method0("public_key").unwrap();
                let raw = public
                    .call_method0("public_bytes_raw")
                    .unwrap()
                    .extract::<Vec<u8>>()
                    .unwrap();
                let parsed = match key {
                    PrivateKey::X25519(_) => PublicKey::X25519(raw.try_into().unwrap()),
                    PrivateKey::X448(_) => PublicKey::X448(raw.try_into().unwrap()),
                    PrivateKey::Ed25519(_) => PublicKey::Ed25519(raw.try_into().unwrap()),
                    PrivateKey::Ed448(_) => PublicKey::Ed448(raw.try_into().unwrap()),
                    PrivateKey::MlKem768(_) => PublicKey::MlKem768(raw),
                    PrivateKey::MlKem1024(_) => PublicKey::MlKem1024(raw),
                    PrivateKey::MlDsa44(_) => PublicKey::MlDsa44(raw),
                    PrivateKey::MlDsa65(_) => PublicKey::MlDsa65(raw),
                    PrivateKey::MlDsa87(_) => PublicKey::MlDsa87(raw),
                    _ => unreachable!(),
                };
                let loaded = public_key_from_raw(py, parsed).ok().expect("a key object");
                assert!(loaded.eq(&public).unwrap());
            }

            // A malformed encapsulation key is a ValueError.
            assert!(public_key_from_raw(py, PublicKey::MlKem768(vec![0xff; 1184])).is_err());
            assert!(public_key_from_raw(py, PublicKey::MlDsa44(vec![0; 1311])).is_err());
        });
    }
}
