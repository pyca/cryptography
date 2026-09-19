// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::IntoPyObject;

use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::x509;

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
                .map(cryptography_key_parsing::ParsedPrivateKey::Ec)
        },
        |d| {
            cryptography_key_parsing::rsa::parse_pkcs1_private_key(d)
                .map(cryptography_key_parsing::ParsedPrivateKey::Rsa)
        },
        |d| {
            cryptography_key_parsing::dsa::parse_pkcs1_private_key(d)
                .map(cryptography_key_parsing::ParsedPrivateKey::Dsa)
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
        "RSA PRIVATE KEY" => cryptography_key_parsing::rsa::parse_pkcs1_private_key(&data).map(cryptography_key_parsing::ParsedPrivateKey::Rsa).map_err(|e| {
            CryptographyError::from(e).add_note(py, "If your key is in PKCS#8 format, you must use BEGIN/END PRIVATE KEY PEM delimiters")
        })?,
        "EC PRIVATE KEY" => cryptography_key_parsing::ec::parse_pkcs1_private_key(&data, None).map(cryptography_key_parsing::ParsedPrivateKey::Ec).map_err(|e| {
            CryptographyError::from(e).add_note(py, "If your key is in PKCS#8 format, you must use BEGIN/END PRIVATE KEY PEM delimiters")
        })?,
        "DSA PRIVATE KEY" => cryptography_key_parsing::dsa::parse_pkcs1_private_key(&data).map(cryptography_key_parsing::ParsedPrivateKey::Dsa).map_err(|e| {
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

fn private_key_from_parsed(
    py: pyo3::Python<'_>,
    parsed: cryptography_key_parsing::ParsedPrivateKey,
    unsafe_skip_rsa_key_validation: bool,
) -> CryptographyResult<pyo3::Bound<'_, pyo3::PyAny>> {
    match parsed {
        cryptography_key_parsing::ParsedPrivateKey::Rsa(key) => {
            Ok(crate::backend::rsa::private_key_from_components(
                key.components(),
                unsafe_skip_rsa_key_validation,
            )?
            .into_pyobject(py)?
            .into_any())
        }
        cryptography_key_parsing::ParsedPrivateKey::Ec(key) => {
            Ok(crate::backend::ec::private_key_from_key(py, key)?
                .into_pyobject(py)?
                .into_any())
        }
        cryptography_key_parsing::ParsedPrivateKey::Dsa(key) => {
            Ok(crate::backend::dsa::private_key_from_key(py, key)?
                .into_pyobject(py)?
                .into_any())
        }
        cryptography_key_parsing::ParsedPrivateKey::Dh(key) => {
            Ok(crate::backend::dh::private_key_from_key(py, key)?
                .into_pyobject(py)?
                .into_any())
        }
        cryptography_key_parsing::ParsedPrivateKey::Ed25519(key) => {
            Ok(crate::backend::ed25519::private_key_from_key(key)?
                .into_pyobject(py)?
                .into_any())
        }
        cryptography_key_parsing::ParsedPrivateKey::X25519(key) => {
            Ok(crate::backend::x25519::private_key_from_key(key)?
                .into_pyobject(py)?
                .into_any())
        }
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        cryptography_key_parsing::ParsedPrivateKey::Ed448(key) => {
            Ok(crate::backend::ed448::private_key_from_key(key)?
                .into_pyobject(py)?
                .into_any())
        }
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        cryptography_key_parsing::ParsedPrivateKey::X448(key) => {
            Ok(crate::backend::x448::private_key_from_key(key)?
                .into_pyobject(py)?
                .into_any())
        }
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        cryptography_key_parsing::ParsedPrivateKey::MlDsa(key) => match key.variant() {
            openssl_bridge::mldsa::Variant::MlDsa44 => {
                Ok(crate::backend::mldsa::mldsa44_private_key_from_key(key)?
                    .into_pyobject(py)?
                    .into_any())
            }
            openssl_bridge::mldsa::Variant::MlDsa65 => {
                Ok(crate::backend::mldsa::mldsa65_private_key_from_key(key)?
                    .into_pyobject(py)?
                    .into_any())
            }
            openssl_bridge::mldsa::Variant::MlDsa87 => {
                Ok(crate::backend::mldsa::mldsa87_private_key_from_key(key)?
                    .into_pyobject(py)?
                    .into_any())
            }
        },
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        cryptography_key_parsing::ParsedPrivateKey::MlKem(key) => match key.variant() {
            openssl_bridge::mlkem::Variant::MlKem768 => {
                Ok(crate::backend::mlkem::mlkem768_private_key_from_key(key)?
                    .into_pyobject(py)?
                    .into_any())
            }
            openssl_bridge::mlkem::Variant::MlKem1024 => {
                Ok(crate::backend::mlkem::mlkem1024_private_key_from_key(key)?
                    .into_pyobject(py)?
                    .into_any())
            }
        },
    }
}

fn public_key_from_parsed(
    py: pyo3::Python<'_>,
    parsed: cryptography_key_parsing::ParsedPublicKey,
) -> CryptographyResult<pyo3::Bound<'_, pyo3::PyAny>> {
    match parsed {
        cryptography_key_parsing::ParsedPublicKey::Rsa(key) => {
            Ok(crate::backend::rsa::public_key_from_key(key)?
                .into_pyobject(py)?
                .into_any())
        }
        cryptography_key_parsing::ParsedPublicKey::Ec(key) => {
            Ok(crate::backend::ec::public_key_from_key(py, key)?
                .into_pyobject(py)?
                .into_any())
        }
        cryptography_key_parsing::ParsedPublicKey::Dsa(key) => {
            Ok(crate::backend::dsa::public_key_from_key(py, key)?
                .into_pyobject(py)?
                .into_any())
        }
        cryptography_key_parsing::ParsedPublicKey::Dh(key) => {
            Ok(crate::backend::dh::public_key_from_key(py, key)?
                .into_pyobject(py)?
                .into_any())
        }
        cryptography_key_parsing::ParsedPublicKey::Ed25519(key) => {
            Ok(crate::backend::ed25519::public_key_from_key(key)?
                .into_pyobject(py)?
                .into_any())
        }
        cryptography_key_parsing::ParsedPublicKey::X25519(key) => {
            Ok(crate::backend::x25519::public_key_from_key(key)?
                .into_pyobject(py)?
                .into_any())
        }
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        cryptography_key_parsing::ParsedPublicKey::Ed448(key) => {
            Ok(crate::backend::ed448::public_key_from_key(key)?
                .into_pyobject(py)?
                .into_any())
        }
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        cryptography_key_parsing::ParsedPublicKey::X448(key) => {
            Ok(crate::backend::x448::public_key_from_key(key)?
                .into_pyobject(py)?
                .into_any())
        }
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        cryptography_key_parsing::ParsedPublicKey::MlDsa(key) => match key.variant() {
            openssl_bridge::mldsa::Variant::MlDsa44 => {
                Ok(crate::backend::mldsa::mldsa44_public_key_from_key(key)?
                    .into_pyobject(py)?
                    .into_any())
            }
            openssl_bridge::mldsa::Variant::MlDsa65 => {
                Ok(crate::backend::mldsa::mldsa65_public_key_from_key(key)?
                    .into_pyobject(py)?
                    .into_any())
            }
            openssl_bridge::mldsa::Variant::MlDsa87 => {
                Ok(crate::backend::mldsa::mldsa87_public_key_from_key(key)?
                    .into_pyobject(py)?
                    .into_any())
            }
        },
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        cryptography_key_parsing::ParsedPublicKey::MlKem(key) => match key.variant() {
            openssl_bridge::mlkem::Variant::MlKem768 => {
                Ok(crate::backend::mlkem::mlkem768_public_key_from_key(key)?
                    .into_pyobject(py)?
                    .into_any())
            }
            openssl_bridge::mlkem::Variant::MlKem1024 => {
                Ok(crate::backend::mlkem::mlkem1024_public_key_from_key(key)?
                    .into_pyobject(py)?
                    .into_any())
            }
        },
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
            let pkey =
                cryptography_key_parsing::rsa::parse_pkcs1_public_key(data).map_err(|_| e)?;
            public_key_from_parsed(py, cryptography_key_parsing::ParsedPublicKey::Rsa(pkey))
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
                Ok(pkey) => cryptography_key_parsing::ParsedPublicKey::Rsa(pkey),
                Err(err) => {
                    let parsed = cryptography_key_parsing::spki::parse_public_key(p.contents())
                        .map_err(|_| err)?;
                    match parsed {
                        cryptography_key_parsing::ParsedPublicKey::Rsa(_) =>
                        {
                            parsed
                        }
                        _ => {
                            return Err(CryptographyError::from(
                                pyo3::exceptions::PyValueError::new_err(
                                    "Incorrect PEM delimiter for key type.",
                                ),
                            ));
                        }
                    }
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

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod keys {
    #[pymodule_export]
    use super::{
        load_der_private_key, load_der_public_key, load_pem_private_key, load_pem_public_key,
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn unrelated_algorithm_is_rejected_by_public_parser() {
        // SubjectPublicKeyInfo with the HMAC-SHA256 OID is not an asymmetric key.
        let der = b"\x30\x11\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x09\x05\x00\x03\x01\x00";
        assert!(matches!(
            cryptography_key_parsing::spki::parse_public_key(der),
            Err(cryptography_key_parsing::KeyParsingError::UnsupportedKeyType(_))
        ));
    }
    #[test]
    fn unrelated_algorithm_is_rejected_by_private_parser() {
        let der =
            b"\x30\x13\x02\x01\x00\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x09\x05\x00\x04\x00";
        assert!(matches!(
            cryptography_key_parsing::pkcs8::parse_private_key(der),
            Err(cryptography_key_parsing::KeyParsingError::UnsupportedKeyType(_))
        ));
    }
}
