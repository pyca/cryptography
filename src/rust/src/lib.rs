// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#![deny(rust_2018_idioms, clippy::undocumented_unsafe_blocks)]
#![allow(unknown_lints, non_local_definitions, clippy::result_large_err)]

#[cfg(not(any(
    CRYPTOGRAPHY_IS_LIBRESSL,
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC
)))]
use std::env;

#[cfg(not(any(
    CRYPTOGRAPHY_IS_LIBRESSL,
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC
)))]
use pyo3::PyTypeInfo;

#[cfg(not(any(
    CRYPTOGRAPHY_IS_LIBRESSL,
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC
)))]
use crate::error::CryptographyResult;
mod asn1;
mod backend;
mod buf;
mod cobblestone;
mod declarative_asn1;
mod error;
mod exceptions;
mod fernet;
pub(crate) mod oid;
mod padding;
mod pkcs12;
mod pkcs7;
mod pyopenssl;
pub(crate) mod serialization;
mod test_support;
pub(crate) mod types;
mod x509;

#[cfg(not(any(
    CRYPTOGRAPHY_IS_LIBRESSL,
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC
)))]
#[pyo3::pyclass(module = "cryptography.hazmat.bindings._rust")]
struct LoadedProviders {
    legacy: bool,
}

#[pyo3::pyfunction]
fn openssl_version() -> i64 {
    openssl_bridge::runtime::version_number() as i64
}

#[pyo3::pyfunction]
fn has_implicit_rsa_rejection() -> bool {
    openssl_bridge::runtime::has_implicit_rsa_rejection()
}

#[pyo3::pyfunction]
fn openssl_version_text() -> String {
    openssl_bridge::runtime::version_text()
}

#[pyo3::pyfunction]
fn is_fips_enabled() -> bool {
    openssl_bridge::runtime::is_fips_enabled()
}

#[cfg(not(any(
    CRYPTOGRAPHY_IS_LIBRESSL,
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC
)))]
fn _initialize_providers(py: pyo3::Python<'_>) -> CryptographyResult<LoadedProviders> {
    // As of OpenSSL 3.0.0 we must register a legacy cipher provider
    // to get RC2 (needed for junk asymmetric private key
    // serialization), RC4, Blowfish, IDEA, SEED, etc. These things
    // are ugly legacy, but we aren't going to get rid of them
    // any time soon.

    let load_legacy = !cfg!(CRYPTOGRAPHY_BUILD_OPENSSL_NO_LEGACY)
        && !env::var("CRYPTOGRAPHY_OPENSSL_NO_LEGACY").is_ok_and(|v| !v.is_empty() && v != "0");

    let legacy = if load_legacy {
        let legacy_result = openssl_bridge::runtime::load_legacy_provider();
        if legacy_result.is_err() {
            let message = c"OpenSSL 3's legacy provider failed to load. Legacy algorithms will not be available. If you need those algorithms, check your OpenSSL configuration.";
            let warning_cls = pyo3::exceptions::PyWarning::type_object(py);
            pyo3::PyErr::warn(py, &warning_cls, message, 1)?;

            false
        } else {
            legacy_result?;
            true
        }
    } else {
        false
    };
    openssl_bridge::runtime::load_default_provider()?;
    Ok(LoadedProviders { legacy })
}

#[cfg(not(any(
    CRYPTOGRAPHY_IS_LIBRESSL,
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC
)))]
// NO-COVERAGE-START
#[pyo3::pyfunction]
// NO-COVERAGE-END
fn enable_fips(_providers: &LoadedProviders) -> CryptographyResult<()> {
    openssl_bridge::runtime::require_fips_enabled()?;
    Ok(())
}

#[pyo3::pymodule(gil_used = false)]
mod _rust {
    use pyo3::types::PyModuleMethods;

    #[pymodule_export]
    use crate::asn1::asn1_mod;
    #[pymodule_export]
    use crate::cobblestone::cobblestone_mod;
    #[pymodule_export]
    use crate::exceptions::exceptions;
    #[pymodule_export]
    use crate::fernet::fernet_mod;
    #[pymodule_export]
    use crate::oid::ObjectIdentifier;
    #[pymodule_export]
    use crate::padding::{
        ANSIX923PaddingContext, ANSIX923UnpaddingContext, PKCS7PaddingContext,
        PKCS7UnpaddingContext,
    };
    #[pymodule_export]
    use crate::pkcs12::pkcs12;
    #[pymodule_export]
    use crate::pkcs7::pkcs7_mod;
    #[pymodule_export]
    use crate::pyopenssl::pyopenssl;
    #[pymodule_export]
    use crate::serialization::{Encoding, ParameterFormat, PrivateFormat, PublicFormat};
    #[pymodule_export]
    use crate::test_support::test_support;

    #[pyo3::pymodule(gil_used = false)]
    mod declarative_asn1 {
        #[pymodule_export]
        use crate::declarative_asn1::asn1::{decode_der, encode_der};
        #[pymodule_export]
        use crate::declarative_asn1::types::{
            non_root_python_to_rust, AnnotatedType, Annotation, BitString, Encoding,
            GeneralizedTime, IA5String, Null, PrintableString, SetOf, Size, Tlv, Type, UtcTime,
            Variant,
        };
    }

    #[pyo3::pymodule(gil_used = false)]
    mod x509 {
        #[pymodule_export]
        use crate::x509::certificate::{
            create_x509_certificate, load_der_x509_certificate, load_pem_x509_certificate,
            load_pem_x509_certificates, Certificate,
        };
        #[pymodule_export]
        use crate::x509::common::{encode_extension_value, encode_name_bytes, parse_name_bytes};
        #[pymodule_export]
        use crate::x509::crl::{
            create_revoked_certificate, create_x509_crl, load_der_x509_crl, load_pem_x509_crl,
            CertificateRevocationList, RevokedCertificate,
        };
        #[pymodule_export]
        use crate::x509::csr::{
            create_x509_csr, load_der_x509_csr, load_pem_x509_csr, CertificateSigningRequest,
        };
        #[pymodule_export]
        use crate::x509::sct::Sct;
        #[pymodule_export]
        use crate::x509::verify::{
            PolicyBuilder, PyClientVerifier, PyCriticality, PyExtensionPolicy, PyPolicy,
            PyServerVerifier, PyStore, PyVerifiedClient, VerificationError,
        };
    }

    #[pyo3::pymodule(gil_used = false)]
    mod ocsp {
        #[pymodule_export]
        use crate::x509::ocsp_req::{create_ocsp_request, load_der_ocsp_request, OCSPRequest};
        #[pymodule_export]
        use crate::x509::ocsp_resp::{
            create_ocsp_response, load_der_ocsp_response, OCSPResponse, OCSPSingleResponse,
        };
    }

    #[pyo3::pymodule(gil_used = false)]
    mod openssl {
        use pyo3::prelude::PyModuleMethods;

        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        #[pymodule_export]
        use super::super::enable_fips;
        #[pymodule_export]
        use super::super::{
            has_implicit_rsa_rejection, is_fips_enabled, openssl_version, openssl_version_text,
        };
        #[pymodule_export]
        use crate::backend::aead::aead;
        #[pymodule_export]
        use crate::backend::ciphers::ciphers;
        #[pymodule_export]
        use crate::backend::cmac::cmac;
        #[pymodule_export]
        use crate::backend::dh::dh;
        #[pymodule_export]
        use crate::backend::dsa::dsa;
        #[pymodule_export]
        use crate::backend::ec::ec;
        #[pymodule_export]
        use crate::backend::ed25519::ed25519;
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        #[pymodule_export]
        use crate::backend::ed448::ed448;
        #[pymodule_export]
        use crate::backend::hashes::hashes;
        #[pymodule_export]
        use crate::backend::hmac::hmac;
        #[pymodule_export]
        use crate::backend::hpke::hpke;
        #[pymodule_export]
        use crate::backend::kdf::kdf;
        #[pymodule_export]
        use crate::backend::keys::keys;
        #[pymodule_export]
        use crate::backend::keywrap::keywrap;
        #[cfg(any(
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC,
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
        ))]
        #[pymodule_export]
        use crate::backend::mldsa::mldsa;
        #[cfg(any(
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC,
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
        ))]
        #[pymodule_export]
        use crate::backend::mlkem::mlkem;
        #[pymodule_export]
        use crate::backend::poly1305::poly1305;
        #[pymodule_export]
        use crate::backend::rsa::rsa;
        #[pymodule_export]
        use crate::backend::x25519::x25519;
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        #[pymodule_export]
        use crate::backend::x448::x448;
        #[pymodule_export]
        use crate::error::{capture_error_stack, raise_openssl_error, OpenSSLError};

        #[pymodule_export]
        const CRYPTOGRAPHY_OPENSSL_309_OR_GREATER: bool = cfg!(CRYPTOGRAPHY_OPENSSL_309_OR_GREATER);
        #[pymodule_export]
        const CRYPTOGRAPHY_OPENSSL_320_OR_GREATER: bool = cfg!(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER);
        #[pymodule_export]
        const CRYPTOGRAPHY_OPENSSL_330_OR_GREATER: bool = cfg!(CRYPTOGRAPHY_OPENSSL_330_OR_GREATER);
        #[pymodule_export]
        const CRYPTOGRAPHY_OPENSSL_350_OR_GREATER: bool = cfg!(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER);

        #[pymodule_export]
        const CRYPTOGRAPHY_IS_LIBRESSL: bool = cfg!(CRYPTOGRAPHY_IS_LIBRESSL);
        #[pymodule_export]
        const CRYPTOGRAPHY_IS_BORINGSSL: bool = cfg!(CRYPTOGRAPHY_IS_BORINGSSL);
        #[pymodule_export]
        const CRYPTOGRAPHY_IS_AWSLC: bool = cfg!(CRYPTOGRAPHY_IS_AWSLC);

        #[pymodule_init]
        fn init(openssl_mod: &pyo3::Bound<'_, pyo3::types::PyModule>) -> pyo3::PyResult<()> {
            openssl_bridge::initialize().map_err(crate::error::CryptographyError::from)?;
            cfg_if::cfg_if! {
                if #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))] {
                    let providers = super::super::_initialize_providers(openssl_mod.py())?;
                    if providers.legacy {
                        openssl_mod.add("_legacy_provider_loaded", true)?;
                    } else {
                        openssl_mod.add("_legacy_provider_loaded", false)?;
                    }
                    openssl_mod.add("_providers", providers)?;
                } else {
                    // default value for non-OpenSSL implementations
                    openssl_mod.add("_legacy_provider_loaded", false)?;
                }
            }

            Ok(())
        }
    }

    #[pymodule_init]
    fn init(m: &pyo3::Bound<'_, pyo3::types::PyModule>) -> pyo3::PyResult<()> {
        m.add("_PACKAGE_VERSION", env!("CRYPTOGRAPHY_PACKAGE_VERSION"))?;
        m.add_submodule(&cryptography_cffi::create_module(m.py())?)?;

        Ok(())
    }
}
