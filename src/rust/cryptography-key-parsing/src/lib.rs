// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, clippy::undocumented_unsafe_blocks)]
#![allow(unknown_lints, clippy::result_large_err)]

pub(crate) mod common;
#[cfg(feature = "openssl")]
pub mod dsa;
#[cfg(feature = "verified-garbage")]
#[path = "vg/dsa.rs"]
pub mod dsa;
#[cfg(feature = "openssl")]
pub mod ec;
#[cfg(feature = "verified-garbage")]
#[path = "vg/ec.rs"]
pub mod ec;
pub mod pbe;
#[cfg(feature = "openssl")]
pub mod pem;
#[cfg(feature = "verified-garbage")]
#[path = "vg/pem.rs"]
pub mod pem;
#[cfg(feature = "openssl")]
pub mod pkcs8;
#[cfg(feature = "verified-garbage")]
#[path = "vg/pkcs8.rs"]
pub mod pkcs8;
#[cfg(feature = "verified-garbage")]
pub mod raw;
#[cfg(feature = "openssl")]
pub mod rsa;
#[cfg(feature = "verified-garbage")]
#[path = "vg/rsa.rs"]
pub mod rsa;
#[cfg(feature = "openssl")]
pub mod spki;
#[cfg(feature = "verified-garbage")]
#[path = "vg/spki.rs"]
pub mod spki;
#[cfg(feature = "openssl")]
pub(crate) mod utils;
#[cfg(feature = "verified-garbage")]
#[path = "vg/cipher.rs"]
pub(crate) mod vg_cipher;
#[cfg(feature = "verified-garbage")]
#[path = "vg/util.rs"]
pub(crate) mod vg_util;

pub const MIN_DH_MODULUS_SIZE: u32 = 512;

pub enum KeyParsingError {
    InvalidKey,
    ExplicitCurveUnsupported,
    UnsupportedKeyType(asn1::ObjectIdentifier),
    UnsupportedEllipticCurve(asn1::ObjectIdentifier),
    Parse(asn1::ParseError),
    #[cfg(feature = "openssl")]
    OpenSSL(openssl::error::ErrorStack),
    UnsupportedEncryptionAlgorithm(asn1::ObjectIdentifier),
    EncryptedKeyWithoutPassword,
    IncorrectPassword,
    TruncatedEcPrivateKey,
    // PEM encryption errors
    PemMissingDekInfo,
    PemInvalidDekInfo,
    PemInvalidIv,
    PemUnableToDeriveKey,
    PemUnsupportedCipher,
    PemInvalidProcType,
    /// A verified-garbage operation failed unexpectedly (the counterpart of
    /// `OpenSSL`).
    #[cfg(feature = "verified-garbage")]
    VerifiedGarbage(&'static str),
}

impl From<asn1::ParseError> for KeyParsingError {
    fn from(e: asn1::ParseError) -> KeyParsingError {
        KeyParsingError::Parse(e)
    }
}

#[cfg(feature = "openssl")]
impl From<openssl::error::ErrorStack> for KeyParsingError {
    fn from(e: openssl::error::ErrorStack) -> KeyParsingError {
        KeyParsingError::OpenSSL(e)
    }
}

#[cfg(feature = "verified-garbage")]
impl From<cryptography_crypto::hash::Error> for KeyParsingError {
    fn from(_: cryptography_crypto::hash::Error) -> KeyParsingError {
        KeyParsingError::VerifiedGarbage("hash")
    }
}

pub type KeyParsingResult<T> = Result<T, KeyParsingError>;

pub enum ParsedPrivateKey {
    #[cfg(feature = "openssl")]
    Pkey(openssl::pkey::PKey<openssl::pkey::Private>),
    /// With verified-garbage, keys are parsed into their raw components,
    /// which the backend validates and turns into its key objects.
    #[cfg(feature = "verified-garbage")]
    Raw(raw::PrivateKey),
}

pub enum ParsedPublicKey {
    #[cfg(feature = "openssl")]
    Pkey(openssl::pkey::PKey<openssl::pkey::Public>),
    #[cfg(feature = "verified-garbage")]
    Raw(raw::PublicKey),
}

#[cfg(feature = "openssl")]
impl From<openssl::pkey::PKey<openssl::pkey::Private>> for ParsedPrivateKey {
    fn from(pkey: openssl::pkey::PKey<openssl::pkey::Private>) -> ParsedPrivateKey {
        ParsedPrivateKey::Pkey(pkey)
    }
}

#[cfg(feature = "openssl")]
impl From<openssl::pkey::PKey<openssl::pkey::Public>> for ParsedPublicKey {
    fn from(pkey: openssl::pkey::PKey<openssl::pkey::Public>) -> ParsedPublicKey {
        ParsedPublicKey::Pkey(pkey)
    }
}

#[cfg(feature = "verified-garbage")]
impl From<raw::RsaPrivateKey> for ParsedPrivateKey {
    fn from(key: raw::RsaPrivateKey) -> ParsedPrivateKey {
        ParsedPrivateKey::Raw(raw::PrivateKey::Rsa(key))
    }
}

#[cfg(feature = "verified-garbage")]
impl From<raw::EcPrivateKey> for ParsedPrivateKey {
    fn from(key: raw::EcPrivateKey) -> ParsedPrivateKey {
        ParsedPrivateKey::Raw(raw::PrivateKey::Ec(key))
    }
}

#[cfg(feature = "verified-garbage")]
impl From<raw::DsaPrivateKey> for ParsedPrivateKey {
    fn from(key: raw::DsaPrivateKey) -> ParsedPrivateKey {
        ParsedPrivateKey::Raw(raw::PrivateKey::Dsa(key))
    }
}

#[cfg(feature = "verified-garbage")]
impl From<raw::RsaPublicKey> for ParsedPublicKey {
    fn from(key: raw::RsaPublicKey) -> ParsedPublicKey {
        ParsedPublicKey::Raw(raw::PublicKey::Rsa(key))
    }
}

impl ParsedPublicKey {
    /// Whether this is an RSA key. `id-RSASSA-PSS` keys count: as with
    /// OpenSSL, which parses them into plain RSA keys.
    pub fn is_rsa(&self) -> bool {
        match self {
            #[cfg(feature = "openssl")]
            ParsedPublicKey::Pkey(pkey) => pkey.id() == openssl::pkey::Id::RSA,
            #[cfg(feature = "verified-garbage")]
            ParsedPublicKey::Raw(key) => {
                matches!(key, raw::PublicKey::Rsa(_) | raw::PublicKey::RsaPss(_))
            }
        }
    }
}

pub enum KeySerializationError {
    PasswordMustBeUtf8,
    Write(asn1::WriteError),
    #[cfg(feature = "openssl")]
    OpenSSL(openssl::error::ErrorStack),
    /// A verified-garbage operation (or the system's random number
    /// generator) failed unexpectedly.
    #[cfg(feature = "verified-garbage")]
    VerifiedGarbage(&'static str),
}

#[cfg(feature = "verified-garbage")]
impl From<cryptography_crypto::hash::Error> for KeySerializationError {
    fn from(_: cryptography_crypto::hash::Error) -> KeySerializationError {
        KeySerializationError::VerifiedGarbage("hash")
    }
}

impl From<asn1::WriteError> for KeySerializationError {
    fn from(e: asn1::WriteError) -> KeySerializationError {
        KeySerializationError::Write(e)
    }
}

#[cfg(feature = "openssl")]
impl From<openssl::error::ErrorStack> for KeySerializationError {
    fn from(e: openssl::error::ErrorStack) -> KeySerializationError {
        KeySerializationError::OpenSSL(e)
    }
}

pub type KeySerializationResult<T> = Result<T, KeySerializationError>;

#[cfg(all(test, feature = "openssl"))]
mod tests {
    use super::{KeyParsingError, KeySerializationError};

    #[test]
    fn test_key_parsing_error_from() {
        let e = openssl::error::ErrorStack::get();

        assert!(matches!(
            KeyParsingError::from(e),
            KeyParsingError::OpenSSL(_)
        ));
    }

    #[test]
    fn test_key_serialization_error_from_asn1_write_error() {
        let e = asn1::WriteError::AllocationError;
        assert!(matches!(
            KeySerializationError::from(e),
            KeySerializationError::Write(asn1::WriteError::AllocationError)
        ));
    }

    #[test]
    fn test_key_serialization_error_from_openssl_error_stack() {
        let e = openssl::error::ErrorStack::get();
        assert!(matches!(
            KeySerializationError::from(e),
            KeySerializationError::OpenSSL(_)
        ));
    }
}
