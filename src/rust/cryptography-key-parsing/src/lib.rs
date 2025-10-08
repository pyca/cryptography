// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, clippy::undocumented_unsafe_blocks)]
#![allow(unknown_lints, clippy::result_large_err)]

pub mod dsa;
pub mod ec;
pub mod pem;
pub mod pkcs8;
pub mod rsa;
pub mod spki;
pub(crate) mod utils;

pub const MIN_DH_MODULUS_SIZE: u32 = 512;

pub enum KeyParsingError {
    InvalidKey,
    ExplicitCurveUnsupported,
    UnsupportedKeyType(asn1::ObjectIdentifier),
    UnsupportedEllipticCurve(asn1::ObjectIdentifier),
    Parse(asn1::ParseError),
    OpenSSL(openssl::error::ErrorStack),
    UnsupportedEncryptionAlgorithm(asn1::ObjectIdentifier),
    EncryptedKeyWithoutPassword,
    IncorrectPassword,
    // PEM encryption errors
    PemMissingDekInfo,
    PemInvalidDekInfo,
    PemInvalidIv,
    PemUnableToDeriveKey,
    PemUnsupportedCipher,
    PemInvalidProcType,
}

impl From<asn1::ParseError> for KeyParsingError {
    fn from(e: asn1::ParseError) -> KeyParsingError {
        KeyParsingError::Parse(e)
    }
}

impl From<openssl::error::ErrorStack> for KeyParsingError {
    fn from(e: openssl::error::ErrorStack) -> KeyParsingError {
        KeyParsingError::OpenSSL(e)
    }
}

pub type KeyParsingResult<T> = Result<T, KeyParsingError>;

pub enum KeySerializationError {
    Write(asn1::WriteError),
    OpenSSL(openssl::error::ErrorStack),
}

impl From<asn1::WriteError> for KeySerializationError {
    fn from(e: asn1::WriteError) -> KeySerializationError {
        KeySerializationError::Write(e)
    }
}

impl From<openssl::error::ErrorStack> for KeySerializationError {
    fn from(e: openssl::error::ErrorStack) -> KeySerializationError {
        KeySerializationError::OpenSSL(e)
    }
}

pub type KeySerializationResult<T> = Result<T, KeySerializationError>;

#[cfg(test)]
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
