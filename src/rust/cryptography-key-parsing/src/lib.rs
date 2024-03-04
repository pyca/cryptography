// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, clippy::undocumented_unsafe_blocks)]
#![allow(unknown_lints, clippy::result_large_err)]

pub mod rsa;
pub mod spki;

pub enum KeyParsingError {
    InvalidKey,
    ExplicitCurveUnsupported,
    UnsupportedKeyType(asn1::ObjectIdentifier),
    UnsupportedEllipticCurve(asn1::ObjectIdentifier),
    Parse(asn1::ParseError),
    OpenSSL(openssl::error::ErrorStack),
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

#[cfg(test)]
mod tests {
    use super::KeyParsingError;

    #[test]
    fn test_key_parsing_error_from() {
        let e = openssl::error::ErrorStack::get();

        assert!(matches!(
            KeyParsingError::from(e),
            KeyParsingError::OpenSSL(_)
        ));
    }
}
