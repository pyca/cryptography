// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#[derive(Debug, PartialEq)]
pub enum CertificateError {
    DuplicateExtension(asn1::ObjectIdentifier),
    Malformed(asn1::ParseError),
}

impl From<asn1::ParseError> for CertificateError {
    fn from(value: asn1::ParseError) -> Self {
        CertificateError::Malformed(value)
    }
}
