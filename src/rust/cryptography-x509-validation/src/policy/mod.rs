// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::ObjectIdentifier;
use cryptography_x509::certificate::Certificate;

use crate::{certificate::CertificateError, ops::CryptoOps};

#[derive(Debug, PartialEq)]
pub enum ProfileError {
    Cert(CertificateError),
    Other(&'static str),
}

impl From<asn1::ParseError> for ProfileError {
    fn from(value: asn1::ParseError) -> Self {
        Self::Cert(CertificateError::Malformed(value))
    }
}

impl From<CertificateError> for ProfileError {
    fn from(value: CertificateError) -> Self {
        Self::Cert(value)
    }
}

impl From<&'static str> for ProfileError {
    fn from(value: &'static str) -> Self {
        Self::Other(value)
    }
}

pub trait Profile<B: CryptoOps> {
    /// Critical CA certificate extensions that this profile is aware of.
    ///
    /// These are checked by the surrounding policy, in addition to any
    /// other extensions that the user asserts as critical.
    ///
    /// NOTE: Inclusion in this list doesn't mean that the extension is
    /// *required* to be critical, or that it must appear in a CA certificate,
    /// only that a CA certificate that contains such a critical extension
    /// will be considered accounted for.
    const CRITICAL_CA_EXTENSIONS: &'static [ObjectIdentifier];

    /// Critical EE certificate extensions that this profile is aware of.
    ///
    /// These are checked by the surrounding policy, in addition to any
    /// other extensions that the user asserts as critical.
    ///
    /// NOTE: Inclusion in this list doesn't mean that the extension is
    /// *required* to be critical, or that it must appear in an EE certificate,
    /// only that an EE certificate that contains such a critical extension
    /// will be considered accounted for.
    const CRITICAL_EE_EXTENSIONS: &'static [ObjectIdentifier];

    /// Returns a `Result` indicating whether the given certificate
    /// meet the "basic" (i.e., both CA and EE) requirements of this profile.
    fn permits_basic(&self, ops: &B, cert: &Certificate) -> Result<(), ProfileError>;

    /// Returns a `Result` indicating whether the given certificate is
    /// considered a valid CA certificate under this profile.
    fn permits_ca(&self, ops: &B, cert: &Certificate) -> Result<(), ProfileError>;

    /// Returns a `Result` indicating whether the given certificate is
    /// considered a valid end entity certificate under this profile.
    fn permits_ee(&self, ops: &B, cert: &Certificate) -> Result<(), ProfileError>;
}
