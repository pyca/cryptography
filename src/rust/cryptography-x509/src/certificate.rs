// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::common;
use crate::extensions;
use crate::extensions::{Extension, Extensions};
use crate::name;
use crate::name::NameReadable;

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

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Eq, Clone)]
pub struct Certificate<'a> {
    pub tbs_cert: TbsCertificate<'a>,
    pub signature_alg: common::AlgorithmIdentifier<'a>,
    pub signature: asn1::BitString<'a>,
}

impl Certificate<'_> {
    /// Returns the certificate's issuer.
    pub fn issuer(&self) -> &NameReadable<'_> {
        self.tbs_cert.issuer.unwrap_read()
    }

    /// Returns the certificate's subject.
    pub fn subject(&self) -> &NameReadable<'_> {
        self.tbs_cert.subject.unwrap_read()
    }

    /// Returns whether the certificate is "self-issued", whether its
    /// issuer and subject are the same.
    pub fn is_self_issued(&self) -> bool {
        self.issuer() == self.subject()
    }

    /// Returns an iterable container over the certificate's extension, or
    /// an error if the extension set contains a duplicate extension.
    pub fn extensions(&self) -> Result<Extensions<'_>, CertificateError> {
        self.tbs_cert
            .extensions()
            .map_err(CertificateError::DuplicateExtension)
    }

    /// Returns whether the given extension (by OID) is critical, or
    /// false if the extension is not present.
    pub fn extension_is_critical(&self, oid: &asn1::ObjectIdentifier) -> bool {
        match self.extensions() {
            Ok(exts) => exts
                .get_extension(oid)
                .map(|ext| ext.critical)
                .unwrap_or(false),
            Err(_) => false,
        }
    }

    /// Returns a specific extension by OID.
    pub fn extension(
        &self,
        oid: &asn1::ObjectIdentifier,
    ) -> Result<Option<Extension<'_>>, CertificateError> {
        Ok(self.extensions()?.get_extension(oid))
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Eq, Clone)]
pub struct TbsCertificate<'a> {
    #[explicit(0)]
    #[default(0)]
    pub version: u8,
    pub serial: asn1::BigInt<'a>,
    pub signature_alg: common::AlgorithmIdentifier<'a>,

    pub issuer: name::Name<'a>,
    pub validity: Validity,
    pub subject: name::Name<'a>,

    pub spki: common::SubjectPublicKeyInfo<'a>,
    #[implicit(1)]
    pub issuer_unique_id: Option<asn1::BitString<'a>>,
    #[implicit(2)]
    pub subject_unique_id: Option<asn1::BitString<'a>>,
    #[explicit(3)]
    pub raw_extensions: Option<extensions::RawExtensions<'a>>,
}

impl TbsCertificate<'_> {
    pub fn extensions(&self) -> Result<Extensions<'_>, asn1::ObjectIdentifier> {
        Extensions::from_raw_extensions(self.raw_extensions.as_ref())
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Eq, Clone)]
pub struct Validity {
    pub not_before: common::Time,
    pub not_after: common::Time,
}
