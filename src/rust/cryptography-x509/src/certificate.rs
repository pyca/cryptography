// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::common;
use crate::extensions;
use crate::extensions::Extensions;
use crate::name;

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Clone)]
pub struct Certificate<'a> {
    pub tbs_cert: TbsCertificate<'a>,
    pub signature_alg: common::AlgorithmIdentifier<'a>,
    pub signature: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Clone)]
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

impl<'a> TbsCertificate<'a> {
    pub fn extensions(&'a self) -> Result<Extensions<'a>, asn1::ObjectIdentifier> {
        Extensions::from_raw_extensions(self.raw_extensions.as_ref())
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Clone)]
pub struct Validity {
    pub not_before: common::Time,
    pub not_after: common::Time,
}
