// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::{
    common,
    extensions::{self},
    name,
};

pub type ReasonFlags<'a> =
    Option<common::Asn1ReadableOrWritable<'a, asn1::BitString<'a>, asn1::OwnedBitString>>;

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash)]
pub struct CertificateRevocationList<'a> {
    pub tbs_cert_list: TBSCertList<'a>,
    pub signature_algorithm: common::AlgorithmIdentifier<'a>,
    pub signature_value: asn1::BitString<'a>,
}

pub type RevokedCertificates<'a> = Option<
    common::Asn1ReadableOrWritable<
        'a,
        asn1::SequenceOf<'a, RevokedCertificate<'a>>,
        asn1::SequenceOfWriter<'a, RevokedCertificate<'a>, Vec<RevokedCertificate<'a>>>,
    >,
>;

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash)]
pub struct TBSCertList<'a> {
    pub version: Option<u8>,
    pub signature: common::AlgorithmIdentifier<'a>,
    pub issuer: name::Name<'a>,
    pub this_update: common::Time,
    pub next_update: Option<common::Time>,
    pub revoked_certificates: RevokedCertificates<'a>,
    #[explicit(0)]
    pub raw_crl_extensions: Option<extensions::RawExtensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone)]
pub struct RevokedCertificate<'a> {
    pub user_certificate: asn1::BigUint<'a>,
    pub revocation_date: common::Time,
    pub raw_crl_entry_extensions: Option<extensions::RawExtensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct IssuingDistributionPoint<'a> {
    #[explicit(0)]
    pub distribution_point: Option<extensions::DistributionPointName<'a>>,

    #[implicit(1)]
    #[default(false)]
    pub only_contains_user_certs: bool,

    #[implicit(2)]
    #[default(false)]
    pub only_contains_ca_certs: bool,

    #[implicit(3)]
    pub only_some_reasons: ReasonFlags<'a>,

    #[implicit(4)]
    #[default(false)]
    pub indirect_crl: bool,

    #[implicit(5)]
    #[default(false)]
    pub only_contains_attribute_certs: bool,
}

pub type CRLReason = asn1::Enumerated;
