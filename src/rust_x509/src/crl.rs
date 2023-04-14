use crate::{common, extensions, name};
use asn1;

pub type ReasonFlags<'a> =
    Option<common::Asn1ReadableOrWritable<'a, asn1::BitString<'a>, asn1::OwnedBitString>>;

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash)]
pub struct RawCertificateRevocationList<'a> {
    pub tbs_cert_list: TBSCertList<'a>,
    pub signature_algorithm: common::AlgorithmIdentifier<'a>,
    pub signature_value: asn1::BitString<'a>,
}

pub type RevokedCertificates<'a> = Option<
    common::Asn1ReadableOrWritable<
        'a,
        asn1::SequenceOf<'a, RawRevokedCertificate<'a>>,
        asn1::SequenceOfWriter<'a, RawRevokedCertificate<'a>, Vec<RawRevokedCertificate<'a>>>,
    >,
>;

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash)]
pub struct TBSCertList<'a> {
    pub version: Option<u8>,
    pub signature: common::AlgorithmIdentifier<'a>,
    pub issuer: name::Name<'a>,
    pub this_update: common::Time,
    pub next_update: Option<common::Time>,
    pub revoked_certificates: RevokedCertificates<'a>,
    #[explicit(0)]
    pub crl_extensions: Option<extensions::Extensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash, Clone)]
pub struct RawRevokedCertificate<'a> {
    pub user_certificate: asn1::BigUint<'a>,
    pub revocation_date: common::Time,
    pub crl_entry_extensions: Option<extensions::Extensions<'a>>,
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
