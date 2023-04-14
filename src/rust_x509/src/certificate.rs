use crate::common;
use crate::extensions;
use crate::name;
use asn1;

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Clone)]
pub struct RawCertificate<'a> {
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
    pub extensions: Option<extensions::Extensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Clone)]
pub struct Validity {
    pub not_before: common::Time,
    pub not_after: common::Time,
}
