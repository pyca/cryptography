// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::{
    certificate, common, crl,
    extensions::{self},
    name, ocsp_req,
};

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct OCSPResponse<'a> {
    pub response_status: asn1::Enumerated,
    #[explicit(0)]
    pub response_bytes: Option<ResponseBytes<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ResponseBytes<'a> {
    pub response_type: asn1::ObjectIdentifier,
    pub response: asn1::OctetStringEncoded<BasicOCSPResponse<'a>>,
}

pub type OCSPCerts<'a> = Option<
    common::Asn1ReadableOrWritable<
        'a,
        asn1::SequenceOf<'a, certificate::Certificate<'a>>,
        asn1::SequenceOfWriter<'a, certificate::Certificate<'a>, Vec<certificate::Certificate<'a>>>,
    >,
>;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct BasicOCSPResponse<'a> {
    pub tbs_response_data: ResponseData<'a>,
    pub signature_algorithm: common::AlgorithmIdentifier<'a>,
    pub signature: asn1::BitString<'a>,
    #[explicit(0)]
    pub certs: OCSPCerts<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ResponseData<'a> {
    #[explicit(0)]
    #[default(0)]
    pub version: u8,
    pub responder_id: ResponderId<'a>,
    pub produced_at: asn1::GeneralizedTime,
    pub responses: common::Asn1ReadableOrWritable<
        'a,
        asn1::SequenceOf<'a, SingleResponse<'a>>,
        asn1::SequenceOfWriter<'a, SingleResponse<'a>, Vec<SingleResponse<'a>>>,
    >,
    #[explicit(1)]
    pub raw_response_extensions: Option<extensions::RawExtensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub enum ResponderId<'a> {
    #[explicit(1)]
    ByName(name::Name<'a>),
    #[explicit(2)]
    ByKey(&'a [u8]),
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct SingleResponse<'a> {
    pub cert_id: ocsp_req::CertID<'a>,
    pub cert_status: CertStatus,
    pub this_update: asn1::GeneralizedTime,
    #[explicit(0)]
    pub next_update: Option<asn1::GeneralizedTime>,
    #[explicit(1)]
    pub raw_single_extensions: Option<extensions::RawExtensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub enum CertStatus {
    #[implicit(0)]
    Good(()),
    #[implicit(1)]
    Revoked(RevokedInfo),
    #[implicit(2)]
    Unknown(()),
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct RevokedInfo {
    pub revocation_time: asn1::GeneralizedTime,
    #[explicit(0)]
    pub revocation_reason: Option<crl::CRLReason>,
}
