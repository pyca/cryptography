// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::{certificate, common, csr, name};

pub const PKCS7_DATA_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 7, 1);
pub const PKCS7_SIGNED_DATA_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 7, 2);

#[derive(asn1::Asn1Write)]
pub struct ContentInfo<'a> {
    pub _content_type: asn1::DefinedByMarker<asn1::ObjectIdentifier>,

    #[defined_by(_content_type)]
    pub content: Content<'a>,
}

#[derive(asn1::Asn1DefinedByWrite)]
pub enum Content<'a> {
    #[defined_by(PKCS7_SIGNED_DATA_OID)]
    SignedData(asn1::Explicit<'a, Box<SignedData<'a>>, 0>),
    #[defined_by(PKCS7_DATA_OID)]
    Data(Option<asn1::Explicit<'a, &'a [u8], 0>>),
}

#[derive(asn1::Asn1Write)]
pub struct SignedData<'a> {
    pub version: u8,
    pub digest_algorithms: asn1::SetOfWriter<'a, common::AlgorithmIdentifier<'a>>,
    pub content_info: ContentInfo<'a>,
    #[implicit(0)]
    pub certificates: Option<asn1::SetOfWriter<'a, &'a certificate::Certificate<'a>>>,

    // We don't ever supply any of these, so for now, don't fill out the fields.
    #[implicit(1)]
    pub crls: Option<asn1::SetOfWriter<'a, asn1::Sequence<'a>>>,

    pub signer_infos: asn1::SetOfWriter<'a, SignerInfo<'a>>,
}

#[derive(asn1::Asn1Write)]
pub struct SignerInfo<'a> {
    pub version: u8,
    pub issuer_and_serial_number: IssuerAndSerialNumber<'a>,
    pub digest_algorithm: common::AlgorithmIdentifier<'a>,
    #[implicit(0)]
    pub authenticated_attributes: Option<csr::Attributes<'a>>,

    pub digest_encryption_algorithm: common::AlgorithmIdentifier<'a>,
    pub encrypted_digest: &'a [u8],

    #[implicit(1)]
    pub unauthenticated_attributes: Option<csr::Attributes<'a>>,
}

#[derive(asn1::Asn1Write)]
pub struct IssuerAndSerialNumber<'a> {
    pub issuer: name::Name<'a>,
    pub serial_number: asn1::BigInt<'a>,
}
