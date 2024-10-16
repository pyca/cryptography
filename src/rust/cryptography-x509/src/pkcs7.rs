// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::{certificate, common, csr, name};

pub const PKCS7_DATA_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 7, 1);
pub const PKCS7_SIGNED_DATA_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 7, 2);
pub const PKCS7_ENVELOPED_DATA_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 7, 3);
pub const PKCS7_ENCRYPTED_DATA_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 7, 6);

#[derive(asn1::Asn1Write, asn1::Asn1Read)]
pub struct ContentInfo<'a> {
    pub _content_type: asn1::DefinedByMarker<asn1::ObjectIdentifier>,

    #[defined_by(_content_type)]
    pub content: Content<'a>,
}

#[derive(asn1::Asn1DefinedByWrite, asn1::Asn1DefinedByRead)]
pub enum Content<'a> {
    #[defined_by(PKCS7_ENVELOPED_DATA_OID)]
    EnvelopedData(asn1::Explicit<Box<EnvelopedData<'a>>, 0>),
    #[defined_by(PKCS7_SIGNED_DATA_OID)]
    SignedData(asn1::Explicit<Box<SignedData<'a>>, 0>),
    #[defined_by(PKCS7_DATA_OID)]
    Data(Option<asn1::Explicit<&'a [u8], 0>>),
    #[defined_by(PKCS7_ENCRYPTED_DATA_OID)]
    EncryptedData(asn1::Explicit<EncryptedData<'a>, 0>),
}

#[derive(asn1::Asn1Write, asn1::Asn1Read)]
pub struct SignedData<'a> {
    pub version: u8,
    pub digest_algorithms: common::Asn1ReadableOrWritable<
        asn1::SetOf<'a, common::AlgorithmIdentifier<'a>>,
        asn1::SetOfWriter<'a, common::AlgorithmIdentifier<'a>>,
    >,
    pub content_info: ContentInfo<'a>,
    #[implicit(0)]
    pub certificates: Option<
        common::Asn1ReadableOrWritable<
            asn1::SetOf<'a, certificate::Certificate<'a>>,
            asn1::SetOfWriter<'a, &'a certificate::Certificate<'a>>,
        >,
    >,

    // We don't ever supply any of these, so for now, don't fill out the fields.
    #[implicit(1)]
    pub crls: Option<
        common::Asn1ReadableOrWritable<
            asn1::SetOf<'a, asn1::Sequence<'a>>,
            asn1::SetOfWriter<'a, asn1::Sequence<'a>>,
        >,
    >,

    pub signer_infos: common::Asn1ReadableOrWritable<
        asn1::SetOf<'a, SignerInfo<'a>>,
        asn1::SetOfWriter<'a, SignerInfo<'a>>,
    >,
}

#[derive(asn1::Asn1Write, asn1::Asn1Read)]
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

#[derive(asn1::Asn1Write, asn1::Asn1Read)]
pub struct EnvelopedData<'a> {
    pub version: u8,
    pub recipient_infos: common::Asn1ReadableOrWritable<
        asn1::SetOf<'a, RecipientInfo<'a>>,
        asn1::SetOfWriter<'a, RecipientInfo<'a>>,
    >,
    pub encrypted_content_info: EncryptedContentInfo<'a>,
}

#[derive(asn1::Asn1Write, asn1::Asn1Read)]
pub struct RecipientInfo<'a> {
    pub version: u8,
    pub issuer_and_serial_number: IssuerAndSerialNumber<'a>,
    pub key_encryption_algorithm: common::AlgorithmIdentifier<'a>,
    pub encrypted_key: &'a [u8],
}

#[derive(asn1::Asn1Write, asn1::Asn1Read)]
pub struct IssuerAndSerialNumber<'a> {
    pub issuer: name::Name<'a>,
    pub serial_number: asn1::BigInt<'a>,
}

#[derive(asn1::Asn1Write, asn1::Asn1Read)]
pub struct EncryptedData<'a> {
    pub version: u8,
    pub encrypted_content_info: EncryptedContentInfo<'a>,
}

#[derive(asn1::Asn1Write, asn1::Asn1Read)]
pub struct EncryptedContentInfo<'a> {
    pub content_type: asn1::ObjectIdentifier,
    pub content_encryption_algorithm: common::AlgorithmIdentifier<'a>,
    #[implicit(0)]
    pub encrypted_content: Option<&'a [u8]>,
}

#[derive(asn1::Asn1Write, asn1::Asn1Read)]
pub struct DigestInfo<'a> {
    pub algorithm: common::AlgorithmIdentifier<'a>,
    pub digest: &'a [u8],
}
