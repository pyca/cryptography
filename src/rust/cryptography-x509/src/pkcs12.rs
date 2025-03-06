// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::common::{AlgorithmIdentifier, Utf8StoredBMPString};
use crate::pkcs7;

pub const CERT_BAG_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 12, 10, 1, 3);
pub const KEY_BAG_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 12, 10, 1, 1);
pub const SHROUDED_KEY_BAG_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 12, 10, 1, 2);
pub const X509_CERTIFICATE_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 9, 22, 1);
pub const FRIENDLY_NAME_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 9, 20);
pub const LOCAL_KEY_ID_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 9, 21);

#[derive(asn1::Asn1Write)]
pub struct Pfx<'a> {
    pub version: u8,
    pub auth_safe: pkcs7::ContentInfo<'a>,
    pub mac_data: Option<MacData<'a>>,
}

#[derive(asn1::Asn1Write)]
pub struct MacData<'a> {
    pub mac: pkcs7::DigestInfo<'a>,
    pub salt: &'a [u8],
    #[default(1u64)]
    pub iterations: u64,
}

#[derive(asn1::Asn1Write)]
pub struct SafeBag<'a> {
    pub _bag_id: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    #[defined_by(_bag_id)]
    pub bag_value: asn1::Explicit<BagValue<'a>, 0>,
    pub attributes: Option<asn1::SetOfWriter<'a, Attribute<'a>, Vec<Attribute<'a>>>>,
}

#[derive(asn1::Asn1Write)]
pub struct Attribute<'a> {
    pub _attr_id: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    #[defined_by(_attr_id)]
    pub attr_values: AttributeSet<'a>,
}

#[derive(asn1::Asn1DefinedByWrite)]
pub enum AttributeSet<'a> {
    #[defined_by(FRIENDLY_NAME_OID)]
    FriendlyName(asn1::SetOfWriter<'a, Utf8StoredBMPString<'a>, [Utf8StoredBMPString<'a>; 1]>),

    #[defined_by(LOCAL_KEY_ID_OID)]
    LocalKeyId(asn1::SetOfWriter<'a, &'a [u8], [&'a [u8]; 1]>),
}

#[derive(asn1::Asn1DefinedByWrite)]
pub enum BagValue<'a> {
    #[defined_by(CERT_BAG_OID)]
    CertBag(Box<CertBag<'a>>),

    #[defined_by(KEY_BAG_OID)]
    KeyBag(asn1::Tlv<'a>),

    #[defined_by(SHROUDED_KEY_BAG_OID)]
    ShroudedKeyBag(EncryptedPrivateKeyInfo<'a>),
}

#[derive(asn1::Asn1Write)]
pub struct CertBag<'a> {
    pub _cert_id: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    #[defined_by(_cert_id)]
    pub cert_value: asn1::Explicit<CertType<'a>, 0>,
}

#[derive(asn1::Asn1DefinedByWrite)]
pub enum CertType<'a> {
    #[defined_by(X509_CERTIFICATE_OID)]
    X509(asn1::OctetStringEncoded<crate::certificate::Certificate<'a>>),
}

#[derive(asn1::Asn1Write)]
pub struct EncryptedPrivateKeyInfo<'a> {
    pub encryption_algorithm: AlgorithmIdentifier<'a>,
    pub encrypted_data: &'a [u8],
}
