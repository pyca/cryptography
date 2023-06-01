// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::oid;
use asn1::Asn1DefinedByWritable;
use std::marker::PhantomData;

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash, Clone, Eq, Debug)]
pub struct AlgorithmIdentifier<'a> {
    pub oid: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    #[defined_by(oid)]
    pub params: AlgorithmParameters<'a>,
}

impl AlgorithmIdentifier<'_> {
    pub fn oid(&self) -> &asn1::ObjectIdentifier {
        self.params.item()
    }
}

#[derive(asn1::Asn1DefinedByRead, asn1::Asn1DefinedByWrite, PartialEq, Eq, Hash, Clone, Debug)]
pub enum AlgorithmParameters<'a> {
    #[defined_by(oid::SHA1_OID)]
    Sha1(Option<asn1::Null>),
    #[defined_by(oid::SHA224_OID)]
    Sha224(Option<asn1::Null>),
    #[defined_by(oid::SHA256_OID)]
    Sha256(Option<asn1::Null>),
    #[defined_by(oid::SHA384_OID)]
    Sha384(Option<asn1::Null>),
    #[defined_by(oid::SHA512_OID)]
    Sha512(Option<asn1::Null>),
    #[defined_by(oid::SHA3_224_OID)]
    Sha3_224(Option<asn1::Null>),
    #[defined_by(oid::SHA3_256_OID)]
    Sha3_256(Option<asn1::Null>),
    #[defined_by(oid::SHA3_384_OID)]
    Sha3_384(Option<asn1::Null>),
    #[defined_by(oid::SHA3_512_OID)]
    Sha3_512(Option<asn1::Null>),

    #[defined_by(oid::ED25519_OID)]
    Ed25519,
    #[defined_by(oid::ED448_OID)]
    Ed448,

    // These ECDSA algorithms should have no parameters,
    // but Java 11 (up to at least 11.0.19) encodes them
    // with NULL parameters. The JDK team is looking to
    // backport the fix as of June 2023.
    #[defined_by(oid::ECDSA_WITH_SHA224_OID)]
    EcDsaWithSha224(Option<asn1::Null>),
    #[defined_by(oid::ECDSA_WITH_SHA256_OID)]
    EcDsaWithSha256(Option<asn1::Null>),
    #[defined_by(oid::ECDSA_WITH_SHA384_OID)]
    EcDsaWithSha384(Option<asn1::Null>),
    #[defined_by(oid::ECDSA_WITH_SHA512_OID)]
    EcDsaWithSha512(Option<asn1::Null>),

    #[defined_by(oid::ECDSA_WITH_SHA3_224_OID)]
    EcDsaWithSha3_224,
    #[defined_by(oid::ECDSA_WITH_SHA3_256_OID)]
    EcDsaWithSha3_256,
    #[defined_by(oid::ECDSA_WITH_SHA3_384_OID)]
    EcDsaWithSha3_384,
    #[defined_by(oid::ECDSA_WITH_SHA3_512_OID)]
    EcDsaWithSha3_512,

    #[defined_by(oid::RSA_WITH_SHA1_OID)]
    RsaWithSha1(Option<asn1::Null>),
    #[defined_by(oid::RSA_WITH_SHA1_ALT_OID)]
    RsaWithSha1Alt(Option<asn1::Null>),

    #[defined_by(oid::RSA_WITH_SHA224_OID)]
    RsaWithSha224(Option<asn1::Null>),
    #[defined_by(oid::RSA_WITH_SHA256_OID)]
    RsaWithSha256(Option<asn1::Null>),
    #[defined_by(oid::RSA_WITH_SHA384_OID)]
    RsaWithSha384(Option<asn1::Null>),
    #[defined_by(oid::RSA_WITH_SHA512_OID)]
    RsaWithSha512(Option<asn1::Null>),

    #[defined_by(oid::RSA_WITH_SHA3_224_OID)]
    RsaWithSha3_224(Option<asn1::Null>),
    #[defined_by(oid::RSA_WITH_SHA3_256_OID)]
    RsaWithSha3_256(Option<asn1::Null>),
    #[defined_by(oid::RSA_WITH_SHA3_384_OID)]
    RsaWithSha3_384(Option<asn1::Null>),
    #[defined_by(oid::RSA_WITH_SHA3_512_OID)]
    RsaWithSha3_512(Option<asn1::Null>),

    // RsaPssParameters must be present in Certificate::tbs_cert::signature_alg::params
    // and Certificate::signature_alg::params, but Certificate::tbs_cert::spki::algorithm::oid
    // also uses RSASSA_PSS_OID and the params field is omitted since it has no meaning there.
    #[defined_by(oid::RSASSA_PSS_OID)]
    RsaPss(Option<Box<RsaPssParameters<'a>>>),

    #[defined_by(oid::DSA_WITH_SHA224_OID)]
    DsaWithSha224,
    #[defined_by(oid::DSA_WITH_SHA256_OID)]
    DsaWithSha256,
    #[defined_by(oid::DSA_WITH_SHA384_OID)]
    DsaWithSha384,
    #[defined_by(oid::DSA_WITH_SHA512_OID)]
    DsaWithSha512,

    #[default]
    Other(asn1::ObjectIdentifier, Option<asn1::Tlv<'a>>),
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Clone)]
pub struct SubjectPublicKeyInfo<'a> {
    _algorithm: AlgorithmIdentifier<'a>,
    pub subject_public_key: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone)]
pub struct AttributeTypeValue<'a> {
    pub type_id: asn1::ObjectIdentifier,
    pub value: RawTlv<'a>,
}

// Like `asn1::Tlv` but doesn't store `full_data` so it can be constructed from
// an un-encoded tag and value.
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct RawTlv<'a> {
    tag: asn1::Tag,
    value: &'a [u8],
}

impl<'a> RawTlv<'a> {
    pub fn new(tag: asn1::Tag, value: &'a [u8]) -> Self {
        RawTlv { tag, value }
    }

    pub fn tag(&self) -> asn1::Tag {
        self.tag
    }
    pub fn data(&self) -> &'a [u8] {
        self.value
    }
}
impl<'a> asn1::Asn1Readable<'a> for RawTlv<'a> {
    fn parse(parser: &mut asn1::Parser<'a>) -> asn1::ParseResult<Self> {
        let tlv = parser.read_element::<asn1::Tlv<'a>>()?;
        Ok(RawTlv::new(tlv.tag(), tlv.data()))
    }

    fn can_parse(_tag: asn1::Tag) -> bool {
        true
    }
}
impl<'a> asn1::Asn1Writable for RawTlv<'a> {
    fn write(&self, w: &mut asn1::Writer<'_>) -> asn1::WriteResult {
        w.write_tlv(self.tag, move |dest| dest.push_slice(self.value))
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash, Clone)]
pub enum Time {
    UtcTime(asn1::UtcTime),
    GeneralizedTime(asn1::GeneralizedTime),
}

impl Time {
    pub fn as_datetime(&self) -> &asn1::DateTime {
        match self {
            Time::UtcTime(data) => data.as_datetime(),
            Time::GeneralizedTime(data) => data.as_datetime(),
        }
    }
}

#[derive(Hash, PartialEq, Clone)]
pub enum Asn1ReadableOrWritable<'a, T, U> {
    Read(T, PhantomData<&'a ()>),
    Write(U, PhantomData<&'a ()>),
}

impl<'a, T, U> Asn1ReadableOrWritable<'a, T, U> {
    pub fn new_read(v: T) -> Self {
        Asn1ReadableOrWritable::Read(v, PhantomData)
    }

    pub fn new_write(v: U) -> Self {
        Asn1ReadableOrWritable::Write(v, PhantomData)
    }

    pub fn unwrap_read(&self) -> &T {
        match self {
            Asn1ReadableOrWritable::Read(v, _) => v,
            Asn1ReadableOrWritable::Write(_, _) => panic!("unwrap_read called on a Write value"),
        }
    }
}

impl<'a, T: asn1::SimpleAsn1Readable<'a>, U> asn1::SimpleAsn1Readable<'a>
    for Asn1ReadableOrWritable<'a, T, U>
{
    const TAG: asn1::Tag = T::TAG;
    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        Ok(Self::new_read(T::parse_data(data)?))
    }
}

impl<'a, T: asn1::SimpleAsn1Writable, U: asn1::SimpleAsn1Writable> asn1::SimpleAsn1Writable
    for Asn1ReadableOrWritable<'a, T, U>
{
    const TAG: asn1::Tag = U::TAG;
    fn write_data(&self, w: &mut asn1::WriteBuf) -> asn1::WriteResult {
        match self {
            Asn1ReadableOrWritable::Read(v, _) => T::write_data(v, w),
            Asn1ReadableOrWritable::Write(v, _) => U::write_data(v, w),
        }
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct DssSignature<'a> {
    pub r: asn1::BigUint<'a>,
    pub s: asn1::BigUint<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct DHParams<'a> {
    pub p: asn1::BigUint<'a>,
    pub g: asn1::BigUint<'a>,
    pub q: Option<asn1::BigUint<'a>>,
}
// RSA-PSS ASN.1 default hash algorithm
pub const PSS_SHA1_HASH_ALG: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::Sha1(Some(())),
};

// This is defined as an AlgorithmIdentifier in RFC 4055,
// but the mask generation algorithm **must** contain an AlgorithmIdentifier
// in its params, so we define it this way.
#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, Clone, PartialEq, Eq, Debug)]
pub struct MaskGenAlgorithm<'a> {
    pub oid: asn1::ObjectIdentifier,
    pub params: AlgorithmIdentifier<'a>,
}

// RSA-PSS ASN.1 default mask gen algorithm
pub const PSS_SHA1_MASK_GEN_ALG: MaskGenAlgorithm<'_> = MaskGenAlgorithm {
    oid: oid::MGF1_OID,
    params: PSS_SHA1_HASH_ALG,
};

// From RFC 4055 section 3.1:
// RSASSA-PSS-params  ::=  SEQUENCE  {
//     hashAlgorithm      [0] HashAlgorithm DEFAULT
//                               sha1Identifier,
//     maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT
//                               mgf1SHA1Identifier,
//     saltLength         [2] INTEGER DEFAULT 20,
//     trailerField       [3] INTEGER DEFAULT 1  }
#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, Clone, PartialEq, Eq, Debug)]
pub struct RsaPssParameters<'a> {
    #[explicit(0)]
    #[default(PSS_SHA1_HASH_ALG)]
    pub hash_algorithm: AlgorithmIdentifier<'a>,
    #[explicit(1)]
    #[default(PSS_SHA1_MASK_GEN_ALG)]
    pub mask_gen_algorithm: MaskGenAlgorithm<'a>,
    #[explicit(2)]
    #[default(20u16)]
    pub salt_length: u16,
    #[explicit(3)]
    #[default(1u8)]
    pub _trailer_field: u8,
}

/// A VisibleString ASN.1 element whose contents is not validated as meeting the
/// requirements (visible characters of IA5), and instead is only known to be
/// valid UTF-8.
pub struct UnvalidatedVisibleString<'a>(pub &'a str);

impl<'a> UnvalidatedVisibleString<'a> {
    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl<'a> asn1::SimpleAsn1Readable<'a> for UnvalidatedVisibleString<'a> {
    const TAG: asn1::Tag = asn1::VisibleString::TAG;
    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        Ok(UnvalidatedVisibleString(
            std::str::from_utf8(data)
                .map_err(|_| asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue))?,
        ))
    }
}

impl<'a> asn1::SimpleAsn1Writable for UnvalidatedVisibleString<'a> {
    const TAG: asn1::Tag = asn1::VisibleString::TAG;
    fn write_data(&self, _: &mut asn1::WriteBuf) -> asn1::WriteResult {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::{Asn1ReadableOrWritable, RawTlv, UnvalidatedVisibleString};
    use asn1::Asn1Readable;

    #[test]
    #[should_panic]
    fn test_unvalidated_visible_string_write() {
        let v = UnvalidatedVisibleString("foo");
        asn1::write_single(&v).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_asn1_readable_or_writable_unwrap_read() {
        Asn1ReadableOrWritable::<u32, u32>::new_write(17).unwrap_read();
    }

    #[test]
    fn test_asn1_readable_or_writable_write_read_data() {
        let v = Asn1ReadableOrWritable::<u32, u32>::new_read(17);
        assert_eq!(&asn1::write_single(&v).unwrap(), b"\x02\x01\x11");
    }

    #[test]
    fn test_raw_tlv_can_parse() {
        let t = asn1::Tag::from_bytes(&[0]).unwrap().0;
        assert!(RawTlv::can_parse(t));
    }
}
