// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::common;

pub type Name<'a> = common::Asn1ReadableOrWritable<
    'a,
    asn1::SequenceOf<'a, asn1::SetOf<'a, common::AttributeTypeValue<'a>>>,
    asn1::SequenceOfWriter<
        'a,
        asn1::SetOfWriter<'a, common::AttributeTypeValue<'a>, Vec<common::AttributeTypeValue<'a>>>,
        Vec<
            asn1::SetOfWriter<
                'a,
                common::AttributeTypeValue<'a>,
                Vec<common::AttributeTypeValue<'a>>,
            >,
        >,
    >,
>;

/// An IA5String ASN.1 element whose contents is not validated as meeting the
/// requirements (ASCII characters only), and instead is only known to be
/// valid UTF-8.
pub struct UnvalidatedIA5String<'a>(pub &'a str);

impl<'a> asn1::SimpleAsn1Readable<'a> for UnvalidatedIA5String<'a> {
    const TAG: asn1::Tag = asn1::IA5String::TAG;
    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        Ok(UnvalidatedIA5String(std::str::from_utf8(data).map_err(
            |_| asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue),
        )?))
    }
}

impl<'a> asn1::SimpleAsn1Writable for UnvalidatedIA5String<'a> {
    const TAG: asn1::Tag = asn1::IA5String::TAG;
    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
        dest.push_slice(self.0.as_bytes())
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash)]
pub struct OtherName<'a> {
    pub type_id: asn1::ObjectIdentifier,
    #[explicit(0, required)]
    pub value: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub enum GeneralName<'a> {
    #[implicit(0)]
    OtherName(OtherName<'a>),

    #[implicit(1)]
    RFC822Name(UnvalidatedIA5String<'a>),

    #[implicit(2)]
    DNSName(UnvalidatedIA5String<'a>),

    #[implicit(3)]
    // unsupported
    X400Address(asn1::Sequence<'a>),

    // Name is explicit per RFC 5280 Appendix A.1.
    #[explicit(4)]
    DirectoryName(Name<'a>),

    #[implicit(5)]
    // unsupported
    EDIPartyName(asn1::Sequence<'a>),

    #[implicit(6)]
    UniformResourceIdentifier(UnvalidatedIA5String<'a>),

    #[implicit(7)]
    IPAddress(&'a [u8]),

    #[implicit(8)]
    RegisteredID(asn1::ObjectIdentifier),
}

pub(crate) type SequenceOfGeneralName<'a> = common::Asn1ReadableOrWritable<
    'a,
    asn1::SequenceOf<'a, GeneralName<'a>>,
    asn1::SequenceOfWriter<'a, GeneralName<'a>, Vec<GeneralName<'a>>>,
>;
