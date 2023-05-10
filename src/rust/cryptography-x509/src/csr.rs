// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::common;
use crate::extensions;
use crate::name;
use crate::oid;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct Csr<'a> {
    pub csr_info: CertificationRequestInfo<'a>,
    pub signature_alg: common::AlgorithmIdentifier<'a>,
    pub signature: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct CertificationRequestInfo<'a> {
    pub version: u8,
    pub subject: name::Name<'a>,
    pub spki: common::SubjectPublicKeyInfo<'a>,
    #[implicit(0, required)]
    pub attributes: Attributes<'a>,
}

impl CertificationRequestInfo<'_> {
    pub fn get_extension_attribute(
        &self,
    ) -> Result<Option<extensions::RawExtensions<'_>>, asn1::ParseError> {
        for attribute in self.attributes.unwrap_read().clone() {
            if attribute.type_id == oid::EXTENSION_REQUEST
                || attribute.type_id == oid::MS_EXTENSION_REQUEST
            {
                check_attribute_length(attribute.values.unwrap_read().clone())?;
                let val = attribute.values.unwrap_read().clone().next().unwrap();
                let exts = asn1::parse_single(val.full_data())?;
                return Ok(Some(exts));
            }
        }
        Ok(None)
    }
}

pub fn check_attribute_length<'a>(
    values: asn1::SetOf<'a, asn1::Tlv<'a>>,
) -> Result<(), asn1::ParseError> {
    if values.count() > 1 {
        // TODO: We should raise a more specific error here
        // Only single-valued attributes are supported
        Err(asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue))
    } else {
        Ok(())
    }
}

pub type Attributes<'a> = common::Asn1ReadableOrWritable<
    'a,
    asn1::SetOf<'a, Attribute<'a>>,
    asn1::SetOfWriter<'a, Attribute<'a>, Vec<Attribute<'a>>>,
>;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct Attribute<'a> {
    pub type_id: asn1::ObjectIdentifier,
    pub values: common::Asn1ReadableOrWritable<
        'a,
        asn1::SetOf<'a, asn1::Tlv<'a>>,
        asn1::SetOfWriter<'a, common::RawTlv<'a>, [common::RawTlv<'a>; 1]>,
    >,
}
