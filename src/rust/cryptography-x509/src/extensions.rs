// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::HashSet;

use crate::common::Asn1Operation;
use crate::{common, crl, name};

pub struct DuplicateExtensionsError(pub asn1::ObjectIdentifier);

pub type RawExtensions<'a> = common::Asn1ReadableOrWritable<
    asn1::SequenceOf<'a, Extension<'a>>,
    asn1::SequenceOfWriter<'a, Extension<'a>, Vec<Extension<'a>>>,
>;

/// An invariant-enforcing wrapper for `RawExtensions`.
///
/// In particular, an `Extensions` cannot be constructed from a `RawExtensions`
/// that contains duplicated extensions (by OID).
pub struct Extensions<'a>(Option<RawExtensions<'a>>);

impl<'a> Extensions<'a> {
    /// Create an `Extensions` from the given `RawExtensions`.
    ///
    /// Returns an `Err` variant containing the first duplicated extension's
    /// OID, if there are any duplicates.
    pub fn from_raw_extensions(
        raw: Option<&RawExtensions<'a>>,
    ) -> Result<Self, DuplicateExtensionsError> {
        match raw {
            Some(raw_exts) => {
                let mut seen_oids = HashSet::new();

                for ext in raw_exts.unwrap_read().clone() {
                    if !seen_oids.insert(ext.extn_id.clone()) {
                        return Err(DuplicateExtensionsError(ext.extn_id));
                    }
                }

                Ok(Self(Some(raw_exts.clone())))
            }
            None => Ok(Self(None)),
        }
    }

    /// Retrieves the extension identified by the given OID,
    /// or None if the extension is not present (or no extensions are present).
    pub fn get_extension(&self, oid: &asn1::ObjectIdentifier) -> Option<Extension<'a>> {
        self.iter().find(|ext| &ext.extn_id == oid)
    }

    /// Returns a reference to the underlying extensions.
    pub fn as_raw(&self) -> Option<&RawExtensions<'a>> {
        self.0.as_ref()
    }

    /// Returns an iterator over the underlying extensions.
    pub fn iter(&self) -> impl Iterator<Item = Extension<'a>> {
        self.as_raw()
            .map(|raw| raw.unwrap_read().clone())
            .into_iter()
            .flatten()
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone)]
pub struct Extension<'a> {
    pub extn_id: asn1::ObjectIdentifier,
    #[default(false)]
    pub critical: bool,
    pub extn_value: &'a [u8],
}

impl<'a> Extension<'a> {
    pub fn value<T: asn1::Asn1Readable<'a>>(&self) -> asn1::ParseResult<T> {
        asn1::parse_single(self.extn_value)
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct PolicyConstraints {
    #[implicit(0)]
    pub require_explicit_policy: Option<u64>,
    #[implicit(1)]
    pub inhibit_policy_mapping: Option<u64>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct AccessDescription<'a> {
    pub access_method: asn1::ObjectIdentifier,
    pub access_location: name::GeneralName<'a>,
}

pub type SequenceOfAccessDescriptions<'a, Op> =
    <Op as Asn1Operation>::SequenceOfVec<'a, AccessDescription<'a>>;

// Needed due to clippy type complexity warning.
type SequenceOfPolicyQualifiers<'a, Op> =
    <Op as Asn1Operation>::SequenceOfVec<'a, PolicyQualifierInfo<'a, Op>>;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct PolicyInformation<'a, Op: Asn1Operation + 'a> {
    pub policy_identifier: asn1::ObjectIdentifier,
    pub policy_qualifiers: Option<SequenceOfPolicyQualifiers<'a, Op>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct PolicyQualifierInfo<'a, Op: Asn1Operation> {
    pub policy_qualifier_id: asn1::ObjectIdentifier,
    pub qualifier: Qualifier<'a, Op>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub enum Qualifier<'a, Op: Asn1Operation> {
    CpsUri(asn1::IA5String<'a>),
    UserNotice(UserNotice<'a, Op>),
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct UserNotice<'a, Op: Asn1Operation> {
    pub notice_ref: Option<NoticeReference<'a, Op>>,
    pub explicit_text: Option<DisplayText<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct NoticeReference<'a, Op: Asn1Operation> {
    pub organization: DisplayText<'a>,
    pub notice_numbers: Op::SequenceOfVec<'a, asn1::BigUint<'a>>,
}

// DisplayText also allows BMPString, which we currently do not support.
#[allow(clippy::enum_variant_names)]
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub enum DisplayText<'a> {
    IA5String(asn1::IA5String<'a>),
    Utf8String(asn1::Utf8String<'a>),
    // Not validated due to certificates with UTF-8 in VisibleString. See PR #8884
    VisibleString(common::UnvalidatedVisibleString<'a>),
    BmpString(asn1::BMPString<'a>),
}

pub type SequenceOfSubtrees<'a, Op> = <Op as Asn1Operation>::SequenceOfVec<'a, GeneralSubtree<'a>>;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct NameConstraints<'a, Op: Asn1Operation> {
    #[implicit(0)]
    pub permitted_subtrees: Option<SequenceOfSubtrees<'a, Op>>,

    #[implicit(1)]
    pub excluded_subtrees: Option<SequenceOfSubtrees<'a, Op>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct GeneralSubtree<'a> {
    pub base: name::GeneralName<'a>,

    #[implicit(0)]
    #[default(0u64)]
    pub minimum: u64,

    #[implicit(1)]
    pub maximum: Option<u64>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct MSCertificateTemplate {
    pub template_id: asn1::ObjectIdentifier,
    pub major_version: Option<u32>,
    pub minor_version: Option<u32>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct DistributionPoint<'a, Op: Asn1Operation> {
    #[explicit(0)]
    pub distribution_point: Option<DistributionPointName<'a, Op>>,

    #[implicit(1)]
    pub reasons: crl::ReasonFlags<'a, Op>,

    #[implicit(2)]
    pub crl_issuer: Option<name::SequenceOfGeneralName<'a, Op>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub enum DistributionPointName<'a, Op: Asn1Operation> {
    #[implicit(0)]
    FullName(name::SequenceOfGeneralName<'a, Op>),

    #[implicit(1)]
    NameRelativeToCRLIssuer(Op::SetOfVec<'a, common::AttributeTypeValue<'a>>),
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct AuthorityKeyIdentifier<'a, Op: Asn1Operation> {
    #[implicit(0)]
    pub key_identifier: Option<&'a [u8]>,
    #[implicit(1)]
    pub authority_cert_issuer: Option<name::SequenceOfGeneralName<'a, Op>>,
    #[implicit(2)]
    pub authority_cert_serial_number: Option<asn1::BigUint<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct BasicConstraints {
    #[default(false)]
    pub ca: bool,
    pub path_length: Option<u64>,
}

pub type SubjectAlternativeName<'a> = asn1::SequenceOf<'a, name::GeneralName<'a>>;
pub type IssuerAlternativeName<'a> = asn1::SequenceOf<'a, name::GeneralName<'a>>;
pub type ExtendedKeyUsage<'a> = asn1::SequenceOf<'a, asn1::ObjectIdentifier, 1>;

pub struct KeyUsage<'a>(asn1::BitString<'a>);

impl<'a> asn1::SimpleAsn1Readable<'a> for KeyUsage<'a> {
    const TAG: asn1::Tag = asn1::BitString::TAG;

    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        asn1::BitString::parse_data(data).map(Self)
    }
}

impl KeyUsage<'_> {
    pub fn is_zeroed(&self) -> bool {
        self.0.as_bytes().iter().all(|&b| b == 0)
    }

    pub fn digital_signature(&self) -> bool {
        self.0.has_bit_set(0)
    }

    pub fn content_commitment(&self) -> bool {
        self.0.has_bit_set(1)
    }

    pub fn key_encipherment(&self) -> bool {
        self.0.has_bit_set(2)
    }

    pub fn data_encipherment(&self) -> bool {
        self.0.has_bit_set(3)
    }

    pub fn key_agreement(&self) -> bool {
        self.0.has_bit_set(4)
    }

    pub fn key_cert_sign(&self) -> bool {
        self.0.has_bit_set(5)
    }

    pub fn crl_sign(&self) -> bool {
        self.0.has_bit_set(6)
    }

    pub fn encipher_only(&self) -> bool {
        self.0.has_bit_set(7)
    }

    pub fn decipher_only(&self) -> bool {
        self.0.has_bit_set(8)
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct NamingAuthority<'a> {
    pub id: Option<asn1::ObjectIdentifier>,
    pub url: Option<asn1::IA5String<'a>>,
    pub text: Option<DisplayText<'a>>,
}

type SequenceOfDisplayTexts<'a, Op> = <Op as Asn1Operation>::SequenceOfVec<'a, DisplayText<'a>>;

type SequenceOfObjectIdentifiers<'a, Op> =
    <Op as Asn1Operation>::SequenceOfVec<'a, asn1::ObjectIdentifier>;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ProfessionInfo<'a, Op: Asn1Operation> {
    #[explicit(0)]
    pub naming_authority: Option<NamingAuthority<'a>>,
    pub profession_items: SequenceOfDisplayTexts<'a, Op>,
    pub profession_oids: Option<SequenceOfObjectIdentifiers<'a, Op>>,
    pub registration_number: Option<asn1::PrintableString<'a>>,
    pub add_profession_info: Option<&'a [u8]>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct Admission<'a, Op: Asn1Operation + 'a> {
    #[explicit(0)]
    pub admission_authority: Option<name::GeneralName<'a>>,
    #[explicit(1)]
    pub naming_authority: Option<NamingAuthority<'a>>,
    pub profession_infos: Op::SequenceOfVec<'a, ProfessionInfo<'a, Op>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct Admissions<'a, Op: Asn1Operation> {
    pub admission_authority: Option<name::GeneralName<'a>>,
    pub contents_of_admissions: Op::SequenceOfVec<'a, Admission<'a, Op>>,
}

#[cfg(test)]
mod tests {
    use super::{BasicConstraints, Extension, Extensions, KeyUsage};
    use crate::oid::{AUTHORITY_KEY_IDENTIFIER_OID, BASIC_CONSTRAINTS_OID};

    #[test]
    fn test_get_extension() {
        let bc = BasicConstraints {
            ca: true,
            path_length: Some(3),
        };
        let extension = Extension {
            extn_id: BASIC_CONSTRAINTS_OID,
            critical: true,
            extn_value: &asn1::write_single(&bc).unwrap(),
        };
        let extensions = asn1::SequenceOfWriter::new(vec![extension]);

        let der = asn1::write_single(&extensions).unwrap();
        let raw = asn1::parse_single(&der).unwrap();

        let extensions = Extensions::from_raw_extensions(Some(&raw)).ok().unwrap();

        assert!(&extensions.get_extension(&BASIC_CONSTRAINTS_OID).is_some());
        assert!(&extensions
            .get_extension(&AUTHORITY_KEY_IDENTIFIER_OID)
            .is_none());
    }

    #[test]
    fn test_extensions_iter() {
        let bc = BasicConstraints {
            ca: true,
            path_length: Some(3),
        };
        let extension = Extension {
            extn_id: BASIC_CONSTRAINTS_OID,
            critical: true,
            extn_value: &asn1::write_single(&bc).unwrap(),
        };
        let extensions = asn1::SequenceOfWriter::new(vec![extension]);

        let der = asn1::write_single(&extensions).unwrap();
        let parsed = asn1::parse_single(&der).unwrap();

        let extensions = Extensions::from_raw_extensions(Some(&parsed)).ok().unwrap();

        let extension_list: Vec<_> = extensions.iter().collect();
        assert_eq!(extension_list.len(), 1);
    }

    #[test]
    fn test_extension_value() {
        let bc = BasicConstraints {
            ca: true,
            path_length: Some(3),
        };
        let extension = Extension {
            extn_id: BASIC_CONSTRAINTS_OID,
            critical: true,
            extn_value: &asn1::write_single(&bc).unwrap(),
        };

        let extracted: BasicConstraints = extension.value().unwrap();
        assert_eq!(bc.ca, extracted.ca);
        assert_eq!(bc.path_length, extracted.path_length);
    }

    #[test]
    fn test_keyusage() {
        // let ku: KeyUsage = asn1::parse_single(data)
        let ku_bits = [0b1111_1111u8, 0b1000_0000u8];
        let ku_bitstring = asn1::BitString::new(&ku_bits, 7).unwrap();
        let asn1 = asn1::write_single(&ku_bitstring).unwrap();

        let ku: KeyUsage<'_> = asn1::parse_single(&asn1).unwrap();
        assert!(!ku.is_zeroed());
        assert!(ku.digital_signature());
        assert!(ku.content_commitment());
        assert!(ku.key_encipherment());
        assert!(ku.data_encipherment());
        assert!(ku.key_agreement());
        assert!(ku.key_cert_sign());
        assert!(ku.crl_sign());
        assert!(ku.encipher_only());
        assert!(ku.decipher_only());
    }
}
