# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import sys

from pyasn1.type import char, constraint, namedtype, namedval, tag, univ


MAX = sys.maxint

# Upper Bounds
ub_name = univ.Integer(32768)
ub_common_name = univ.Integer(64)
ub_locality_name = univ.Integer(128)
ub_state_name = univ.Integer(128)
ub_organization_name = univ.Integer(64)
ub_organizational_unit_name = univ.Integer(64)
ub_title = univ.Integer(64)
ub_match = univ.Integer(128)
ub_emailaddress_length = univ.Integer(128)
ub_common_name_length = univ.Integer(64)
ub_country_name_alpha_length = univ.Integer(2)
ub_country_name_numeric_length = univ.Integer(3)
ub_domain_defined_attributes = univ.Integer(4)
ub_domain_defined_attribute_type_length = univ.Integer(8)
ub_domain_defined_attribute_value_length = univ.Integer(128)
ub_domain_name_length = univ.Integer(16)
ub_extension_attributes = univ.Integer(256)
ub_e163_4_number_length = univ.Integer(15)
ub_e163_4_sub_address_length = univ.Integer(40)
ub_generation_qualifier_length = univ.Integer(3)
ub_given_name_length = univ.Integer(16)
ub_initials_length = univ.Integer(5)
ub_integer_options = univ.Integer(256)
ub_numeric_user_id_length = univ.Integer(32)
ub_organization_name_length = univ.Integer(64)
ub_organizational_unit_name_length = univ.Integer(32)
ub_organizational_units = univ.Integer(4)
ub_pds_name_length = univ.Integer(16)
ub_pds_parameter_length = univ.Integer(30)
ub_pds_physical_address_lines = univ.Integer(6)
ub_postal_code_length = univ.Integer(16)
ub_surname_length = univ.Integer(40)
ub_terminal_id_length = univ.Integer(24)
ub_unformatted_address_length = univ.Integer(180)
ub_x121_address_length = univ.Integer(16)

id_ce_basicConstraints = univ.ObjectIdentifier("2.5.29.19")
id_ce_keyUsage = univ.ObjectIdentifier("2.5.29.15")
id_ce_s = univ.ObjectIdentifier("2.5.29.15")
id_ce_subjectKeyIdentifier = univ.ObjectIdentifier('2.5.29.14')
id_ce_authorityKeyIdentifier = univ.ObjectIdentifier('2.5.29.35')
id_ce_certificatePolicies = univ.ObjectIdentifier('2.5.29.32')
id_ce_extKeyUsage = univ.ObjectIdentifier('2.5.29.37')
id_ce_issuerAltName = univ.ObjectIdentifier('2.5.29.18')
id_ce_subjectAltName = univ.ObjectIdentifier('2.5.29.17')
id_ce_subjectDirectoryAttributes = univ.ObjectIdentifier('2.5.29.9')
id_ce_cRLDistributionPoints = univ.ObjectIdentifier('2.5.29.31')
id_pe_authorityInfoAccess = univ.ObjectIdentifier('1.3.6.1.5.5.7.1.1')
id_pe_subjectInfoAccess = univ.ObjectIdentifier('1.3.6.1.5.5.5.7.1.11')
id_ce_policyConstraints = univ.ObjectIdentifier('2.5.29.36')
id_pkix_OCSP_noCheck = univ.ObjectIdentifier('1.3.6.1.5.5.7.48.1.5')
id_ce_inhibitAnyPolicy = univ.ObjectIdentifier('2.5.29.54')
id_ce_policyMappings = univ.ObjectIdentifier('2.5.29.33')
id_ce_freshestCRL = univ.ObjectIdentifier('2.5.29.46')


id_qt_cps = univ.ObjectIdentifier('1.3.6.1.5.5.7.2.1')
id_qt_unotice = univ.ObjectIdentifier('1.3.6.1.5.5.7.2.2')


class KeyIdentifier(univ.OctetString):
    pass


class SubjectKeyIdentifier(KeyIdentifier):
    pass


class AttributeValue(univ.Any):
    pass


class AttributeType(univ.ObjectIdentifier):
    pass


class AttributeTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeType()),
        namedtype.NamedType('value', AttributeValue())
    )


class RelativeDistinguishedName(univ.SetOf):
    componentType = AttributeTypeAndValue()


class RDNSequence(univ.SequenceOf):
    componentType = RelativeDistinguishedName()


class Name(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('', RDNSequence())
    )


class DirectoryString(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'teletexString',
            char.TeletexString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            )
        ),
        namedtype.NamedType(
            'printableString',
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            )
        ),
        namedtype.NamedType(
            'universalString',
            char.UniversalString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            )
        ),
        namedtype.NamedType(
            'utf8String',
            char.UTF8String().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            )
        ),
        namedtype.NamedType(
            'bmpString',
            char.BMPString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            )
        ),
        namedtype.NamedType(
            'ia5String',
            char.IA5String().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            )
        )  # hm, this should not be here!? XXX
    )


class EDIPartyName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            'nameAssigner',
            DirectoryString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 0
                )
            )
        ),
        namedtype.NamedType(
            'partyName',
            DirectoryString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 1
                )
            )
        )
    )


class AnotherName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type-id', univ.ObjectIdentifier()),
        namedtype.NamedType(
            'value',
            univ.Any().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 0
                )
            )
        )
    )


class BuiltInDomainDefinedAttribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'type',
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_domain_defined_attribute_type_length
                )
            )
        ),
        namedtype.NamedType(
            'value',
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_domain_defined_attribute_value_length
                )
            )
        )
    )


class BuiltInDomainDefinedAttributes(univ.SequenceOf):
    componentType = BuiltInDomainDefinedAttribute()
    subtypeSpec = (
        univ.SequenceOf.subtypeSpec +
        constraint.ValueSizeConstraint(1, ub_domain_defined_attributes)
    )


class OrganizationalUnitName(char.PrintableString):
    subtypeSpec = (
        univ.SequenceOf.subtypeSpec +
        constraint.ValueSizeConstraint(1, ub_organizational_unit_name_length)
    )


class OrganizationalUnitNames(univ.SequenceOf):
    componentType = OrganizationalUnitName()
    subtypeSpec = (
        univ.SequenceOf.subtypeSpec +
        constraint.ValueSizeConstraint(1, ub_organizational_units)
    )


class PersonalName(univ.Set):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'surname',
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_surname_length
                ),
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 0
                )
            )
        ),
        namedtype.OptionalNamedType(
            'given-name',
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_given_name_length
                ),
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 1
                )
            )
        ),
        namedtype.OptionalNamedType(
            'initials',
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_initials_length
                ),
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 2
                )
            )
        ),
        namedtype.OptionalNamedType(
            'generation-qualifier',
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_generation_qualifier_length
                ),
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 3
                )
            )
        )
    )


class NumericUserIdentifier(char.NumericString):
    subtypeSpec = (
        char.NumericString.subtypeSpec +
        constraint.ValueSizeConstraint(1, ub_numeric_user_id_length)
    )


class OrganizationName(char.PrintableString):
    subtypeSpec = (
        char.PrintableString.subtypeSpec +
        constraint.ValueSizeConstraint(1, ub_organization_name_length)
    )


class PrivateDomainName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'numeric',
            char.NumericString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_domain_name_length
                )
            )
        ),
        namedtype.NamedType(
            'printable',
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_domain_name_length
                )
            )
        )
    )


class TerminalIdentifier(char.PrintableString):
    subtypeSpec = (
        char.PrintableString.subtypeSpec +
        constraint.ValueSizeConstraint(1, ub_terminal_id_length)
    )


class X121Address(char.NumericString):
    subtypeSpec = (
        char.NumericString.subtypeSpec +
        constraint.ValueSizeConstraint(1, ub_x121_address_length)
    )


class NetworkAddress(X121Address):
    pass


class AdministrationDomainName(univ.Choice):
    tagSet = univ.Choice.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 2)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'numeric',
            char.NumericString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    0, ub_domain_name_length
                )
            )
        ),
        namedtype.NamedType(
            'printable',
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    0, ub_domain_name_length
                )
            )
        )
    )


class CountryName(univ.Choice):
    tagSet = univ.Choice.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 1)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'x121-dcc-code',
            char.NumericString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    ub_country_name_numeric_length,
                    ub_country_name_numeric_length
                )
            )
        ),
        namedtype.NamedType(
            'iso-3166-alpha2-code',
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    ub_country_name_alpha_length,
                    ub_country_name_alpha_length
                )
            )
        )
    )


class BuiltInStandardAttributes(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('country-name', CountryName()),
        namedtype.OptionalNamedType(
            'administration-domain-name', AdministrationDomainName()
        ),
        namedtype.OptionalNamedType(
            'network-address',
            NetworkAddress().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 0
                )
            )
        ),
        namedtype.OptionalNamedType(
            'terminal-identifier',
            TerminalIdentifier().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 1
                )
            )
        ),
        namedtype.OptionalNamedType(
            'private-domain-name',
            PrivateDomainName().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 2
                )
            )
        ),
        namedtype.OptionalNamedType(
            'organization-name',
            OrganizationName().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 3
                )
            )
        ),
        namedtype.OptionalNamedType(
            'numeric-user-identifier',
            NumericUserIdentifier().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 4
                )
            )
        ),
        namedtype.OptionalNamedType(
            'personal-name',
            PersonalName().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 5
                )
            )
        ),
        namedtype.OptionalNamedType(
            'organizational-unit-names',
            OrganizationalUnitNames().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 6
                )
            )
        )
    )


class ExtensionAttribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'extension-attribute-type',
            univ.Integer().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    0, ub_extension_attributes
                ),
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 0
                )
            )
        ),
        namedtype.NamedType(
            'extension-attribute-value',
            univ.Any().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 1
                )
            )
        )
    )


class ExtensionAttributes(univ.SetOf):
    componentType = ExtensionAttribute()
    subtypeSpec = (
        univ.SetOf.subtypeSpec +
        constraint.ValueSizeConstraint(1, ub_extension_attributes)
    )


class BuiltInDomainDefinedAttribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'type',
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_domain_defined_attribute_type_length
                )
            )
        ),
        namedtype.NamedType(
            'value',
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_domain_defined_attribute_value_length
                )
            )
        )
    )


class ORAddress(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'built-in-standard-attributes', BuiltInStandardAttributes()
        ),
        namedtype.OptionalNamedType(
            'built-in-domain-defined-attributes',
            BuiltInDomainDefinedAttributes()
        ),
        namedtype.OptionalNamedType(
            'extension-attributes', ExtensionAttributes()
        )
    )


class GeneralName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'otherName',
            AnotherName().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 0
                )
            )
        ),
        namedtype.NamedType(
            'rfc822Name',
            char.IA5String().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 1
                )
            )
        ),
        namedtype.NamedType(
            'dNSName',
            char.IA5String().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 2
                )
            )
        ),
        namedtype.NamedType(
            'x400Address', ORAddress().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 3
                )
            )
        ),
        namedtype.NamedType(
            'directoryName',
            Name().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 4
                )
            )
        ),
        namedtype.NamedType(
            'ediPartyName',
            EDIPartyName().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 5
                )
            )
        ),
        namedtype.NamedType(
            'uniformResourceIdentifier',
            char.IA5String().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 6
                )
            )
        ),
        namedtype.NamedType(
            'iPAddress',
            univ.OctetString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 7
                )
            )
        ),
        namedtype.NamedType(
            'registeredID',
            univ.ObjectIdentifier().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 8
                )
            )
        )
    )


class GeneralNames(univ.SequenceOf):
    componentType = GeneralName()
    subtypeSpec = (
        univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)
    )


class CertificateSerialNumber(univ.Integer):
    pass


class AuthorityKeyIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            'keyIdentifier',
            KeyIdentifier().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 0
                )
            )
        ),
        namedtype.OptionalNamedType(
            'authorityCertIssuer',
            GeneralNames().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 1
                )
            )
        ),
        namedtype.OptionalNamedType(
            'authorityCertSerialNumber',
            CertificateSerialNumber().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 2
                )
            )
        )
    )


# RFC 5280 section 4.1
class X509Extension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extnID', univ.ObjectIdentifier()),
        namedtype.DefaultedNamedType('critical', univ.Boolean(False)),
        namedtype.NamedType('extnValue', univ.OctetString())
    )


# RFC 5280 section 4.2.1.9
class BasicConstraints(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('cA', univ.Boolean(False)),
        namedtype.OptionalNamedType(
            'pathLenConstraint',
            univ.Integer().subtype(
                subtypeSpec=constraint.ValueRangeConstraint(0, MAX)
            )
        )
    )


id_kp_serverAuth = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.1.1')
id_kp_clientAuth = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.2')
id_kp_codeSigning = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.3')
id_kp_emailProtection = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.4')
id_kp_ipsecEndSystem = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.5')
id_kp_ipsecTunnel = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.6')
id_kp_ipsecUser = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.7')
id_kp_timeStamping = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.8')
id_pe_authorityInfoAccess = univ.ObjectIdentifier('1.3.6.1.5.5.7.1.1')


class KeyPurposeId(univ.ObjectIdentifier):
    pass


class ExtKeyUsageSyntax(univ.SequenceOf):
    componentType = KeyPurposeId()
    subtypeSpec = (
        univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)
    )


class KeyUsage(univ.BitString):
    namedValues = namedval.NamedValues(
        ('digitalSignature', 0),
        ('nonRepudiation', 1),
        ('keyEncipherment', 2),
        ('dataEncipherment', 3),
        ('keyAgreement', 4),
        ('keyCertSign', 5),
        ('cRLSign', 6),
        ('encipherOnly', 7),
        ('decipherOnly', 8)
    )


class DisplayText(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'visibleString',
            char.VisibleString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, 200)
            )
        ),
        namedtype.NamedType(
            'bmpString',
            char.BMPString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, 200)
            )
        ),
        namedtype.NamedType(
            'utf8String',
            char.UTF8String().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, 200)
            )
        )
    )


class NoticeReference(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('organization', DisplayText()),
        namedtype.NamedType(
            'noticeNumbers', univ.SequenceOf(componentType=univ.Integer())
        )
    )


class UserNotice(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('noticeRef', NoticeReference()),
        namedtype.OptionalNamedType('explicitText', DisplayText())
    )


class CPSuri(char.IA5String):
    pass


class PolicyQualifierId(univ.ObjectIdentifier):
    subtypeSpec = (
        univ.ObjectIdentifier.subtypeSpec +
        constraint.SingleValueConstraint(id_qt_cps, id_qt_unotice)
    )


class CertPolicyId(univ.ObjectIdentifier):
    pass


class PolicyQualifierInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('policyQualifierId', PolicyQualifierId()),
        namedtype.NamedType('qualifier', univ.Any())
    )


class PolicyInformation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('policyIdentifier', CertPolicyId()),
        namedtype.OptionalNamedType(
            'policyQualifiers',
            univ.SequenceOf(componentType=PolicyQualifierInfo()).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            )
        )
    )


class PolicyMappings(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuerDomainPolicy', CertPolicyId()),
        namedtype.NamedType('subjectDomainPolicy', CertPolicyId()),
    )


class CertificatePolicies(univ.SequenceOf):
    componentType = PolicyInformation()
    subtypeSpec = (
        univ.SequenceOf.subtypeSpec +
        constraint.ValueSizeConstraint(1, MAX)
    )


class SubjectAltName(GeneralNames):
    pass


class IssuerAltName(GeneralNames):
    pass


class ReasonFlags(univ.BitString):
    namedValues = namedval.NamedValues(
        ('unused', 0),
        ('keyCompromise', 1),
        ('cACompromise', 2),
        ('affiliationChanged', 3),
        ('superseded', 4),
        ('cessationOfOperation', 5),
        ('certificateHold', 6)
    )


class DistributionPointName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'fullName',
            GeneralNames().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatConstructed, 0
                )
            )
        ),
        namedtype.NamedType(
            'nameRelativeToCRLIssuer',
            RelativeDistinguishedName().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatConstructed, 1
                )
            )
        )
    )


class DistributionPoint(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            'distributionPoint',
            DistributionPointName().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatConstructed, 0
                )
            )
        ),
        namedtype.OptionalNamedType(
            'reasons',
            ReasonFlags().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 1
                )
            )
        ),
        namedtype.OptionalNamedType(
            'cRLIssuer',
            GeneralNames().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatConstructed, 2
                )
            )
        )
    )


class CRLDistPointsSyntax(univ.SequenceOf):
    componentType = DistributionPoint()
    subtypeSpec = (
        univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)
    )


class AccessDescription(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', GeneralName())
    )


class AuthorityInfoAccessSyntax(univ.SequenceOf):
    componentType = AccessDescription()
    subtypeSpec = (
        univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)
    )


class SubjectInfoAccessSyntax(univ.SequenceOf):
    componentType = AccessDescription()
    subtypeSpec = (
        univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)
    )


class SkipCerts(univ.Integer):
    subtypeSpec = (
        univ.Integer.subtypeSpec + constraint.ValueSizeConstraint(0, MAX)
    )


class PolicyConstraints(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            'requireExplicitPolicy',
            SkipCerts().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatConstructed, 0
                )
            )
        ),
        namedtype.OptionalNamedType(
            'inhibitPolicyMapping',
            SkipCerts().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatConstructed, 1
                )
            )
        )
    )


class BaseDistance(univ.Integer):
    subtypeSpec = (
        univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(0, MAX)
    )


class GeneralSubtree(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('base', GeneralName()),
        namedtype.NamedType(
            'minimum',
            BaseDistance(0).subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatConstructed, 0
                )
            )
        ),
        namedtype.OptionalNamedType(
            'maximum',
            BaseDistance().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatConstructed, 1
                )
            )
        )
    )


class GeneralSubtrees(univ.SequenceOf):
    componentType = GeneralSubtree()
    subtypeSpec = (
        univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)
    )

id_ce_nameConstraints = univ.ObjectIdentifier('2.5.29.30')


class NameConstraints(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            'permittedSubtrees',
            GeneralSubtrees().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatConstructed, 0
                )
            )
        ),
        namedtype.OptionalNamedType(
            'excludedSubtrees',
            GeneralSubtrees().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatConstructed, 0
                )
            )
        )
    )


class OCSPNoCheck(univ.Null):
    pass


class InhibitAnyPolicy(univ.Integer):
    pass


class FreshestCRL(CRLDistPointsSyntax):
    pass


# SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
# as you can see this is not a sequence of Attributes, but rather
# AttributeTypeAndValue. I can't find a definition for an Attribute and the
# implication appears to be TypeAndValue
class SubjectDirectoryAttributes(univ.Sequence):
    componentType = AttributeTypeAndValue()


EXTENSION_MAPPING = {
    id_pe_authorityInfoAccess: AuthorityInfoAccessSyntax,
    id_ce_authorityKeyIdentifier: AuthorityKeyIdentifier,
    id_ce_basicConstraints: BasicConstraints,
    id_ce_certificatePolicies: CertificatePolicies,
    id_ce_cRLDistributionPoints: CRLDistPointsSyntax,
    id_ce_extKeyUsage: ExtKeyUsageSyntax,
    id_ce_freshestCRL: FreshestCRL,  # TODO: test
    id_ce_inhibitAnyPolicy: InhibitAnyPolicy,
    id_ce_issuerAltName: IssuerAltName,
    id_ce_keyUsage: KeyUsage,
    id_ce_nameConstraints: NameConstraints,
    id_pkix_OCSP_noCheck: OCSPNoCheck,
    id_ce_policyConstraints: PolicyConstraints,
    id_ce_policyMappings: PolicyMappings,  # TODO: test
    id_ce_subjectAltName: SubjectAltName,
    id_ce_subjectDirectoryAttributes: SubjectDirectoryAttributes,  # TODO: test
    id_pe_subjectInfoAccess: SubjectInfoAccessSyntax,  # TODO: test
    id_ce_subjectKeyIdentifier: SubjectKeyIdentifier,
}
