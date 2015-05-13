# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc
import ipaddress
from enum import Enum

import six

from cryptography import utils
from cryptography.hazmat.primitives import hashes


_OID_NAMES = {
    "2.5.4.3": "commonName",
    "2.5.4.6": "countryName",
    "2.5.4.7": "localityName",
    "2.5.4.8": "stateOrProvinceName",
    "2.5.4.10": "organizationName",
    "2.5.4.11": "organizationalUnitName",
    "2.5.4.5": "serialNumber",
    "2.5.4.4": "surname",
    "2.5.4.42": "givenName",
    "2.5.4.12": "title",
    "2.5.4.44": "generationQualifier",
    "2.5.4.46": "dnQualifier",
    "2.5.4.65": "pseudonym",
    "0.9.2342.19200300.100.1.25": "domainComponent",
    "1.2.840.113549.1.9.1": "emailAddress",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10040.4.3": "dsa-with-sha1",
    "2.16.840.1.101.3.4.3.1": "dsa-with-sha224",
    "2.16.840.1.101.3.4.3.2": "dsa-with-sha256",
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "OCSPSigning",
    "2.5.29.9": "subjectDirectoryAttributes",
    "2.5.29.14": "subjectKeyIdentifier",
    "2.5.29.15": "keyUsage",
    "2.5.29.17": "subjectAltName",
    "2.5.29.18": "issuerAltName",
    "2.5.29.19": "basicConstraints",
    "2.5.29.30": "nameConstraints",
    "2.5.29.31": "cRLDistributionPoints",
    "2.5.29.32": "certificatePolicies",
    "2.5.29.33": "policyMappings",
    "2.5.29.35": "authorityKeyIdentifier",
    "2.5.29.36": "policyConstraints",
    "2.5.29.37": "extendedKeyUsage",
    "2.5.29.46": "freshestCRL",
    "2.5.29.54": "inhibitAnyPolicy",
    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
    "1.3.6.1.5.5.7.1.11": "subjectInfoAccess",
    "1.3.6.1.5.5.7.48.1.5": "OCSPNoCheck",
    "1.3.6.1.5.5.7.48.1": "OCSP",
    "1.3.6.1.5.5.7.48.2": "caIssuers",
    "1.3.6.1.5.5.7.2.1": "id-qt-cps",
    "1.3.6.1.5.5.7.2.2": "id-qt-unotice",
}


_GENERAL_NAMES = {
    0: "otherName",
    1: "rfc822Name",
    2: "dNSName",
    3: "x400Address",
    4: "directoryName",
    5: "ediPartyName",
    6: "uniformResourceIdentifier",
    7: "iPAddress",
    8: "registeredID",
}


class Version(Enum):
    v1 = 0
    v3 = 2


def load_pem_x509_certificate(data, backend):
    return backend.load_pem_x509_certificate(data)


def load_der_x509_certificate(data, backend):
    return backend.load_der_x509_certificate(data)


def load_pem_x509_csr(data, backend):
    return backend.load_pem_x509_csr(data)


def load_der_x509_csr(data, backend):
    return backend.load_der_x509_csr(data)


class InvalidVersion(Exception):
    def __init__(self, msg, parsed_version):
        super(InvalidVersion, self).__init__(msg)
        self.parsed_version = parsed_version


class DuplicateExtension(Exception):
    def __init__(self, msg, oid):
        super(DuplicateExtension, self).__init__(msg)
        self.oid = oid


class UnsupportedExtension(Exception):
    def __init__(self, msg, oid):
        super(UnsupportedExtension, self).__init__(msg)
        self.oid = oid


class ExtensionNotFound(Exception):
    def __init__(self, msg, oid):
        super(ExtensionNotFound, self).__init__(msg)
        self.oid = oid


class UnsupportedGeneralNameType(Exception):
    def __init__(self, msg, type):
        super(UnsupportedGeneralNameType, self).__init__(msg)
        self.type = type


class NameAttribute(object):
    def __init__(self, oid, value):
        if not isinstance(oid, ObjectIdentifier):
            raise TypeError(
                "oid argument must be an ObjectIdentifier instance."
            )

        self._oid = oid
        self._value = value

    oid = utils.read_only_property("_oid")
    value = utils.read_only_property("_value")

    def __eq__(self, other):
        if not isinstance(other, NameAttribute):
            return NotImplemented

        return (
            self.oid == other.oid and
            self.value == other.value
        )

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return "<NameAttribute(oid={0.oid}, value={0.value!r})>".format(self)


class ObjectIdentifier(object):
    def __init__(self, dotted_string):
        self._dotted_string = dotted_string

    def __eq__(self, other):
        if not isinstance(other, ObjectIdentifier):
            return NotImplemented

        return self._dotted_string == other._dotted_string

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return "<ObjectIdentifier(oid={0}, name={1})>".format(
            self._dotted_string,
            _OID_NAMES.get(self._dotted_string, "Unknown OID")
        )

    def __hash__(self):
        return hash(self.dotted_string)

    dotted_string = utils.read_only_property("_dotted_string")


class Name(object):
    def __init__(self, attributes):
        self._attributes = attributes

    def get_attributes_for_oid(self, oid):
        return [i for i in self if i.oid == oid]

    def __eq__(self, other):
        if not isinstance(other, Name):
            return NotImplemented

        return self._attributes == other._attributes

    def __ne__(self, other):
        return not self == other

    def __iter__(self):
        return iter(self._attributes)

    def __len__(self):
        return len(self._attributes)

    def __repr__(self):
        return "<Name({0!r})>".format(self._attributes)


OID_SUBJECT_DIRECTORY_ATTRIBUTES = ObjectIdentifier("2.5.29.9")
OID_SUBJECT_KEY_IDENTIFIER = ObjectIdentifier("2.5.29.14")
OID_KEY_USAGE = ObjectIdentifier("2.5.29.15")
OID_SUBJECT_ALTERNATIVE_NAME = ObjectIdentifier("2.5.29.17")
OID_ISSUER_ALTERNATIVE_NAME = ObjectIdentifier("2.5.29.18")
OID_BASIC_CONSTRAINTS = ObjectIdentifier("2.5.29.19")
OID_NAME_CONSTRAINTS = ObjectIdentifier("2.5.29.30")
OID_CRL_DISTRIBUTION_POINTS = ObjectIdentifier("2.5.29.31")
OID_CERTIFICATE_POLICIES = ObjectIdentifier("2.5.29.32")
OID_POLICY_MAPPINGS = ObjectIdentifier("2.5.29.33")
OID_AUTHORITY_KEY_IDENTIFIER = ObjectIdentifier("2.5.29.35")
OID_POLICY_CONSTRAINTS = ObjectIdentifier("2.5.29.36")
OID_EXTENDED_KEY_USAGE = ObjectIdentifier("2.5.29.37")
OID_FRESHEST_CRL = ObjectIdentifier("2.5.29.46")
OID_INHIBIT_ANY_POLICY = ObjectIdentifier("2.5.29.54")
OID_AUTHORITY_INFORMATION_ACCESS = ObjectIdentifier("1.3.6.1.5.5.7.1.1")
OID_SUBJECT_INFORMATION_ACCESS = ObjectIdentifier("1.3.6.1.5.5.7.1.11")
OID_OCSP_NO_CHECK = ObjectIdentifier("1.3.6.1.5.5.7.48.1.5")


class Extensions(object):
    def __init__(self, extensions):
        self._extensions = extensions

    def get_extension_for_oid(self, oid):
        for ext in self:
            if ext.oid == oid:
                return ext

        raise ExtensionNotFound("No {0} extension was found".format(oid), oid)

    def __iter__(self):
        return iter(self._extensions)

    def __len__(self):
        return len(self._extensions)


class Extension(object):
    def __init__(self, oid, critical, value):
        if not isinstance(oid, ObjectIdentifier):
            raise TypeError(
                "oid argument must be an ObjectIdentifier instance."
            )

        if not isinstance(critical, bool):
            raise TypeError("critical must be a boolean value")

        self._oid = oid
        self._critical = critical
        self._value = value

    oid = utils.read_only_property("_oid")
    critical = utils.read_only_property("_critical")
    value = utils.read_only_property("_value")

    def __repr__(self):
        return ("<Extension(oid={0.oid}, critical={0.critical}, "
                "value={0.value})>").format(self)


class ExtendedKeyUsage(object):
    def __init__(self, usages):
        if not all(isinstance(x, ObjectIdentifier) for x in usages):
            raise TypeError(
                "Every item in the usages list must be an ObjectIdentifier"
            )

        self._usages = usages

    def __iter__(self):
        return iter(self._usages)

    def __len__(self):
        return len(self._usages)

    def __repr__(self):
        return "<ExtendedKeyUsage({0})>".format(self._usages)

    def __eq__(self, other):
        if not isinstance(other, ExtendedKeyUsage):
            return NotImplemented

        return self._usages == other._usages

    def __ne__(self, other):
        return not self == other


class BasicConstraints(object):
    def __init__(self, ca, path_length):
        if not isinstance(ca, bool):
            raise TypeError("ca must be a boolean value")

        if path_length is not None and not ca:
            raise ValueError("path_length must be None when ca is False")

        if (
            path_length is not None and
            (not isinstance(path_length, six.integer_types) or path_length < 0)
        ):
            raise TypeError(
                "path_length must be a non-negative integer or None"
            )

        self._ca = ca
        self._path_length = path_length

    ca = utils.read_only_property("_ca")
    path_length = utils.read_only_property("_path_length")

    def __repr__(self):
        return ("<BasicConstraints(ca={0.ca}, "
                "path_length={0.path_length})>").format(self)

    def __eq__(self, other):
        if not isinstance(other, BasicConstraints):
            return NotImplemented

        return self.ca == other.ca and self.path_length == other.path_length

    def __ne__(self, other):
        return not self == other


class KeyUsage(object):
    def __init__(self, digital_signature, content_commitment, key_encipherment,
                 data_encipherment, key_agreement, key_cert_sign, crl_sign,
                 encipher_only, decipher_only):
        if not key_agreement and (encipher_only or decipher_only):
            raise ValueError(
                "encipher_only and decipher_only can only be true when "
                "key_agreement is true"
            )

        self._digital_signature = digital_signature
        self._content_commitment = content_commitment
        self._key_encipherment = key_encipherment
        self._data_encipherment = data_encipherment
        self._key_agreement = key_agreement
        self._key_cert_sign = key_cert_sign
        self._crl_sign = crl_sign
        self._encipher_only = encipher_only
        self._decipher_only = decipher_only

    digital_signature = utils.read_only_property("_digital_signature")
    content_commitment = utils.read_only_property("_content_commitment")
    key_encipherment = utils.read_only_property("_key_encipherment")
    data_encipherment = utils.read_only_property("_data_encipherment")
    key_agreement = utils.read_only_property("_key_agreement")
    key_cert_sign = utils.read_only_property("_key_cert_sign")
    crl_sign = utils.read_only_property("_crl_sign")

    @property
    def encipher_only(self):
        if not self.key_agreement:
            raise ValueError(
                "encipher_only is undefined unless key_agreement is true"
            )
        else:
            return self._encipher_only

    @property
    def decipher_only(self):
        if not self.key_agreement:
            raise ValueError(
                "decipher_only is undefined unless key_agreement is true"
            )
        else:
            return self._decipher_only

    def __repr__(self):
        try:
            encipher_only = self.encipher_only
            decipher_only = self.decipher_only
        except ValueError:
            encipher_only = None
            decipher_only = None

        return ("<KeyUsage(digital_signature={0.digital_signature}, "
                "content_commitment={0.content_commitment}, "
                "key_encipherment={0.key_encipherment}, "
                "data_encipherment={0.data_encipherment}, "
                "key_agreement={0.key_agreement}, "
                "key_cert_sign={0.key_cert_sign}, crl_sign={0.crl_sign}, "
                "encipher_only={1}, decipher_only={2})>").format(
                    self, encipher_only, decipher_only)

    def __eq__(self, other):
        if not isinstance(other, KeyUsage):
            return NotImplemented

        return (
            self.digital_signature == other.digital_signature and
            self.content_commitment == other.content_commitment and
            self.key_encipherment == other.key_encipherment and
            self.data_encipherment == other.data_encipherment and
            self.key_agreement == other.key_agreement and
            self.key_cert_sign == other.key_cert_sign and
            self.crl_sign == other.crl_sign and
            self._encipher_only == other._encipher_only and
            self._decipher_only == other._decipher_only
        )

    def __ne__(self, other):
        return not self == other


class AuthorityInformationAccess(object):
    def __init__(self, descriptions):
        if not all(isinstance(x, AccessDescription) for x in descriptions):
            raise TypeError(
                "Every item in the descriptions list must be an "
                "AccessDescription"
            )

        self._descriptions = descriptions

    def __iter__(self):
        return iter(self._descriptions)

    def __len__(self):
        return len(self._descriptions)

    def __repr__(self):
        return "<AuthorityInformationAccess({0})>".format(self._descriptions)

    def __eq__(self, other):
        if not isinstance(other, AuthorityInformationAccess):
            return NotImplemented

        return self._descriptions == other._descriptions

    def __ne__(self, other):
        return not self == other


class AccessDescription(object):
    def __init__(self, access_method, access_location):
        if not (access_method == OID_OCSP or access_method == OID_CA_ISSUERS):
            raise ValueError(
                "access_method must be OID_OCSP or OID_CA_ISSUERS"
            )

        if not isinstance(access_location, GeneralName):
            raise TypeError("access_location must be a GeneralName")

        self._access_method = access_method
        self._access_location = access_location

    def __repr__(self):
        return (
            "<AccessDescription(access_method={0.access_method}, access_locati"
            "on={0.access_location})>".format(self)
        )

    def __eq__(self, other):
        if not isinstance(other, AccessDescription):
            return NotImplemented

        return (
            self.access_method == other.access_method and
            self.access_location == other.access_location
        )

    def __ne__(self, other):
        return not self == other

    access_method = utils.read_only_property("_access_method")
    access_location = utils.read_only_property("_access_location")


class CertificatePolicies(object):
    def __init__(self, policies):
        if not all(isinstance(x, PolicyInformation) for x in policies):
            raise TypeError(
                "Every item in the policies list must be a "
                "PolicyInformation"
            )

        self._policies = policies

    def __iter__(self):
        return iter(self._policies)

    def __len__(self):
        return len(self._policies)

    def __repr__(self):
        return "<CertificatePolicies({0})>".format(self._policies)

    def __eq__(self, other):
        if not isinstance(other, CertificatePolicies):
            return NotImplemented

        return self._policies == other._policies

    def __ne__(self, other):
        return not self == other


class PolicyInformation(object):
    def __init__(self, policy_identifier, policy_qualifiers):
        if not isinstance(policy_identifier, ObjectIdentifier):
            raise TypeError("policy_identifier must be an ObjectIdentifier")

        self._policy_identifier = policy_identifier
        if policy_qualifiers and not all(
            isinstance(
                x, (six.text_type, UserNotice)
            ) for x in policy_qualifiers
        ):
            raise TypeError(
                "policy_qualifiers must be a list of strings and/or UserNotice"
                " objects or None"
            )

        self._policy_qualifiers = policy_qualifiers

    def __repr__(self):
        return (
            "<PolicyInformation(policy_identifier={0.policy_identifier}, polic"
            "y_qualifiers={0.policy_qualifiers})>".format(self)
        )

    def __eq__(self, other):
        if not isinstance(other, PolicyInformation):
            return NotImplemented

        return (
            self.policy_identifier == other.policy_identifier and
            self.policy_qualifiers == other.policy_qualifiers
        )

    def __ne__(self, other):
        return not self == other

    policy_identifier = utils.read_only_property("_policy_identifier")
    policy_qualifiers = utils.read_only_property("_policy_qualifiers")


class UserNotice(object):
    def __init__(self, notice_reference, explicit_text):
        if notice_reference and not isinstance(
            notice_reference, NoticeReference
        ):
            raise TypeError(
                "notice_reference must be None or a NoticeReference"
            )

        self._notice_reference = notice_reference
        self._explicit_text = explicit_text

    def __repr__(self):
        return (
            "<UserNotice(notice_reference={0.notice_reference}, explicit_text="
            "{0.explicit_text!r})>".format(self)
        )

    def __eq__(self, other):
        if not isinstance(other, UserNotice):
            return NotImplemented

        return (
            self.notice_reference == other.notice_reference and
            self.explicit_text == other.explicit_text
        )

    def __ne__(self, other):
        return not self == other

    notice_reference = utils.read_only_property("_notice_reference")
    explicit_text = utils.read_only_property("_explicit_text")


class NoticeReference(object):
    def __init__(self, organization, notice_numbers):
        self._organization = organization
        if not isinstance(notice_numbers, list) or not all(
            isinstance(x, int) for x in notice_numbers
        ):
            raise TypeError(
                "notice_numbers must be a list of integers"
            )

        self._notice_numbers = notice_numbers

    def __repr__(self):
        return (
            "<NoticeReference(organization={0.organization!r}, notice_numbers="
            "{0.notice_numbers})>".format(self)
        )

    def __eq__(self, other):
        if not isinstance(other, NoticeReference):
            return NotImplemented

        return (
            self.organization == other.organization and
            self.notice_numbers == other.notice_numbers
        )

    def __ne__(self, other):
        return not self == other

    organization = utils.read_only_property("_organization")
    notice_numbers = utils.read_only_property("_notice_numbers")


class SubjectKeyIdentifier(object):
    def __init__(self, digest):
        self._digest = digest

    digest = utils.read_only_property("_digest")

    def __repr__(self):
        return "<SubjectKeyIdentifier(digest={0!r})>".format(self.digest)

    def __eq__(self, other):
        if not isinstance(other, SubjectKeyIdentifier):
            return NotImplemented

        return (
            self.digest == other.digest
        )

    def __ne__(self, other):
        return not self == other


class CRLDistributionPoints(object):
    def __init__(self, distribution_points):
        if not all(
            isinstance(x, DistributionPoint) for x in distribution_points
        ):
            raise TypeError(
                "distribution_points must be a list of DistributionPoint "
                "objects"
            )

        self._distribution_points = distribution_points

    def __iter__(self):
        return iter(self._distribution_points)

    def __len__(self):
        return len(self._distribution_points)

    def __repr__(self):
        return "<CRLDistributionPoints({0})>".format(self._distribution_points)

    def __eq__(self, other):
        if not isinstance(other, CRLDistributionPoints):
            return NotImplemented

        return self._distribution_points == other._distribution_points

    def __ne__(self, other):
        return not self == other


class DistributionPoint(object):
    def __init__(self, full_name, relative_name, reasons, crl_issuer):
        if full_name and relative_name:
            raise ValueError(
                "At least one of full_name and relative_name must be None"
            )

        if full_name and not all(
            isinstance(x, GeneralName) for x in full_name
        ):
            raise TypeError(
                "full_name must be a list of GeneralName objects"
            )

        if relative_name and not isinstance(relative_name, Name):
            raise TypeError("relative_name must be a Name")

        if crl_issuer and not all(
            isinstance(x, GeneralName) for x in crl_issuer
        ):
            raise TypeError(
                "crl_issuer must be None or a list of general names"
            )

        if reasons and (not isinstance(reasons, frozenset) or not all(
            isinstance(x, ReasonFlags) for x in reasons
        )):
            raise TypeError("reasons must be None or frozenset of ReasonFlags")

        if reasons and (
            ReasonFlags.unspecified in reasons or
            ReasonFlags.remove_from_crl in reasons
        ):
            raise ValueError(
                "unspecified and remove_from_crl are not valid reasons in a "
                "DistributionPoint"
            )

        if reasons and not crl_issuer and not (full_name or relative_name):
            raise ValueError(
                "You must supply crl_issuer, full_name, or relative_name when "
                "reasons is not None"
            )

        self._full_name = full_name
        self._relative_name = relative_name
        self._reasons = reasons
        self._crl_issuer = crl_issuer

    def __repr__(self):
        return (
            "<DistributionPoint(full_name={0.full_name}, relative_name={0.rela"
            "tive_name}, reasons={0.reasons}, crl_issuer={0.crl_is"
            "suer})>".format(self)
        )

    def __eq__(self, other):
        if not isinstance(other, DistributionPoint):
            return NotImplemented

        return (
            self.full_name == other.full_name and
            self.relative_name == other.relative_name and
            self.reasons == other.reasons and
            self.crl_issuer == other.crl_issuer
        )

    def __ne__(self, other):
        return not self == other

    full_name = utils.read_only_property("_full_name")
    relative_name = utils.read_only_property("_relative_name")
    reasons = utils.read_only_property("_reasons")
    crl_issuer = utils.read_only_property("_crl_issuer")


class ReasonFlags(Enum):
    unspecified = "unspecified"
    key_compromise = "keyCompromise"
    ca_compromise = "cACompromise"
    affiliation_changed = "affiliationChanged"
    superseded = "superseded"
    cessation_of_operation = "cessationOfOperation"
    certificate_hold = "certificateHold"
    privilege_withdrawn = "privilegeWithdrawn"
    aa_compromise = "aACompromise"
    remove_from_crl = "removeFromCRL"


@six.add_metaclass(abc.ABCMeta)
class GeneralName(object):
    @abc.abstractproperty
    def value(self):
        """
        Return the value of the object
        """


@utils.register_interface(GeneralName)
class RFC822Name(object):
    def __init__(self, value):
        if not isinstance(value, six.text_type):
            raise TypeError("value must be a unicode string")

        self._value = value

    value = utils.read_only_property("_value")

    def __repr__(self):
        return "<RFC822Name(value={0})>".format(self.value)

    def __eq__(self, other):
        if not isinstance(other, RFC822Name):
            return NotImplemented

        return self.value == other.value

    def __ne__(self, other):
        return not self == other


@utils.register_interface(GeneralName)
class DNSName(object):
    def __init__(self, value):
        if not isinstance(value, six.text_type):
            raise TypeError("value must be a unicode string")

        self._value = value

    value = utils.read_only_property("_value")

    def __repr__(self):
        return "<DNSName(value={0})>".format(self.value)

    def __eq__(self, other):
        if not isinstance(other, DNSName):
            return NotImplemented

        return self.value == other.value

    def __ne__(self, other):
        return not self == other


@utils.register_interface(GeneralName)
class UniformResourceIdentifier(object):
    def __init__(self, value):
        if not isinstance(value, six.text_type):
            raise TypeError("value must be a unicode string")

        self._value = value

    value = utils.read_only_property("_value")

    def __repr__(self):
        return "<UniformResourceIdentifier(value={0})>".format(self.value)

    def __eq__(self, other):
        if not isinstance(other, UniformResourceIdentifier):
            return NotImplemented

        return self.value == other.value

    def __ne__(self, other):
        return not self == other


@utils.register_interface(GeneralName)
class DirectoryName(object):
    def __init__(self, value):
        if not isinstance(value, Name):
            raise TypeError("value must be a Name")

        self._value = value

    value = utils.read_only_property("_value")

    def __repr__(self):
        return "<DirectoryName(value={0})>".format(self.value)

    def __eq__(self, other):
        if not isinstance(other, DirectoryName):
            return NotImplemented

        return self.value == other.value

    def __ne__(self, other):
        return not self == other


@utils.register_interface(GeneralName)
class RegisteredID(object):
    def __init__(self, value):
        if not isinstance(value, ObjectIdentifier):
            raise TypeError("value must be an ObjectIdentifier")

        self._value = value

    value = utils.read_only_property("_value")

    def __repr__(self):
        return "<RegisteredID(value={0})>".format(self.value)

    def __eq__(self, other):
        if not isinstance(other, RegisteredID):
            return NotImplemented

        return self.value == other.value

    def __ne__(self, other):
        return not self == other


@utils.register_interface(GeneralName)
class IPAddress(object):
    def __init__(self, value):
        if not isinstance(
            value, (ipaddress.IPv4Address, ipaddress.IPv6Address)
        ):
            raise TypeError(
                "value must be an instance of ipaddress.IPv4Address or "
                "ipaddress.IPv6Address"
            )

        self._value = value

    value = utils.read_only_property("_value")

    def __repr__(self):
        return "<IPAddress(value={0})>".format(self.value)

    def __eq__(self, other):
        if not isinstance(other, IPAddress):
            return NotImplemented

        return self.value == other.value

    def __ne__(self, other):
        return not self == other


class SubjectAlternativeName(object):
    def __init__(self, general_names):
        if not all(isinstance(x, GeneralName) for x in general_names):
            raise TypeError(
                "Every item in the general_names list must be an "
                "object conforming to the GeneralName interface"
            )

        self._general_names = general_names

    def __iter__(self):
        return iter(self._general_names)

    def __len__(self):
        return len(self._general_names)

    def get_values_for_type(self, type):
        return [i.value for i in self if isinstance(i, type)]

    def __repr__(self):
        return "<SubjectAlternativeName({0})>".format(self._general_names)

    def __eq__(self, other):
        if not isinstance(other, SubjectAlternativeName):
            return NotImplemented

        return self._general_names == other._general_names

    def __ne__(self, other):
        return not self == other


class AuthorityKeyIdentifier(object):
    def __init__(self, key_identifier, authority_cert_issuer,
                 authority_cert_serial_number):
        if authority_cert_issuer or authority_cert_serial_number:
            if not authority_cert_issuer or not authority_cert_serial_number:
                raise ValueError(
                    "authority_cert_issuer and authority_cert_serial_number "
                    "must both be present or both None"
                )

            if not all(
                isinstance(x, GeneralName) for x in authority_cert_issuer
            ):
                raise TypeError(
                    "authority_cert_issuer must be a list of GeneralName "
                    "objects"
                )

            if not isinstance(authority_cert_serial_number, six.integer_types):
                raise TypeError(
                    "authority_cert_serial_number must be an integer"
                )

        self._key_identifier = key_identifier
        self._authority_cert_issuer = authority_cert_issuer
        self._authority_cert_serial_number = authority_cert_serial_number

    def __repr__(self):
        return (
            "<AuthorityKeyIdentifier(key_identifier={0.key_identifier!r}, "
            "authority_cert_issuer={0.authority_cert_issuer}, "
            "authority_cert_serial_number={0.authority_cert_serial_number}"
            ")>".format(self)
        )

    def __eq__(self, other):
        if not isinstance(other, AuthorityKeyIdentifier):
            return NotImplemented

        return (
            self.key_identifier == other.key_identifier and
            self.authority_cert_issuer == other.authority_cert_issuer and
            self.authority_cert_serial_number ==
            other.authority_cert_serial_number
        )

    def __ne__(self, other):
        return not self == other

    key_identifier = utils.read_only_property("_key_identifier")
    authority_cert_issuer = utils.read_only_property("_authority_cert_issuer")
    authority_cert_serial_number = utils.read_only_property(
        "_authority_cert_serial_number"
    )


OID_COMMON_NAME = ObjectIdentifier("2.5.4.3")
OID_COUNTRY_NAME = ObjectIdentifier("2.5.4.6")
OID_LOCALITY_NAME = ObjectIdentifier("2.5.4.7")
OID_STATE_OR_PROVINCE_NAME = ObjectIdentifier("2.5.4.8")
OID_ORGANIZATION_NAME = ObjectIdentifier("2.5.4.10")
OID_ORGANIZATIONAL_UNIT_NAME = ObjectIdentifier("2.5.4.11")
OID_SERIAL_NUMBER = ObjectIdentifier("2.5.4.5")
OID_SURNAME = ObjectIdentifier("2.5.4.4")
OID_GIVEN_NAME = ObjectIdentifier("2.5.4.42")
OID_TITLE = ObjectIdentifier("2.5.4.12")
OID_GENERATION_QUALIFIER = ObjectIdentifier("2.5.4.44")
OID_DN_QUALIFIER = ObjectIdentifier("2.5.4.46")
OID_PSEUDONYM = ObjectIdentifier("2.5.4.65")
OID_DOMAIN_COMPONENT = ObjectIdentifier("0.9.2342.19200300.100.1.25")
OID_EMAIL_ADDRESS = ObjectIdentifier("1.2.840.113549.1.9.1")

OID_RSA_WITH_MD5 = ObjectIdentifier("1.2.840.113549.1.1.4")
OID_RSA_WITH_SHA1 = ObjectIdentifier("1.2.840.113549.1.1.5")
OID_RSA_WITH_SHA224 = ObjectIdentifier("1.2.840.113549.1.1.14")
OID_RSA_WITH_SHA256 = ObjectIdentifier("1.2.840.113549.1.1.11")
OID_RSA_WITH_SHA384 = ObjectIdentifier("1.2.840.113549.1.1.12")
OID_RSA_WITH_SHA512 = ObjectIdentifier("1.2.840.113549.1.1.13")
OID_ECDSA_WITH_SHA224 = ObjectIdentifier("1.2.840.10045.4.3.1")
OID_ECDSA_WITH_SHA256 = ObjectIdentifier("1.2.840.10045.4.3.2")
OID_ECDSA_WITH_SHA384 = ObjectIdentifier("1.2.840.10045.4.3.3")
OID_ECDSA_WITH_SHA512 = ObjectIdentifier("1.2.840.10045.4.3.4")
OID_DSA_WITH_SHA1 = ObjectIdentifier("1.2.840.10040.4.3")
OID_DSA_WITH_SHA224 = ObjectIdentifier("2.16.840.1.101.3.4.3.1")
OID_DSA_WITH_SHA256 = ObjectIdentifier("2.16.840.1.101.3.4.3.2")

_SIG_OIDS_TO_HASH = {
    OID_RSA_WITH_MD5.dotted_string: hashes.MD5(),
    OID_RSA_WITH_SHA1.dotted_string: hashes.SHA1(),
    OID_RSA_WITH_SHA224.dotted_string: hashes.SHA224(),
    OID_RSA_WITH_SHA256.dotted_string: hashes.SHA256(),
    OID_RSA_WITH_SHA384.dotted_string: hashes.SHA384(),
    OID_RSA_WITH_SHA512.dotted_string: hashes.SHA512(),
    OID_ECDSA_WITH_SHA224.dotted_string: hashes.SHA224(),
    OID_ECDSA_WITH_SHA256.dotted_string: hashes.SHA256(),
    OID_ECDSA_WITH_SHA384.dotted_string: hashes.SHA384(),
    OID_ECDSA_WITH_SHA512.dotted_string: hashes.SHA512(),
    OID_DSA_WITH_SHA1.dotted_string: hashes.SHA1(),
    OID_DSA_WITH_SHA224.dotted_string: hashes.SHA224(),
    OID_DSA_WITH_SHA256.dotted_string: hashes.SHA256()
}

OID_SERVER_AUTH = ObjectIdentifier("1.3.6.1.5.5.7.3.1")
OID_CLIENT_AUTH = ObjectIdentifier("1.3.6.1.5.5.7.3.2")
OID_CODE_SIGNING = ObjectIdentifier("1.3.6.1.5.5.7.3.3")
OID_EMAIL_PROTECTION = ObjectIdentifier("1.3.6.1.5.5.7.3.4")
OID_TIME_STAMPING = ObjectIdentifier("1.3.6.1.5.5.7.3.8")
OID_OCSP_SIGNING = ObjectIdentifier("1.3.6.1.5.5.7.3.9")

OID_CA_ISSUERS = ObjectIdentifier("1.3.6.1.5.5.7.48.2")
OID_OCSP = ObjectIdentifier("1.3.6.1.5.5.7.48.1")

OID_CPS_QUALIFIER = ObjectIdentifier("1.3.6.1.5.5.7.2.1")
OID_CPS_USER_NOTICE = ObjectIdentifier("1.3.6.1.5.5.7.2.2")


@six.add_metaclass(abc.ABCMeta)
class Certificate(object):
    @abc.abstractmethod
    def fingerprint(self, algorithm):
        """
        Returns bytes using digest passed.
        """

    @abc.abstractproperty
    def serial(self):
        """
        Returns certificate serial number
        """

    @abc.abstractproperty
    def version(self):
        """
        Returns the certificate version
        """

    @abc.abstractmethod
    def public_key(self):
        """
        Returns the public key
        """

    @abc.abstractproperty
    def not_valid_before(self):
        """
        Not before time (represented as UTC datetime)
        """

    @abc.abstractproperty
    def not_valid_after(self):
        """
        Not after time (represented as UTC datetime)
        """

    @abc.abstractproperty
    def issuer(self):
        """
        Returns the issuer name object.
        """

    @abc.abstractproperty
    def subject(self):
        """
        Returns the subject name object.
        """

    @abc.abstractproperty
    def signature_hash_algorithm(self):
        """
        Returns a HashAlgorithm corresponding to the type of the digest signed
        in the certificate.
        """

    @abc.abstractmethod
    def __eq__(self, other):
        """
        Checks equality.
        """

    @abc.abstractmethod
    def __ne__(self, other):
        """
        Checks not equal.
        """


@six.add_metaclass(abc.ABCMeta)
class CertificateSigningRequest(object):
    @abc.abstractmethod
    def public_key(self):
        """
        Returns the public key
        """

    @abc.abstractproperty
    def subject(self):
        """
        Returns the subject name object.
        """

    @abc.abstractproperty
    def signature_hash_algorithm(self):
        """
        Returns a HashAlgorithm corresponding to the type of the digest signed
        in the certificate.
        """
