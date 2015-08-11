# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import hashlib
from enum import Enum

from pyasn1.codec.der import decoder
from pyasn1.type import namedtype, univ

import six

from cryptography import utils
from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import ExtensionType
from cryptography.x509.general_name import GeneralName
from cryptography.x509.name import Name
from cryptography.x509.oid import (
    AuthorityInformationAccessOID, ExtensionOID, ObjectIdentifier
)


class _SubjectPublicKeyInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.Sequence()),
        namedtype.NamedType('subjectPublicKey', univ.BitString())
    )


def _key_identifier_from_public_key(public_key):
    # This is a very slow way to do this.
    serialized = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    spki, remaining = decoder.decode(
        serialized, asn1Spec=_SubjectPublicKeyInfo()
    )
    assert not remaining
    # the univ.BitString object is a tuple of bits. We need bytes and
    # pyasn1 really doesn't want to give them to us. To get it we'll
    # build an integer and convert that to bytes.
    bits = 0
    for bit in spki.getComponentByName("subjectPublicKey"):
        bits = bits << 1 | bit

    data = utils.int_to_bytes(bits)
    return hashlib.sha1(data).digest()


@utils.register_interface(ExtensionType)
class AuthorityKeyIdentifier(object):
    oid = ExtensionOID.AUTHORITY_KEY_IDENTIFIER

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

    @classmethod
    def from_issuer_public_key(cls, public_key):
        digest = _key_identifier_from_public_key(public_key)
        return cls(
            key_identifier=digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        )

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


@utils.register_interface(ExtensionType)
class SubjectKeyIdentifier(object):
    oid = ExtensionOID.SUBJECT_KEY_IDENTIFIER

    def __init__(self, digest):
        self._digest = digest

    @classmethod
    def from_public_key(cls, public_key):
        return cls(_key_identifier_from_public_key(public_key))

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


@utils.register_interface(ExtensionType)
class AuthorityInformationAccess(object):
    oid = ExtensionOID.AUTHORITY_INFORMATION_ACCESS

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
        if not (access_method == AuthorityInformationAccessOID.OCSP or
                access_method == AuthorityInformationAccessOID.CA_ISSUERS):
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


@utils.register_interface(ExtensionType)
class BasicConstraints(object):
    oid = ExtensionOID.BASIC_CONSTRAINTS

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


@utils.register_interface(ExtensionType)
class CRLDistributionPoints(object):
    oid = ExtensionOID.CRL_DISTRIBUTION_POINTS

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
                "You cannot provide both full_name and relative_name, at "
                "least one must be None."
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


@utils.register_interface(ExtensionType)
class CertificatePolicies(object):
    oid = ExtensionOID.CERTIFICATE_POLICIES

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


@utils.register_interface(ExtensionType)
class ExtendedKeyUsage(object):
    oid = ExtensionOID.EXTENDED_KEY_USAGE

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


@utils.register_interface(ExtensionType)
class OCSPNoCheck(object):
    oid = ExtensionOID.OCSP_NO_CHECK


@utils.register_interface(ExtensionType)
class InhibitAnyPolicy(object):
    oid = ExtensionOID.INHIBIT_ANY_POLICY

    def __init__(self, skip_certs):
        if not isinstance(skip_certs, six.integer_types):
            raise TypeError("skip_certs must be an integer")

        if skip_certs < 0:
            raise ValueError("skip_certs must be a non-negative integer")

        self._skip_certs = skip_certs

    def __repr__(self):
        return "<InhibitAnyPolicy(skip_certs={0.skip_certs})>".format(self)

    def __eq__(self, other):
        if not isinstance(other, InhibitAnyPolicy):
            return NotImplemented

        return self.skip_certs == other.skip_certs

    def __ne__(self, other):
        return not self == other

    skip_certs = utils.read_only_property("_skip_certs")
