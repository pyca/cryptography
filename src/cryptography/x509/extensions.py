# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import hashlib

from pyasn1.codec.der import decoder
from pyasn1.type import namedtype, univ

import six

from cryptography import utils
from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import ExtensionType
from cryptography.x509.general_name import GeneralName
from cryptography.x509.oid import (
    ExtensionOID
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
