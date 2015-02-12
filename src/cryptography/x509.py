# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc
from enum import Enum

import six

from cryptography import utils


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
    "1.2.840.113549.1.1.4": "md5WithRSA",
    "1.2.840.113549.1.1.5": "sha1WithRSA",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.3.1": "ecdsa_with_SHA224",
    "1.2.840.10045.4.3.2": "ecdsa_with_SHA256",
    "1.2.840.10045.4.3.3": "ecdsa_with_SHA384",
    "1.2.840.10045.4.3.4": "ecdsa_with_SHA512",
    "1.2.840.10040.4.3": "dsaWithSHA1",
    "2.16.840.1.101.3.4.3.1": "dsa_with_SHA224",
    "2.16.840.1.101.3.4.3.2": "dsa_with_SHA256",
}


class Version(Enum):
    v1 = 0
    v3 = 2


def load_pem_x509_certificate(data, backend):
    return backend.load_pem_x509_certificate(data)


def load_der_x509_certificate(data, backend):
    return backend.load_der_x509_certificate(data)


class InvalidVersion(Exception):
    def __init__(self, msg, parsed_version):
        super(InvalidVersion, self).__init__(msg)
        self.parsed_version = parsed_version


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
        return "<NameAttribute(oid={oid}, value={value!r})>".format(
            oid=self.oid,
            value=self.value
        )


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

    dotted_string = utils.read_only_property("_dotted_string")


class Name(object):
    def __init__(self, attributes):
        self._attributes = attributes

    def get_attributes_for_oid(self, oid):
        return [i for i in self._attributes if i.oid == oid]

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

OID_MD5_WITH_RSA = ObjectIdentifier("1.2.840.113549.1.1.4")
OID_SHA1_WITH_RSA = ObjectIdentifier("1.2.840.113549.1.1.5")
OID_SHA224_WITH_RSA = ObjectIdentifier("1.2.840.113549.1.1.14")
OID_SHA256_WITH_RSA = ObjectIdentifier("1.2.840.113549.1.1.11")
OID_SHA384_WITH_RSA = ObjectIdentifier("1.2.840.113549.1.1.12")
OID_SHA512_WITH_RSA = ObjectIdentifier("1.2.840.113549.1.1.13")
OID_ECDSA_WITH_SHA224 = ObjectIdentifier("1.2.840.10045.4.3.1")
OID_ECDSA_WITH_SHA256 = ObjectIdentifier("1.2.840.10045.4.3.2")
OID_ECDSA_WITH_SHA384 = ObjectIdentifier("1.2.840.10045.4.3.3")
OID_ECDSA_WITH_SHA512 = ObjectIdentifier("1.2.840.10045.4.3.4")
OID_DSA_WITH_SHA1 = ObjectIdentifier("1.2.840.10040.4.3")
OID_DSA_WITH_SHA224 = ObjectIdentifier("2.16.840.1.101.3.4.3.1")
OID_DSA_WITH_SHA256 = ObjectIdentifier("2.16.840.1.101.3.4.3.2")


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
    def signature_algorithm(self):
        """
        Returns an ObjectIdentifier corresponding to the signature algorithm of
        the certificate.
        """
