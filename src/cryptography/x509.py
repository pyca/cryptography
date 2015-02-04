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
            raise TypeError("oid argument must be an ObjectIdentifier object")

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
