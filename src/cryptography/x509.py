# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc
from enum import Enum

import six

from cryptography import utils


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


class UnknownAttribute(Exception):
    pass


class Attribute(object):
    def __init__(self, oid, name, value):
        self._oid = oid
        self._name = name
        self._value = value

    oid = utils.read_only_property("_oid")
    name = utils.read_only_property("_name")
    value = utils.read_only_property("_value")

    def __eq__(self, other):
        if not isinstance(other, Attribute):
            return NotImplemented

        return (
            self.oid == other.oid and
            self.name == other.name and
            self.value == other.value
        )

    def __ne__(self, other):
        return not self == other


class Name(object):
    def __init__(self, attributes):
        self._attributes = attributes

    def _build_list(self, oid):
        return [i for i in self._attributes if i.oid == oid]

    @property
    def common_name(self):
        return self._build_list("2.5.4.3")

    @property
    def country_name(self):
        return self._build_list("2.5.4.6")

    @property
    def locality_name(self):
        return self._build_list("2.5.4.7")

    @property
    def state_or_province_name(self):
        return self._build_list("2.5.4.8")

    @property
    def organization_name(self):
        return self._build_list("2.5.4.10")

    @property
    def organizational_unit_name(self):
        return self._build_list("2.5.4.11")

    @property
    def serial_number(self):
        return self._build_list("2.5.4.5")

    @property
    def surname(self):
        return self._build_list("2.5.4.4")

    @property
    def given_name(self):
        return self._build_list("2.5.4.42")

    @property
    def title(self):
        return self._build_list("2.5.4.12")

    @property
    def generation_qualifier(self):
        return self._build_list("2.5.4.44")

    @property
    def dn_qualifier(self):
        return self._build_list("2.5.4.46")

    @property
    def pseudonym(self):
        return self._build_list("2.5.4.65")

    @property
    def domain_component(self):
        return self._build_list("0.9.2342.19200300.100.1.25")

    @property
    def email_address(self):
        return self._build_list("1.2.840.113549.1.9.1")

    @property
    def attributes(self):
        return [i for i in self._attributes]


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
