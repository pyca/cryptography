# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc
import collections
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


Attribute = collections.namedtuple("Attribute", ["oid", "name", "value"])


class Name(object):
    def __init__(self, attributes):
        self._attributes = attributes
        self._country_name = []
        self._organization_name = []
        self._organizational_unit_name = []
        self._dn_qualifier = []
        self._state_or_province_name = []
        self._common_name = []
        self._serial_number = []
        self._locality_name = []
        self._title = []
        self._surname = []
        self._given_name = []
        self._pseudonym = []
        self._generation_qualifier = []
        self._domain_component = []
        self._email_address = []

        for attribute in attributes:
            if attribute.oid == "2.5.4.3":
                self._common_name.append(attribute)
            elif attribute.oid == "2.5.4.6":
                self._country_name.append(attribute)
            elif attribute.oid == "2.5.4.7":
                self._locality_name.append(attribute)
            elif attribute.oid == "2.5.4.8":
                self._state_or_province_name.append(attribute)
            elif attribute.oid == "2.5.4.10":
                self._organization_name.append(attribute)
            elif attribute.oid == "2.5.4.11":
                self._organizational_unit_name.append(attribute)
            elif attribute.oid == "2.5.4.5":
                self._serial_number.append(attribute)
            elif attribute.oid == "2.5.4.4":
                self._surname.append(attribute)
            elif attribute.oid == "2.5.4.42":
                self._given_name.append(attribute)
            elif attribute.oid == "2.5.4.12":
                self._title.append(attribute)
            elif attribute.oid == "2.5.4.44":
                self._generation_qualifier.append(attribute)
            elif attribute.oid == "2.5.4.46":
                self._dn_qualifier.append(attribute)
            elif attribute.oid == "2.5.4.65":
                self._pseudonym.append(attribute)
            elif attribute.oid == "0.9.2342.19200300.100.1.25":
                self._domain_component.append(attribute)
            elif attribute.oid == "1.2.840.113549.1.9.1":
                self._email_address.append(attribute)
            else:
                raise UnknownAttribute(
                    "Unknown OID: {0}".format(attribute.oid)
                )

    country_name = utils.read_only_property("_country_name")
    organization_name = utils.read_only_property("_organization_name")
    organizational_unit_name = utils.read_only_property(
        "_organizational_unit_name"
    )
    dn_qualifier = utils.read_only_property(
        "_dn_qualifier"
    )
    state_or_province_name = utils.read_only_property(
        "_state_or_province_name"
    )
    common_name = utils.read_only_property("_common_name")
    serial_number = utils.read_only_property("_serial_number")
    locality_name = utils.read_only_property("_locality_name")
    title = utils.read_only_property("_title")
    surname = utils.read_only_property("_surname")
    given_name = utils.read_only_property("_given_name")
    pseudonym = utils.read_only_property("_pseudonym")
    generation_qualifier = utils.read_only_property("_generation_qualifier")
    domain_component = utils.read_only_property("_domain_component")
    email_address = utils.read_only_property("_email_address")
    attributes = utils.read_only_property("_attributes")


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
