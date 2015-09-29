# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc
import datetime
from enum import Enum

import six

from cryptography import utils
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.extensions import Extension, ExtensionType
from cryptography.x509.name import Name


_UNIX_EPOCH = datetime.datetime(1970, 1, 1)


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

    @abc.abstractproperty
    def extensions(self):
        """
        Returns an Extensions object.
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

    @abc.abstractmethod
    def __hash__(self):
        """
        Computes a hash.
        """

    @abc.abstractmethod
    def public_bytes(self, encoding):
        """
        Serializes the certificate to PEM or DER format.
        """


@six.add_metaclass(abc.ABCMeta)
class CertificateRevocationList(object):

    @abc.abstractmethod
    def fingerprint(self, algorithm):
        """
        Returns bytes using digest passed.
        """

    @abc.abstractproperty
    def signature_hash_algorithm(self):
        """
        Returns a HashAlgorithm corresponding to the type of the digest signed
        in the certificate.
        """

    @abc.abstractproperty
    def issuer(self):
        """
        Returns the X509Name with the issuer of this CRL.
        """

    @abc.abstractproperty
    def next_update(self):
        """
        Returns the date of next update for this CRL.
        """

    @abc.abstractproperty
    def last_update(self):
        """
        Returns the date of last update for this CRL.
        """

    @abc.abstractproperty
    def revoked_certificates(self):
        """
        Returns a list of RevokedCertificate objects for this CRL.
        """

    @abc.abstractproperty
    def extensions(self):
        """
        Returns an Extensions object containing a list of CRL extensions.
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
    def __eq__(self, other):
        """
        Checks equality.
        """

    @abc.abstractmethod
    def __ne__(self, other):
        """
        Checks not equal.
        """

    @abc.abstractmethod
    def __hash__(self):
        """
        Computes a hash.
        """

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

    @abc.abstractproperty
    def extensions(self):
        """
        Returns the extensions in the signing request.
        """

    @abc.abstractmethod
    def public_bytes(self, encoding):
        """
        Encodes the request to PEM or DER format.
        """


@six.add_metaclass(abc.ABCMeta)
class RevokedCertificate(object):
    @abc.abstractproperty
    def serial_number(self):
        """
        Returns the serial number of the revoked certificate.
        """

    @abc.abstractproperty
    def revocation_date(self):
        """
        Returns the date of when this certificate was revoked.
        """

    @abc.abstractproperty
    def extensions(self):
        """
        Returns an Extensions object containing a list of Revoked extensions.
        """


class CertificateSigningRequestBuilder(object):
    def __init__(self, subject_name=None, extensions=[]):
        """
        Creates an empty X.509 certificate request (v1).
        """
        self._subject_name = subject_name
        self._extensions = extensions

    def subject_name(self, name):
        """
        Sets the certificate requestor's distinguished name.
        """
        if not isinstance(name, Name):
            raise TypeError('Expecting x509.Name object.')
        if self._subject_name is not None:
            raise ValueError('The subject name may only be set once.')
        return CertificateSigningRequestBuilder(name, self._extensions)

    def add_extension(self, extension, critical):
        """
        Adds an X.509 extension to the certificate request.
        """
        if not isinstance(extension, ExtensionType):
            raise TypeError("extension must be an ExtensionType")

        extension = Extension(extension.oid, critical, extension)

        # TODO: This is quadratic in the number of extensions
        for e in self._extensions:
            if e.oid == extension.oid:
                raise ValueError('This extension has already been set.')
        return CertificateSigningRequestBuilder(
            self._subject_name, self._extensions + [extension]
        )

    def sign(self, private_key, algorithm, backend):
        """
        Signs the request using the requestor's private key.
        """
        if self._subject_name is None:
            raise ValueError("A CertificateSigningRequest must have a subject")
        return backend.create_x509_csr(self, private_key, algorithm)


class CertificateBuilder(object):
    def __init__(self, issuer_name=None, subject_name=None,
                 public_key=None, serial_number=None,
                 not_valid_before=None, not_valid_after=None,
                 optional_extensions=[], critical_extensions=[]):
        self._version = Version.v3
        self._issuer_name = None
        self._subject_name = None
        self._public_key = None
        self._serial_number = None
        self._not_valid_before = None
        self._not_valid_after = None
        self._extensions = []

        if issuer_name is not None:
            self._set_issuer_name(issuer_name)

        if subject_name is not None:
            self._set_subject_name(subject_name)

        if public_key is not None:
            self._set_public_key(public_key)

        if serial_number is not None:
            self._set_serial_number(serial_number)

        if not_valid_before is not None:
            self._set_not_valid_before(not_valid_before)

        if not_valid_after is not None:
            self._set_not_valid_after(not_valid_after)

        for extension in optional_extensions:
            self._add_extension(extension, critical=False)

        for extension in critical_extensions:
            self._add_extension(extension, critical=True)

    def _clone(self):
        clone = self.__class__()
        clone._issuer_name = self._issuer_name
        clone._subject_name = self._subject_name
        clone._public_key = self._public_key
        clone._serial_number = self._serial_number
        clone._not_valid_before = self._not_valid_before
        clone._not_valid_after = self._not_valid_after
        clone._extensions = list(self._extensions)
        return clone

    def _set_issuer_name(self, issuer_name):
        if not isinstance(issuer_name, Name):
            raise TypeError('Expecting x509.Name object for issuer name.')
        if self._issuer_name is not None:
            raise ValueError('The issuer name may only be set once.')
        self._issuer_name = issuer_name

    def issuer_name(self, name):
        """
        Sets the CA's distinguished name.
        """
        clone = self._clone()
        clone._set_issuer_name(name)
        return clone

    def _set_subject_name(self, subject_name):
        if not isinstance(subject_name, Name):
            raise TypeError('Expecting x509.Name object for subject name.')
        if self._subject_name is not None:
            raise ValueError('The subject name may only be set once.')
        self._subject_name = subject_name

    def subject_name(self, name):
        """
        Sets the requestor's distinguished name.
        """
        clone = self._clone()
        clone._set_subject_name(name)
        return clone

    def _set_public_key(self, public_key):
        if not isinstance(public_key, (dsa.DSAPublicKey, rsa.RSAPublicKey,
                                       ec.EllipticCurvePublicKey)):
            raise TypeError('Expecting one of DSAPublicKey, RSAPublicKey,'
                            ' or EllipticCurvePublicKey.')
        if self._public_key is not None:
            raise ValueError('The public key may only be set once.')
        self._public_key = public_key

    def public_key(self, key):
        """
        Sets the requestor's public key (as found in the signing request).
        """
        clone = self._clone()
        clone._set_public_key(key)
        return clone

    def _set_serial_number(self, serial_number):
        if not isinstance(serial_number, six.integer_types):
            raise TypeError('Serial number must be of integral type.')
        if self._serial_number is not None:
            raise ValueError('The serial number may only be set once.')
        if serial_number < 0:
            raise ValueError('The serial number should be non-negative.')
        if utils.bit_length(serial_number) > 160:  # As defined in RFC 5280
            raise ValueError('The serial number should not be more than '
                             '160 bits.')
        self._serial_number = serial_number

    def serial_number(self, number):
        """
        Sets the certificate serial number.
        """
        clone = self._clone()
        clone._set_serial_number(number)
        return clone

    def _set_not_valid_before(self, not_valid_before):
        if not isinstance(not_valid_before, datetime.datetime):
            raise TypeError('Expecting datetime object.')
        if self._not_valid_before is not None:
            raise ValueError('The not valid before may only be set once.')
        if not_valid_before <= _UNIX_EPOCH:
            raise ValueError('The not valid before date must be after the '
                             'unix epoch (1970 January 1).')
        self._not_valid_before = not_valid_before

    def not_valid_before(self, time):
        """
        Sets the certificate activation time.
        """
        clone = self._clone()
        clone._set_not_valid_before(time)
        return clone

    def _set_not_valid_after(self, not_valid_after):
        if not isinstance(not_valid_after, datetime.datetime):
            raise TypeError('Expecting datetime object.')
        if self._not_valid_after is not None:
            raise ValueError('The not valid after may only be set once.')
        if not_valid_after <= _UNIX_EPOCH:
            raise ValueError('The not valid after date must be after the '
                             'unix epoch (1970 January 1).')
        self._not_valid_after = not_valid_after

    def not_valid_after(self, time):
        """
        Sets the certificate expiration time.
        """
        clone = self._clone()
        clone._set_not_valid_after(time)
        return clone

    def _add_extension(self, extension, critical):
        """
        Adds an X.509 extension to the certificate in-place.
        """
        if not isinstance(extension, ExtensionType):
            raise TypeError("extension must be an ExtensionType")

        extension = Extension(extension.oid, critical, extension)

        # TODO: This is quadratic in the number of extensions
        for e in self._extensions:
            if e.oid == extension.oid:
                raise ValueError('This extension has already been set.')

        self._extensions.append(extension)

    def add_extension(self, extension, critical):
        """
        Adds an X.509 extension to the certificate.
        """
        clone = self._clone()
        clone._add_extension(extension, critical)
        return clone

    def sign(self, private_key, algorithm, backend):
        """
        Signs the certificate using the CA's private key.
        """
        if self._subject_name is None:
            raise ValueError("A certificate must have a subject name")

        if self._issuer_name is None:
            raise ValueError("A certificate must have an issuer name")

        if self._serial_number is None:
            raise ValueError("A certificate must have a serial number")

        if self._not_valid_before is None:
            raise ValueError("A certificate must have a not valid before time")

        if self._not_valid_after is None:
            raise ValueError("A certificate must have a not valid after time")

        if self._public_key is None:
            raise ValueError("A certificate must have a public key")

        return backend.create_x509_certificate(self, private_key, algorithm)
