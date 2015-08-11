# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc
import datetime
import ipaddress
from enum import Enum

import six

from cryptography import utils
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.general_name import GeneralName, IPAddress, OtherName
from cryptography.x509.name import Name
from cryptography.x509.oid import (
    ExtensionOID, ObjectIdentifier
)


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

    def __eq__(self, other):
        if not isinstance(other, Extension):
            return NotImplemented

        return (
            self.oid == other.oid and
            self.critical == other.critical and
            self.value == other.value
        )

    def __ne__(self, other):
        return not self == other


@six.add_metaclass(abc.ABCMeta)
class ExtensionType(object):
    @abc.abstractproperty
    def oid(self):
        """
        Returns the oid associated with the given extension type.
        """


@utils.register_interface(ExtensionType)
class KeyUsage(object):
    oid = ExtensionOID.KEY_USAGE

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


@utils.register_interface(ExtensionType)
class NameConstraints(object):
    oid = ExtensionOID.NAME_CONSTRAINTS

    def __init__(self, permitted_subtrees, excluded_subtrees):
        if permitted_subtrees is not None:
            if not all(
                isinstance(x, GeneralName) for x in permitted_subtrees
            ):
                raise TypeError(
                    "permitted_subtrees must be a list of GeneralName objects "
                    "or None"
                )

            self._validate_ip_name(permitted_subtrees)

        if excluded_subtrees is not None:
            if not all(
                isinstance(x, GeneralName) for x in excluded_subtrees
            ):
                raise TypeError(
                    "excluded_subtrees must be a list of GeneralName objects "
                    "or None"
                )

            self._validate_ip_name(excluded_subtrees)

        if permitted_subtrees is None and excluded_subtrees is None:
            raise ValueError(
                "At least one of permitted_subtrees and excluded_subtrees "
                "must not be None"
            )

        self._permitted_subtrees = permitted_subtrees
        self._excluded_subtrees = excluded_subtrees

    def __eq__(self, other):
        if not isinstance(other, NameConstraints):
            return NotImplemented

        return (
            self.excluded_subtrees == other.excluded_subtrees and
            self.permitted_subtrees == other.permitted_subtrees
        )

    def __ne__(self, other):
        return not self == other

    def _validate_ip_name(self, tree):
        if any(isinstance(name, IPAddress) and not isinstance(
            name.value, (ipaddress.IPv4Network, ipaddress.IPv6Network)
        ) for name in tree):
            raise TypeError(
                "IPAddress name constraints must be an IPv4Network or"
                " IPv6Network object"
            )

    def __repr__(self):
        return (
            u"<NameConstraints(permitted_subtrees={0.permitted_subtrees}, "
            u"excluded_subtrees={0.excluded_subtrees})>".format(self)
        )

    permitted_subtrees = utils.read_only_property("_permitted_subtrees")
    excluded_subtrees = utils.read_only_property("_excluded_subtrees")


class GeneralNames(object):
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
        # Return the value of each GeneralName, except for OtherName instances
        # which we return directly because it has two important properties not
        # just one value.
        objs = (i for i in self if isinstance(i, type))
        if type != OtherName:
            objs = (i.value for i in objs)
        return list(objs)

    def __repr__(self):
        return "<GeneralNames({0})>".format(self._general_names)

    def __eq__(self, other):
        if not isinstance(other, GeneralNames):
            return NotImplemented

        return self._general_names == other._general_names

    def __ne__(self, other):
        return not self == other


@utils.register_interface(ExtensionType)
class SubjectAlternativeName(object):
    oid = ExtensionOID.SUBJECT_ALTERNATIVE_NAME

    def __init__(self, general_names):
        self._general_names = GeneralNames(general_names)

    def __iter__(self):
        return iter(self._general_names)

    def __len__(self):
        return len(self._general_names)

    def get_values_for_type(self, type):
        return self._general_names.get_values_for_type(type)

    def __repr__(self):
        return "<SubjectAlternativeName({0})>".format(self._general_names)

    def __eq__(self, other):
        if not isinstance(other, SubjectAlternativeName):
            return NotImplemented

        return self._general_names == other._general_names

    def __ne__(self, other):
        return not self == other


@utils.register_interface(ExtensionType)
class IssuerAlternativeName(object):
    oid = ExtensionOID.ISSUER_ALTERNATIVE_NAME

    def __init__(self, general_names):
        self._general_names = GeneralNames(general_names)

    def __iter__(self):
        return iter(self._general_names)

    def __len__(self):
        return len(self._general_names)

    def get_values_for_type(self, type):
        return self._general_names.get_values_for_type(type)

    def __repr__(self):
        return "<IssuerAlternativeName({0})>".format(self._general_names)

    def __eq__(self, other):
        if not isinstance(other, IssuerAlternativeName):
            return NotImplemented

        return self._general_names == other._general_names

    def __ne__(self, other):
        return not self == other


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
                 public_key=None, serial_number=None, not_valid_before=None,
                 not_valid_after=None, extensions=[]):
        self._version = Version.v3
        self._issuer_name = issuer_name
        self._subject_name = subject_name
        self._public_key = public_key
        self._serial_number = serial_number
        self._not_valid_before = not_valid_before
        self._not_valid_after = not_valid_after
        self._extensions = extensions

    def issuer_name(self, name):
        """
        Sets the CA's distinguished name.
        """
        if not isinstance(name, Name):
            raise TypeError('Expecting x509.Name object.')
        if self._issuer_name is not None:
            raise ValueError('The issuer name may only be set once.')
        return CertificateBuilder(
            name, self._subject_name, self._public_key,
            self._serial_number, self._not_valid_before,
            self._not_valid_after, self._extensions
        )

    def subject_name(self, name):
        """
        Sets the requestor's distinguished name.
        """
        if not isinstance(name, Name):
            raise TypeError('Expecting x509.Name object.')
        if self._subject_name is not None:
            raise ValueError('The subject name may only be set once.')
        return CertificateBuilder(
            self._issuer_name, name, self._public_key,
            self._serial_number, self._not_valid_before,
            self._not_valid_after, self._extensions
        )

    def public_key(self, key):
        """
        Sets the requestor's public key (as found in the signing request).
        """
        if not isinstance(key, (dsa.DSAPublicKey, rsa.RSAPublicKey,
                                ec.EllipticCurvePublicKey)):
            raise TypeError('Expecting one of DSAPublicKey, RSAPublicKey,'
                            ' or EllipticCurvePublicKey.')
        if self._public_key is not None:
            raise ValueError('The public key may only be set once.')
        return CertificateBuilder(
            self._issuer_name, self._subject_name, key,
            self._serial_number, self._not_valid_before,
            self._not_valid_after, self._extensions
        )

    def serial_number(self, number):
        """
        Sets the certificate serial number.
        """
        if not isinstance(number, six.integer_types):
            raise TypeError('Serial number must be of integral type.')
        if self._serial_number is not None:
            raise ValueError('The serial number may only be set once.')
        if number < 0:
            raise ValueError('The serial number should be non-negative.')
        if utils.bit_length(number) > 160:  # As defined in RFC 5280
            raise ValueError('The serial number should not be more than 160 '
                             'bits.')
        return CertificateBuilder(
            self._issuer_name, self._subject_name,
            self._public_key, number, self._not_valid_before,
            self._not_valid_after, self._extensions
        )

    def not_valid_before(self, time):
        """
        Sets the certificate activation time.
        """
        if not isinstance(time, datetime.datetime):
            raise TypeError('Expecting datetime object.')
        if self._not_valid_before is not None:
            raise ValueError('The not valid before may only be set once.')
        if time <= _UNIX_EPOCH:
            raise ValueError('The not valid before date must be after the unix'
                             ' epoch (1970 January 1).')
        return CertificateBuilder(
            self._issuer_name, self._subject_name,
            self._public_key, self._serial_number, time,
            self._not_valid_after, self._extensions
        )

    def not_valid_after(self, time):
        """
        Sets the certificate expiration time.
        """
        if not isinstance(time, datetime.datetime):
            raise TypeError('Expecting datetime object.')
        if self._not_valid_after is not None:
            raise ValueError('The not valid after may only be set once.')
        if time <= _UNIX_EPOCH:
            raise ValueError('The not valid after date must be after the unix'
                             ' epoch (1970 January 1).')
        return CertificateBuilder(
            self._issuer_name, self._subject_name,
            self._public_key, self._serial_number, self._not_valid_before,
            time, self._extensions
        )

    def add_extension(self, extension, critical):
        """
        Adds an X.509 extension to the certificate.
        """
        if not isinstance(extension, ExtensionType):
            raise TypeError("extension must be an ExtensionType")

        extension = Extension(extension.oid, critical, extension)

        # TODO: This is quadratic in the number of extensions
        for e in self._extensions:
            if e.oid == extension.oid:
                raise ValueError('This extension has already been set.')

        return CertificateBuilder(
            self._issuer_name, self._subject_name,
            self._public_key, self._serial_number, self._not_valid_before,
            self._not_valid_after, self._extensions + [extension]
        )

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
