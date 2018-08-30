# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc

import six

from cryptography.hazmat.primitives import hashes
from cryptography.x509 import Certificate


_OIDS_TO_HASH = {
    "1.3.14.3.2.26": hashes.SHA1(),
    "2.16.840.1.101.3.4.2.4": hashes.SHA224(),
    "2.16.840.1.101.3.4.2.1": hashes.SHA256(),
    "2.16.840.1.101.3.4.2.2": hashes.SHA384(),
    "2.16.840.1.101.3.4.2.3": hashes.SHA512(),
}


def load_der_ocsp_request(data):
    from cryptography.hazmat.backends.openssl.backend import backend
    return backend.load_der_ocsp_request(data)


class OCSPRequestBuilder(object):
    def __init__(self, request=None):
        self._request = request

    def add_certificate(self, cert, issuer, algorithm):
        if self._request is not None:
            raise ValueError("Only one certificate can be added to a request")

        allowed_hashes = (
            hashes.SHA1, hashes.SHA224, hashes.SHA256,
            hashes.SHA384, hashes.SHA512
        )
        if not isinstance(algorithm, allowed_hashes):
            raise ValueError(
                "Algorithm must be SHA1, SHA224, SHA256, SHA384, or SHA512"
            )
        if (
            not isinstance(cert, Certificate) or
            not isinstance(issuer, Certificate)
        ):
            raise TypeError("cert and issuer must be a Certificate")

        return OCSPRequestBuilder((cert, issuer, algorithm))

    def build(self):
        from cryptography.hazmat.backends.openssl.backend import backend
        if self._request is None:
            raise ValueError("You must add a certificate before building")

        return backend.create_ocsp_request(self)


@six.add_metaclass(abc.ABCMeta)
class OCSPRequest(object):
    @abc.abstractproperty
    def issuer_key_hash(self):
        """
        The hash of the issuer public key
        """

    @abc.abstractproperty
    def issuer_name_hash(self):
        """
        The hash of the issuer name
        """

    @abc.abstractproperty
    def hash_algorithm(self):
        """
        The hash algorithm used in the issuer name and key hashes
        """

    @abc.abstractproperty
    def serial_number(self):
        """
        The serial number of the cert whose status is being checked
        """
    @abc.abstractmethod
    def public_bytes(self, encoding):
        """
        Serializes the request to DER
        """
