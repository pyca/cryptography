# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Contains authentication primitives."""
import base64
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.utils import InterfaceNotImplemented, verify_interface

from ...exceptions import NotSupportedError
from .elliptic_curve import (
    _ecc_encode_compressed_point,
    _ecc_public_numbers_from_compressed_point,
    _ecc_static_length_signature,
)

_LOGGER = logging.getLogger(__name__)


class _PrehashingAuthenticator(object):
    """Parent class for Signer/Verifier. Provides common behavior and interface.

    :param algorithm: Algorithm on which to base authenticator
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param key: Key with which to build authenticator
    """

    def __init__(self, algorithm, key):
        """Prepares initial values."""
        self.algorithm = algorithm
        self._signature_type = self._set_signature_type()
        self.key = key
        self._hasher = self._build_hasher()

    def _set_signature_type(self):
        """Ensures that the algorithm signature type is a known type and sets a reference value."""
        try:
            verify_interface(ec.EllipticCurve, self.algorithm.signing_algorithm_info)
            return ec.EllipticCurve
        except InterfaceNotImplemented:
            raise NotSupportedError("Unsupported signing algorithm info")

    def _build_hasher(self):
        """Builds the hasher instance which will calculate the digest of all passed data.

        :returns: Hasher object
        """
        return hashes.Hash(self.algorithm.signing_hash_type(), backend=default_backend())


class Signer(_PrehashingAuthenticator):
    """Abstract signing handler.

    :param algorithm: Algorithm on which to base signer
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param key: Private key from which a signer can be generated
    :type key: currently only Elliptic Curve Private Keys are supported
    """

    @classmethod
    def from_key_bytes(cls, algorithm, key_bytes):
        """Builds a `Signer` from an algorithm suite and a raw signing key.

        :param algorithm: Algorithm on which to base signer
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param bytes key_bytes: Raw signing key
        :rtype: aws_encryption_sdk.internal.crypto.Signer
        """
        key = serialization.load_der_private_key(data=key_bytes, password=None, backend=default_backend())
        return cls(algorithm, key)

    def key_bytes(self):
        """Returns the raw signing key.

        :rtype: bytes
        """
        return self.key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def encoded_public_key(self):
        """Returns the encoded public key.

        .. note::
            For ECC curves, this will return the encoded compressed public point.

        :returns: Encoded public key from signer
        :rtype: bytes
        """
        return base64.b64encode(_ecc_encode_compressed_point(self.key))

    def update(self, data):
        """Updates the cryptographic signer with the supplied data.

        :param bytes data: Data to be signed
        """
        self._hasher.update(data)

    def finalize(self):
        """Finalizes the signer and returns the signature.

        :returns: Calculated signer signature
        :rtype: bytes
        """
        prehashed_digest = self._hasher.finalize()
        return _ecc_static_length_signature(key=self.key, algorithm=self.algorithm, digest=prehashed_digest)


class Verifier(_PrehashingAuthenticator):
    """Abstract signature verification handler.

    .. note::
        For ECC curves, the signature must be DER encoded as specified in RFC 3279.

    :param algorithm: Algorithm on which to base verifier
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param public_key: Appropriate public key object for algorithm
    :type public_key: may vary
    """

    @classmethod
    def from_encoded_point(cls, algorithm, encoded_point):
        """Creates a Verifier object based on the supplied algorithm and encoded compressed ECC curve point.

        :param algorithm: Algorithm on which to base verifier
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param bytes encoded_point: ECC public point compressed and encoded with _ecc_encode_compressed_point
        :returns: Instance of Verifier generated from encoded point
        :rtype: aws_encryption_sdk.internal.crypto.Verifier
        """
        return cls(
            algorithm=algorithm,
            key=_ecc_public_numbers_from_compressed_point(
                curve=algorithm.signing_algorithm_info(), compressed_point=base64.b64decode(encoded_point)
            ).public_key(default_backend()),
        )

    @classmethod
    def from_key_bytes(cls, algorithm, key_bytes):
        """Creates a `Verifier` object based on the supplied algorithm and raw verification key.

        :param algorithm: Algorithm on which to base verifier
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param bytes encoded_point: Raw verification key
        :returns: Instance of Verifier generated from encoded point
        :rtype: aws_encryption_sdk.internal.crypto.Verifier
        """
        return cls(
            algorithm=algorithm, key=serialization.load_der_public_key(data=key_bytes, backend=default_backend())
        )

    def key_bytes(self):
        """Returns the raw verification key.

        :rtype: bytes
        """
        return self.key.public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def update(self, data):
        """Updates the cryptographic verifier with the supplied data.

        :param bytes data: Data to verify using the signature
        """
        self._hasher.update(data)

    def verify(self, signature):
        """Verifies the signature against the current cryptographic verifier state.

        :param bytes signature: The signature to verify
        """
        prehashed_digest = self._hasher.finalize()
        self.key.verify(
            signature=signature,
            data=prehashed_digest,
            signature_algorithm=ec.ECDSA(Prehashed(self.algorithm.signing_hash_type())),
        )
