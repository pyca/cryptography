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
"""AWS Encryption SDK native data structures for defining implementation-specific characteristics."""
import struct
from enum import Enum

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.kdf import hkdf

from aws_encryption_sdk.exceptions import InvalidAlgorithmError

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Optional  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

__version__ = "1.4.1"
USER_AGENT_SUFFIX = "AwsEncryptionSdkPython/{}".format(__version__)


class EncryptionSuite(Enum):
    """Static definition of encryption algorithm details.

    .. warning:: These members must only be used as part of an AlgorithmSuite.

    :param algorithm: Encryption algorithm to use
    :type algorithm: cryptography.io ciphers algorithm object
    :param mode: Encryption mode in which to operate
    :type mode: cryptography.io ciphers modes object
    :param int data_key_length: Number of bytes in envelope encryption data key
    :param int iv_length: Number of bytes in IV
    :param int auth_length: Number of bytes in auth data (tag)
    :param int auth_key_length: Number of bytes in auth key (not currently supported by any algorithms)
    """

    AES_128_GCM_IV12_TAG16 = (algorithms.AES, modes.GCM, 16, 12, 16)
    AES_192_GCM_IV12_TAG16 = (algorithms.AES, modes.GCM, 24, 12, 16)
    AES_256_GCM_IV12_TAG16 = (algorithms.AES, modes.GCM, 32, 12, 16)

    def __init__(self, algorithm, mode, data_key_length, iv_length, auth_length, auth_key_length=0):
        """Prepare a new EncryptionSuite."""
        self.algorithm = algorithm
        self.mode = mode
        self.data_key_length = data_key_length
        self.iv_length = iv_length
        self.auth_length = self.tag_len = auth_length
        # Auth keys are not currently supported
        self.auth_key_length = auth_key_length

    def valid_kdf(self, kdf):
        """Determine whether a KDFSuite can be used with this EncryptionSuite.

        :param kdf: KDFSuite to evaluate
        :type kdf: aws_encryption_sdk.identifiers.KDFSuite
        :rtype: bool
        """
        if kdf.input_length is None:
            return True

        if self.data_key_length > kdf.input_length(self):
            raise InvalidAlgorithmError(
                "Invalid Algorithm definition: data_key_len must not be greater than kdf_input_len"
            )

        return True


class KDFSuite(Enum):
    """Static definition of key derivation algorithm details.

    .. warning:: These members must only be used as part of an AlgorithmSuite.

    :param algorithm: KDF algorithm to use
    :type algorithm: cryptography.io KDF object
    :param int input_length: Number of bytes of input data to feed into KDF function
    :param hash_algorithm: Hash algorithm to use in KDF
    :type hash_algorithm: cryptography.io hashes object
    """

    NONE = (None, None, None)
    HKDF_SHA256 = (hkdf.HKDF, None, hashes.SHA256)
    HKDF_SHA384 = (hkdf.HKDF, None, hashes.SHA384)

    def __init__(self, algorithm, input_length, hash_algorithm):
        """Prepare a new KDFSuite."""
        self.algorithm = algorithm
        self._input_length = input_length
        self.hash_algorithm = hash_algorithm

    def input_length(self, encryption):
        # type: (EncryptionSuite) -> int
        """Determine the correct KDF input value length for this KDFSuite when used with
        a specific EncryptionSuite.

        :param encryption: EncryptionSuite to use
        :type encryption: aws_encryption_sdk.identifiers.EncryptionSuite
        :rtype: int
        """
        if self._input_length is None:
            return encryption.data_key_length

        return self._input_length


class AuthenticationSuite(Enum):
    """Static definition of authentication algorithm details.

    .. warning:: These members must only be used as part of an AlgorithmSuite.

    :param algorithm: Information needed by signing algorithm to define behavior
    :type algorithm: may vary (currently only ECC curve object)
    :param hash_algorithm: Hash algorithm to use in signature
    :type hash_algorithm: cryptography.io hashes object
    :param int signature_lenth: Number of bytes in signature
    """

    NONE = (None, None, 0)
    SHA256_ECDSA_P256 = (ec.SECP256R1, hashes.SHA256, 71)
    SHA256_ECDSA_P384 = (ec.SECP384R1, hashes.SHA384, 103)

    def __init__(self, algorithm, hash_algorithm, signature_length):
        """Prepare a new AuthenticationSuite."""
        self.algorithm = algorithm
        self.hash_algorithm = hash_algorithm
        self.signature_length = signature_length


class AlgorithmSuite(Enum):  # pylint: disable=too-many-instance-attributes
    """Static combinations of encryption, KDF, and authentication algorithms.

    .. warning:: No AlgorithmSuites except those defined here are supported.

    :param int algorithm_id: KMS Encryption Algorithm ID
    :param encryption_suite: EncryptionSuite to use with this AlgorithmSuite
    :type encryption_suite: aws_encryption_sdk.identifiers.EncryptionSuite
    :param kdf_suite: KDFSuite to use with this AlgorithmSuite
    :type kdf_suite: aws_encryption_sdk.identifiers.KDFSuite
    :param authentication_suite: AuthenticationSuite to use with this AlgorithmSuite
    :type authentication_suite: aws_encryption_sdk.identifiers.AuthenticationSuite
    """

    __rlookup__ = {}  # algorithm_id -> AlgorithmSuite

    AES_128_GCM_IV12_TAG16 = (0x0014, EncryptionSuite.AES_128_GCM_IV12_TAG16)
    AES_192_GCM_IV12_TAG16 = (0x0046, EncryptionSuite.AES_192_GCM_IV12_TAG16)
    AES_256_GCM_IV12_TAG16 = (0x0078, EncryptionSuite.AES_256_GCM_IV12_TAG16)
    AES_128_GCM_IV12_TAG16_HKDF_SHA256 = (0x0114, EncryptionSuite.AES_128_GCM_IV12_TAG16, KDFSuite.HKDF_SHA256)
    AES_192_GCM_IV12_TAG16_HKDF_SHA256 = (0x0146, EncryptionSuite.AES_192_GCM_IV12_TAG16, KDFSuite.HKDF_SHA256)
    AES_256_GCM_IV12_TAG16_HKDF_SHA256 = (0x0178, EncryptionSuite.AES_256_GCM_IV12_TAG16, KDFSuite.HKDF_SHA256)
    AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 = (
        0x0214,
        EncryptionSuite.AES_128_GCM_IV12_TAG16,
        KDFSuite.HKDF_SHA256,
        AuthenticationSuite.SHA256_ECDSA_P256,
    )
    AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 = (
        0x0346,
        EncryptionSuite.AES_192_GCM_IV12_TAG16,
        KDFSuite.HKDF_SHA384,
        AuthenticationSuite.SHA256_ECDSA_P384,
    )
    AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 = (
        0x0378,
        EncryptionSuite.AES_256_GCM_IV12_TAG16,
        KDFSuite.HKDF_SHA384,
        AuthenticationSuite.SHA256_ECDSA_P384,
    )

    def __init__(
        self,
        algorithm_id,  # type: int
        encryption,  # type: EncryptionSuite
        kdf=KDFSuite.NONE,  # type: Optional[KDFSuite]
        authentication=AuthenticationSuite.NONE,  # type: Optional[AuthenticationSuite]
        allowed=True,  # type: bool
    ):
        # type: (...) -> None
        """Prepare a new AlgorithmSuite."""
        self.algorithm_id = algorithm_id
        self.encryption = encryption
        self.encryption.valid_kdf(kdf)
        self.kdf = kdf
        self.authentication = authentication
        self.allowed = allowed

        # Encryption Values
        self.encryption_algorithm = self.encryption.algorithm
        self.encryption_mode = self.encryption.mode
        self.data_key_len = self.encryption.data_key_length
        self.iv_len = self.encryption.iv_length
        self.auth_key_len = self.encryption.auth_key_length
        self.auth_len = self.tag_len = self.encryption.auth_length

        # KDF Values
        self.kdf_type = self.kdf.algorithm
        self.kdf_hash_type = self.kdf.hash_algorithm

        # Authentication Values
        self.signing_algorithm_info = self.authentication.algorithm
        self.signing_hash_type = self.authentication.hash_algorithm
        self.signature_len = self.authentication.signature_length

        self.__rlookup__[algorithm_id] = self

    @property
    def kdf_input_len(self):
        """Determine the correct KDF input value length for this algorithm suite."""
        return self.kdf.input_length(self.encryption)

    @classmethod
    def get_by_id(cls, algorithm_id):
        """Return the correct member based on the algorithm_id value.

        :param algorithm_id: Value of algorithm_id field with which to retrieve Algorithm
        :type algorithm_id: int
        :returns: Algorithm with ID algorithm_id
        :rtype: aws_encryption_sdk.identifiers.Algorithm
        """
        return cls.__rlookup__[algorithm_id]

    def id_as_bytes(self):
        """Return the algorithm suite ID as a 2-byte array"""
        return struct.pack(">H", self.algorithm_id)

    def safe_to_cache(self):
        """Determine whether encryption materials for this algorithm suite should be cached."""
        return self.kdf is not KDFSuite.NONE


Algorithm = AlgorithmSuite


class EncryptionType(Enum):
    """Identifies symmetric vs asymmetric encryption.  Used to identify encryption type for WrappingAlgorithm."""

    SYMMETRIC = 0
    ASYMMETRIC = 1


class EncryptionKeyType(Enum):
    """Identifies raw encryption key type.  Used to identify key capabilities for WrappingAlgorithm."""

    SYMMETRIC = 0
    PUBLIC = 1
    PRIVATE = 2


class WrappingAlgorithm(Enum):
    """Wrapping Algorithms for use by RawMasterKey objects.

    :param algorithm: Encryption algorithm to use for encryption of data keys
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param padding_type: Padding type to use for encryption of data keys
    :type padding_type:
    :param padding_algorithm: Padding algorithm to use for encryption of data keys
    :type padding_algorithm:
    :param padding_mgf: Padding MGF to use for encryption of data keys
    :type padding_mgf:
    """

    AES_128_GCM_IV12_TAG16_NO_PADDING = (EncryptionType.SYMMETRIC, Algorithm.AES_128_GCM_IV12_TAG16, None, None, None)
    AES_192_GCM_IV12_TAG16_NO_PADDING = (EncryptionType.SYMMETRIC, Algorithm.AES_192_GCM_IV12_TAG16, None, None, None)
    AES_256_GCM_IV12_TAG16_NO_PADDING = (EncryptionType.SYMMETRIC, Algorithm.AES_256_GCM_IV12_TAG16, None, None, None)
    RSA_PKCS1 = (EncryptionType.ASYMMETRIC, rsa, padding.PKCS1v15, None, None)
    RSA_OAEP_SHA1_MGF1 = (EncryptionType.ASYMMETRIC, rsa, padding.OAEP, hashes.SHA1, padding.MGF1)
    RSA_OAEP_SHA256_MGF1 = (EncryptionType.ASYMMETRIC, rsa, padding.OAEP, hashes.SHA256, padding.MGF1)
    RSA_OAEP_SHA384_MGF1 = (EncryptionType.ASYMMETRIC, rsa, padding.OAEP, hashes.SHA384, padding.MGF1)
    RSA_OAEP_SHA512_MGF1 = (EncryptionType.ASYMMETRIC, rsa, padding.OAEP, hashes.SHA512, padding.MGF1)

    def __init__(self, encryption_type, algorithm, padding_type, padding_algorithm, padding_mgf):
        """Prepares new WrappingAlgorithm."""
        self.encryption_type = encryption_type
        self.algorithm = algorithm
        if padding_type == padding.OAEP:
            padding_args = {
                "mgf": padding_mgf(algorithm=padding_algorithm()),
                "algorithm": padding_algorithm(),
                "label": None,
            }
        else:
            padding_args = {}
        if padding_type is not None:
            padding_type = padding_type(**padding_args)
        self.padding = padding_type


class ObjectType(Enum):
    """Valid Type values per the AWS Encryption SDK message format."""

    CUSTOMER_AE_DATA = 128


class SequenceIdentifier(Enum):
    """Identifiers for specific sequence frames."""

    SEQUENCE_NUMBER_END = 0xFFFFFFFF


class SerializationVersion(Enum):
    """Valid Versions of AWS Encryption SDK message format."""

    V1 = 1  # pylint: disable=invalid-name


class ContentType(Enum):
    """Type of content framing contained in message."""

    NO_FRAMING = 1
    FRAMED_DATA = 2


class ContentAADString(Enum):
    """Body Additional Authenticated Data values for building the AAD for a message body."""

    FRAME_STRING_ID = b"AWSKMSEncryptionClient Frame"
    FINAL_FRAME_STRING_ID = b"AWSKMSEncryptionClient Final Frame"
    NON_FRAMED_STRING_ID = b"AWSKMSEncryptionClient Single Block"
