# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class CipherBackend(object):
    @abc.abstractmethod
    def cipher_supported(self, cipher, mode):
        """
        Return True if the given cipher and mode are supported.
        """

    @abc.abstractmethod
    def create_symmetric_encryption_ctx(self, cipher, mode):
        """
        Get a CipherContext that can be used for encryption.
        """

    @abc.abstractmethod
    def create_symmetric_decryption_ctx(self, cipher, mode):
        """
        Get a CipherContext that can be used for decryption.
        """


@six.add_metaclass(abc.ABCMeta)
class HashBackend(object):
    @abc.abstractmethod
    def hash_supported(self, algorithm):
        """
        Return True if the hash algorithm is supported by this backend.
        """

    @abc.abstractmethod
    def create_hash_ctx(self, algorithm):
        """
        Create a HashContext for calculating a message digest.
        """


@six.add_metaclass(abc.ABCMeta)
class HMACBackend(object):
    @abc.abstractmethod
    def hmac_supported(self, algorithm):
        """
        Return True if the hash algorithm is supported for HMAC by this
        backend.
        """

    @abc.abstractmethod
    def create_hmac_ctx(self, key, algorithm):
        """
        Create a HashContext for calculating a message authentication code.
        """


@six.add_metaclass(abc.ABCMeta)
class PBKDF2HMACBackend(object):
    @abc.abstractmethod
    def pbkdf2_hmac_supported(self, algorithm):
        """
        Return True if the hash algorithm is supported for PBKDF2 by this
        backend.
        """

    @abc.abstractmethod
    def derive_pbkdf2_hmac(self, algorithm, length, salt, iterations,
                           key_material):
        """
        Return length bytes derived from provided PBKDF2 parameters.
        """


@six.add_metaclass(abc.ABCMeta)
class RSABackend(object):
    @abc.abstractmethod
    def generate_rsa_private_key(self, public_exponent, key_size):
        """
        Generate an RSAPrivateKey instance with public_exponent and a modulus
        of key_size bits.
        """

    @abc.abstractmethod
    def create_rsa_signature_ctx(self, private_key, padding, algorithm):
        """
        Returns an object conforming to the AsymmetricSignatureContext
        interface.
        """

    @abc.abstractmethod
    def create_rsa_verification_ctx(self, public_key, signature, padding,
                                    algorithm):
        """
        Returns an object conforming to the AsymmetricVerificationContext
        interface.
        """

    @abc.abstractmethod
    def mgf1_hash_supported(self, algorithm):
        """
        Return True if the hash algorithm is supported for MGF1 in PSS.
        """

    @abc.abstractmethod
    def decrypt_rsa(self, private_key, ciphertext, padding):
        """
        Returns decrypted bytes.
        """

    @abc.abstractmethod
    def encrypt_rsa(self, public_key, plaintext, padding):
        """
        Returns encrypted bytes.
        """

    @abc.abstractmethod
    def rsa_padding_supported(self, padding):
        """
        Returns True if the backend supports the given padding options.
        """

    @abc.abstractmethod
    def generate_rsa_parameters_supported(self, public_exponent, key_size):
        """
        Returns True if the backend supports the given parameters for key
        generation.
        """

    @abc.abstractmethod
    def load_rsa_private_numbers(self, numbers):
        """
        Returns an RSAPrivateKey provider.
        """

    @abc.abstractmethod
    def load_rsa_public_numbers(self, numbers):
        """
        Returns an RSAPublicKey provider.
        """


@six.add_metaclass(abc.ABCMeta)
class DSABackend(object):
    @abc.abstractmethod
    def generate_dsa_parameters(self, key_size):
        """
        Generate a DSAParameters instance with a modulus of key_size bits.
        """

    @abc.abstractmethod
    def generate_dsa_private_key(self, parameters):
        """
        Generate an DSAPrivateKey instance with parameters as
        a DSAParameters object.
        """

    @abc.abstractmethod
    def create_dsa_signature_ctx(self, private_key, algorithm):
        """
        Returns an object conforming to the AsymmetricSignatureContext
        interface.
        """

    @abc.abstractmethod
    def create_dsa_verification_ctx(self, public_key, signature, algorithm):
        """
        Returns an object conforming to the AsymmetricVerificationContext
        interface.
        """

    @abc.abstractmethod
    def dsa_hash_supported(self, algorithm):
        """
        Return True if the hash algorithm is supported by the backend for DSA.
        """

    @abc.abstractmethod
    def dsa_parameters_supported(self, p, q, g):
        """
        Return True if the parameters are supported by the backend for DSA.
        """

    @abc.abstractmethod
    def load_dsa_private_numbers(self, numbers):
        """
        Returns a DSAPrivateKey provider.
        """

    @abc.abstractmethod
    def load_dsa_public_numbers(self, numbers):
        """
        Returns a DSAPublicKey provider.
        """

    @abc.abstractmethod
    def load_dsa_parameter_numbers(self, numbers):
        """
        Returns a DSAParameters provider.
        """


@six.add_metaclass(abc.ABCMeta)
class TraditionalOpenSSLSerializationBackend(object):
    @abc.abstractmethod
    def load_traditional_openssl_pem_private_key(self, data, password):
        """
        Load a private key from PEM encoded data, using password if the data
        is encrypted.
        """


@six.add_metaclass(abc.ABCMeta)
class PKCS8SerializationBackend(object):
    @abc.abstractmethod
    def load_pkcs8_pem_private_key(self, data, password):
        """
        Load a private key from PEM encoded data, using password if the data
        is encrypted.
        """


@six.add_metaclass(abc.ABCMeta)
class CMACBackend(object):
    @abc.abstractmethod
    def cmac_algorithm_supported(self, algorithm):
        """
        Returns True if the block cipher is supported for CMAC by this backend
        """

    @abc.abstractmethod
    def create_cmac_ctx(self, algorithm):
        """
        Create a CMACContext for calculating a message authentication code.
        """


@six.add_metaclass(abc.ABCMeta)
class EllipticCurveBackend(object):
    @abc.abstractmethod
    def elliptic_curve_signature_algorithm_supported(
        self, signature_algorithm, curve
    ):
        """
        Returns True if the backend supports the named elliptic curve with the
        specified signature algorithm.
        """

    @abc.abstractmethod
    def elliptic_curve_supported(self, curve):
        """
        Returns True if the backend supports the named elliptic curve.
        """

    @abc.abstractmethod
    def generate_elliptic_curve_private_key(self, curve):
        """
        Return an object conforming to the EllipticCurvePrivateKey interface.
        """

    @abc.abstractmethod
    def elliptic_curve_public_key_from_numbers(self, numbers):
        """
        Return an EllipticCurvePublicKey provider using the given numbers.
        """

    @abc.abstractmethod
    def elliptic_curve_private_key_from_numbers(self, numbers):
        """
        Return an EllipticCurvePublicKey provider using the given numbers.
        """
