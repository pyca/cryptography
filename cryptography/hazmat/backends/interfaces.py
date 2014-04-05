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


class CipherBackend(six.with_metaclass(abc.ABCMeta)):
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


class HashBackend(six.with_metaclass(abc.ABCMeta)):
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


class HMACBackend(six.with_metaclass(abc.ABCMeta)):
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


class PBKDF2HMACBackend(six.with_metaclass(abc.ABCMeta)):
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


class RSABackend(six.with_metaclass(abc.ABCMeta)):
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


class DSABackend(six.with_metaclass(abc.ABCMeta)):
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


class OpenSSLSerializationBackend(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractmethod
    def load_openssl_pem_private_key(self, data, password):
        """
        Load a private key from PEM encoded data, using password if the data
        is encrypted.
        """
