# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class RSAPrivateKey(object):
    @abc.abstractmethod
    def signer(self, padding, algorithm):
        """
        Returns an AsymmetricSignatureContext used for signing data.
        """

    @abc.abstractmethod
    def decrypt(self, ciphertext, padding):
        """
        Decrypts the provided ciphertext.
        """

    @abc.abstractproperty
    def key_size(self):
        """
        The bit length of the public modulus.
        """

    @abc.abstractmethod
    def public_key(self):
        """
        The RSAPublicKey associated with this private key.
        """


@six.add_metaclass(abc.ABCMeta)
class RSAPrivateKeyWithNumbers(RSAPrivateKey):
    @abc.abstractmethod
    def private_numbers(self):
        """
        Returns an RSAPrivateNumbers.
        """


@six.add_metaclass(abc.ABCMeta)
class RSAPublicKey(object):
    @abc.abstractmethod
    def verifier(self, signature, padding, algorithm):
        """
        Returns an AsymmetricVerificationContext used for verifying signatures.
        """

    @abc.abstractmethod
    def encrypt(self, plaintext, padding):
        """
        Encrypts the given plaintext.
        """

    @abc.abstractproperty
    def key_size(self):
        """
        The bit length of the public modulus.
        """


@six.add_metaclass(abc.ABCMeta)
class RSAPublicKeyWithNumbers(RSAPublicKey):
    @abc.abstractmethod
    def public_numbers(self):
        """
        Returns an RSAPublicNumbers
        """
