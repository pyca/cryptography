# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class DSAParameters(object):
    @abc.abstractmethod
    def generate_private_key(self):
        """
        Generates and returns a DSAPrivateKey.
        """


@six.add_metaclass(abc.ABCMeta)
class DSAParametersWithNumbers(DSAParameters):
    @abc.abstractmethod
    def parameter_numbers(self):
        """
        Returns a DSAParameterNumbers.
        """


@six.add_metaclass(abc.ABCMeta)
class DSAPrivateKey(object):
    @abc.abstractproperty
    def key_size(self):
        """
        The bit length of the prime modulus.
        """

    @abc.abstractmethod
    def public_key(self):
        """
        The DSAPublicKey associated with this private key.
        """

    @abc.abstractmethod
    def parameters(self):
        """
        The DSAParameters object associated with this private key.
        """

    @abc.abstractmethod
    def signer(self, signature_algorithm):
        """
        Returns an AsymmetricSignatureContext used for signing data.
        """


@six.add_metaclass(abc.ABCMeta)
class DSAPrivateKeyWithNumbers(DSAPrivateKey):
    @abc.abstractmethod
    def private_numbers(self):
        """
        Returns a DSAPrivateNumbers.
        """


@six.add_metaclass(abc.ABCMeta)
class DSAPublicKey(object):
    @abc.abstractproperty
    def key_size(self):
        """
        The bit length of the prime modulus.
        """

    @abc.abstractmethod
    def parameters(self):
        """
        The DSAParameters object associated with this public key.
        """

    @abc.abstractmethod
    def verifier(self, signature, signature_algorithm):
        """
        Returns an AsymmetricVerificationContext used for signing data.
        """


@six.add_metaclass(abc.ABCMeta)
class DSAPublicKeyWithNumbers(DSAPublicKey):
    @abc.abstractmethod
    def public_numbers(self):
        """
        Returns a DSAPublicNumbers.
        """
