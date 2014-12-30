# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class CipherAlgorithm(object):
    @abc.abstractproperty
    def name(self):
        """
        A string naming this mode (e.g. "AES", "Camellia").
        """

    @abc.abstractproperty
    def key_size(self):
        """
        The size of the key being used as an integer in bits (e.g. 128, 256).
        """


@six.add_metaclass(abc.ABCMeta)
class BlockCipherAlgorithm(object):
    @abc.abstractproperty
    def block_size(self):
        """
        The size of a block as an integer in bits (e.g. 64, 128).
        """


@six.add_metaclass(abc.ABCMeta)
class Mode(object):
    @abc.abstractproperty
    def name(self):
        """
        A string naming this mode (e.g. "ECB", "CBC").
        """

    @abc.abstractmethod
    def validate_for_algorithm(self, algorithm):
        """
        Checks that all the necessary invariants of this (mode, algorithm)
        combination are met.
        """


@six.add_metaclass(abc.ABCMeta)
class ModeWithInitializationVector(object):
    @abc.abstractproperty
    def initialization_vector(self):
        """
        The value of the initialization vector for this mode as bytes.
        """


@six.add_metaclass(abc.ABCMeta)
class ModeWithNonce(object):
    @abc.abstractproperty
    def nonce(self):
        """
        The value of the nonce for this mode as bytes.
        """
