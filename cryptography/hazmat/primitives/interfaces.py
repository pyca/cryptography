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


class CipherAlgorithm(six.with_metaclass(abc.ABCMeta)):
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


class BlockCipherAlgorithm(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractproperty
    def block_size(self):
        """
        The size of a block as an integer in bits (e.g. 64, 128).
        """


class Mode(six.with_metaclass(abc.ABCMeta)):
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


class ModeWithInitializationVector(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractproperty
    def initialization_vector(self):
        """
        The value of the initialization vector for this mode as bytes.
        """


class ModeWithNonce(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractproperty
    def nonce(self):
        """
        The value of the nonce for this mode as bytes.
        """


class ModeWithAuthenticationTag(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractproperty
    def tag(self):
        """
        The value of the tag supplied to the constructor of this mode.
        """


class CipherContext(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractmethod
    def update(self, data):
        """
        Processes the provided bytes through the cipher and returns the results
        as bytes.
        """

    @abc.abstractmethod
    def finalize(self):
        """
        Returns the results of processing the final block as bytes.
        """


class AEADCipherContext(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractmethod
    def authenticate_additional_data(self, data):
        """
        Authenticates the provided bytes.
        """


class AEADEncryptionContext(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractproperty
    def tag(self):
        """
        Returns tag bytes. This is only available after encryption is
        finalized.
        """


class PaddingContext(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractmethod
    def update(self, data):
        """
        Pads the provided bytes and returns any available data as bytes.
        """

    @abc.abstractmethod
    def finalize(self):
        """
        Finalize the padding, returns bytes.
        """


class HashAlgorithm(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractproperty
    def name(self):
        """
        A string naming this algorithm (e.g. "sha256", "md5").
        """

    @abc.abstractproperty
    def digest_size(self):
        """
        The size of the resulting digest in bytes.
        """

    @abc.abstractproperty
    def block_size(self):
        """
        The internal block size of the hash algorithm in bytes.
        """


class HashContext(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractproperty
    def algorithm(self):
        """
        A HashAlgorithm that will be used by this context.
        """

    @abc.abstractmethod
    def update(self, data):
        """
        Processes the provided bytes through the hash.
        """

    @abc.abstractmethod
    def finalize(self):
        """
        Finalizes the hash context and returns the hash digest as bytes.
        """

    @abc.abstractmethod
    def copy(self):
        """
        Return a HashContext that is a copy of the current context.
        """
