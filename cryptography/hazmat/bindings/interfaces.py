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


class CiphersProviderBackend(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractproperty
    def ciphers(self):
        """
        An instance of CiphersProvider
        """


class CiphersProvider(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractmethod
    def supported(self, cipher, mode):
        """
        """

    @abc.abstractmethod
    def register_cipher_adapter(self, cipher, mode):
        """
        """

    @abc.abstractmethod
    def create_encrypt_ctx(self, cipher, mode):
        """
        """

    @abc.abstractmethod
    def create_decrypt_ctx(self, cipher, mode):
        """
        """


class HashesProviderBackend(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractproperty
    def hashes(self):
        """
        An instance of HashesProvider
        """


class HashesProvider(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractmethod
    def supported(self, algorithm):
        """
        """

    @abc.abstractmethod
    def create_ctx(self, algorithm):
        """
        """

    @abc.abstractmethod
    def update_ctx(self, ctx, data):
        """
        """

    @abc.abstractmethod
    def finalize_ctx(self, ctx, digest_size):
        """
        """

    @abc.abstractmethod
    def copy_ctx(self, ctx):
        """
        """


class HMACsProviderBackend(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractproperty
    def hmacs(self):
        """
        An instance of HMACsProvider
        """


class HMACsProvider(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractmethod
    def create_ctx(self, key, algorithm):
        """
        """

    @abc.abstractmethod
    def update_ctx(self, ctx, data):
        """
        """

    @abc.abstractmethod
    def finalize_ctx(self, ctx, digest_size):
        """
        """

    @abc.abstractmethod
    def copy_ctx(self, ctx):
        """
        """
