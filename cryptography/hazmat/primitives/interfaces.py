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


def register(iface):
    def register_decorator(klass):
        iface.register(klass)
        return klass
    return register_decorator


class ModeWithInitializationVector(six.with_metaclass(abc.ABCMeta)):
    pass


class ModeWithNonce(six.with_metaclass(abc.ABCMeta)):
    pass


class CipherContext(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractmethod
    def update(self, data):
        """
        update takes bytes and return bytes
        """

    @abc.abstractmethod
    def finalize(self):
        """
        finalize return bytes
        """


class PaddingContext(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractmethod
    def update(self, data):
        """
        update takes bytes and return bytes
        """

    @abc.abstractmethod
    def finalize(self):
        """
        finalize return bytes
        """


class HashAlgorithm(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractproperty
    def name(self):
        """
        A string naming this algorithm. (ex. sha256, md5)
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
        hash data as bytes
        """

    @abc.abstractmethod
    def finalize(self):
        """
        finalize this copy of the hash and return the digest as bytes.
        """

    @abc.abstractmethod
    def copy(self):
        """
        return a HashContext that is a copy of the current context.
        """
