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


class X509DecoderContext(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractmethod
    def pkcs8_private_key(self, buffer, password_callback):
        """
        Returns the PrivateKey found in buffer
        """

    @abc.abstractmethod
    def pkcs1_public_key(self, buffer):
        """
        Returns the PubliceKey found in buffer
        """


class X509EncoderContext(six.with_metaclass(abc.ABCMeta)):
    @abc.abstractmethod
    def pkcs8_private_key(self, private_key, password_callback):
        """
        Returns a buffer containing a PKCS#8 encoded private_key
        """

    @abc.abstractmethod
    def pkcs1_public_key(self, public_key):
        """
        Returns a buffer containing a PKCS#1 encoded public_key
        """
