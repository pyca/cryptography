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

import binascii

import six

from cryptography.bindings import _default_api


class BaseHash(six.with_metaclass(abc.ABCMeta)):
    def __init__(self, api=None, ctx=None):
        if api is None:
            api = _default_api
        self._api = api
        self._ctx = self._api.create_hash_context(self) if ctx is None else ctx

    def update(self, data):
        self._api.update_hash_context(self._ctx, data)

    def copy(self):
        return self.__class__(ctx=self._copy_ctx())

    def digest(self):
        return self._api.finalize_hash_context(self._copy_ctx(),
                                               self.digest_size)

    def hexdigest(self):
        return binascii.hexlify(self.digest()).decode("ascii")

    def _copy_ctx(self):
        return self._api.copy_hash_context(self._ctx)


class SHA1(BaseHash):
    name = "sha1"
    digest_size = 20
    block_size = 64


class SHA224(BaseHash):
    name = "sha224"
    digest_size = 28
    block_size = 64


class SHA256(BaseHash):
    name = "sha256"
    digest_size = 32
    block_size = 64


class SHA384(BaseHash):
    name = "sha384"
    digest_size = 48
    block_size = 128


class SHA512(BaseHash):
    name = "sha512"
    digest_size = 64
    block_size = 128


class RIPEMD160(BaseHash):
    name = "ripemd160"
    digest_size = 20
    block_size = 64


class Whirlpool(BaseHash):
    name = "whirlpool"
    digest_size = 64
    block_size = 64


class MD5(BaseHash):
    name = "md5"
    digest_size = 16
    block_size = 64
