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

import sys

import cffi

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends.interfaces import (
    CipherBackend, HashBackend, HMACBackend
)
from cryptography.hazmat.primitives import interfaces


@utils.register_interface(CipherBackend)
@utils.register_interface(HashBackend)
@utils.register_interface(HMACBackend)
class Backend(object):
    """
    CommonCrypto API wrapper.
    """
    _module_prefix = "cryptography.hazmat.backends.commoncrypto."
    _modules = [
        "common_digest",
    ]

    ffi = None
    lib = None

    def __init__(self):
        self._ensure_ffi_initialized()

        self.hash_mappings = {
            "md5": {
                "object": "CC_MD5_CTX *",
                "init": self.lib.CC_MD5_Init,
                "update": self.lib.CC_MD5_Update,
                "final": self.lib.CC_MD5_Final},
            "sha1": {
                "object": "CC_SHA1_CTX *",
                "init": self.lib.CC_SHA1_Init,
                "update": self.lib.CC_SHA1_Update,
                "final": self.lib.CC_SHA1_Final},
            "sha224": {
                "object": "CC_SHA256_CTX *",
                "init": self.lib.CC_SHA224_Init,
                "update": self.lib.CC_SHA224_Update,
                "final": self.lib.CC_SHA224_Final},
            "sha256": {
                "object": "CC_SHA256_CTX *",
                "init": self.lib.CC_SHA256_Init,
                "update": self.lib.CC_SHA256_Update,
                "final": self.lib.CC_SHA256_Final},
            "sha384": {
                "object": "CC_SHA512_CTX *",
                "init": self.lib.CC_SHA384_Init,
                "update": self.lib.CC_SHA384_Update,
                "final": self.lib.CC_SHA384_Final},
            "sha512": {
                "object": "CC_SHA512_CTX *",
                "init": self.lib.CC_SHA512_Init,
                "update": self.lib.CC_SHA512_Update,
                "final": self.lib.CC_SHA512_Final},
        }

    @classmethod
    def _ensure_ffi_initialized(cls):
        if cls.ffi is not None and cls.lib is not None:
            return

        ffi = cffi.FFI()
        includes = []
        functions = []
        macros = []
        customizations = []
        for name in cls._modules:
            module_name = cls._module_prefix + name
            __import__(module_name)
            module = sys.modules[module_name]

            ffi.cdef(module.TYPES)

            macros.append(module.MACROS)
            functions.append(module.FUNCTIONS)
            includes.append(module.INCLUDES)
            customizations.append(module.CUSTOMIZATIONS)

        # loop over the functions & macros after declaring all the types
        # so we can set interdependent types in different files and still
        # have them all defined before we parse the funcs & macros
        for func in functions:
            ffi.cdef(func)
        for macro in macros:
            ffi.cdef(macro)

        # We include functions here so that if we got any of their definitions
        # wrong, the underlying C compiler will explode. In C you are allowed
        # to re-declare a function if it has the same signature. That is:
        #   int foo(int);
        #   int foo(int);
        # is legal, but the following will fail to compile:
        #   int foo(int);
        #   int foo(short);
        lib = ffi.verify(
            source="\n".join(includes + functions + customizations),
            libraries=[],
        )

        for name in cls._modules:
            module_name = cls._module_prefix + name
            module = sys.modules[module_name]
            for condition, names in module.CONDITIONAL_NAMES.items():
                if not getattr(lib, condition):
                    for name in names:
                        delattr(lib, name)

        cls.ffi = ffi
        cls.lib = lib

    def hash_supported(self, algorithm):
        return algorithm.name in self.hash_mappings

    def hmac_supported(self, algorithm):
        return False

    def create_hash_ctx(self, algorithm):
        return _HashContext(self, algorithm)

    def cipher_supported(self, cipher, mode):
        return False


@utils.register_interface(interfaces.HashContext)
class _HashContext(object):
    def __init__(self, backend, algorithm, ctx=None):
        self._algorithm = algorithm
        self._backend = backend

        if ctx is None:
            try:
                mapping = self._backend.hash_mappings[algorithm.name]
            except KeyError:
                raise UnsupportedAlgorithm(
                    "{0} is not a supported hash on this backend".format(
                        algorithm.name)
                )
            ctx = self._backend.ffi.new(mapping["object"])
            # init/update/final ALWAYS return 1
            mapping["init"](ctx)

        self._ctx = ctx

    def copy(self):
        mapping = self._backend.hash_mappings[self._algorithm.name]
        new_ctx = self._backend.ffi.new(mapping["object"])
        new_ctx[0] = self._ctx[0]  # supposed to be legit per C90?

        return _HashContext(self._backend, self._algorithm, ctx=new_ctx)

    def update(self, data):
        mapping = self._backend.hash_mappings[self._algorithm.name]
        mapping["update"](self._ctx, data, len(data))

    def finalize(self):
        mapping = self._backend.hash_mappings[self._algorithm.name]
        buf = self._backend.ffi.new("unsigned char[]",
                                    self._algorithm.digest_size)
        mapping["final"](buf, self._ctx)
        return self._backend.ffi.buffer(buf)[:]


backend = Backend()
