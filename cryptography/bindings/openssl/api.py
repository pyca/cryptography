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

from cryptography.primitives import interfaces

import cffi
import sys


class API(object):
    """
    OpenSSL API wrapper.
    """
    _modules = [
        "evp",
        "opensslv",
    ]

    def __init__(self):
        self._ffi = cffi.FFI()
        self.includes, self.types, self.functions = [], [], []
        self._import()
        self._define()
        self._verify()

        self._lib.OpenSSL_add_all_algorithms()

    def _import(self):
        """
        Import all library definitions
        """
        for name in self._modules:
            __import__('cryptography.bindings.openssl.' + name)
            module = sys.modules['cryptography.bindings.openssl.' + name]
            self._import_definitions(module, 'includes')
            self._import_definitions(module, 'types')
            self._import_definitions(module, 'functions')

    def _import_definitions(self, module, name):
        """
        Import definitions named definitions from module
        """
        container = getattr(self, name)
        container.append(getattr(module, name))

    def _define(self):
        for typedef in self.types:
            self._ffi.cdef(typedef)
        for function in self.functions:
            self._ffi.cdef(function)

    def _verify(self):
        self._lib = self._ffi.verify(
            source="\n".join(self.includes),
            libraries=['crypto']
        )

    def openssl_version_text(self):
        """
        Friendly string name of linked OpenSSL.

        Example: OpenSSL 1.0.1e 11 Feb 2013
        """
        return self._ffi.string(api._lib.OPENSSL_VERSION_TEXT).decode("ascii")

    def create_block_cipher_context(self, cipher, mode):
        ctx = self._ffi.new("EVP_CIPHER_CTX *")
        ctx = self._ffi.gc(ctx, self._lib.EVP_CIPHER_CTX_cleanup)
        # TODO: compute name using a better algorithm
        ciphername = "{0}-{1}-{2}".format(
            cipher.name, cipher.key_size, mode.name
        )
        evp_cipher = self._lib.EVP_get_cipherbyname(ciphername.encode("ascii"))
        assert evp_cipher != self._ffi.NULL
        if isinstance(mode, interfaces.ModeWithInitializationVector):
            iv_nonce = mode.initialization_vector
        else:
            iv_nonce = self._ffi.NULL

        # TODO: Sometimes this needs to be a DecryptInit, when?
        res = self._lib.EVP_EncryptInit_ex(
            ctx, evp_cipher, self._ffi.NULL, cipher.key, iv_nonce
        )
        assert res != 0

        # We purposely disable padding here as it's handled higher up in the
        # API.
        self._lib.EVP_CIPHER_CTX_set_padding(ctx, 0)
        return ctx

    def update_encrypt_context(self, ctx, plaintext):
        buf = self._ffi.new("unsigned char[]", len(plaintext))
        outlen = self._ffi.new("int *")
        res = self._lib.EVP_EncryptUpdate(
            ctx, buf, outlen, plaintext, len(plaintext)
        )
        assert res != 0
        return self._ffi.buffer(buf)[:outlen[0]]

    def finalize_encrypt_context(self, ctx):
        cipher = self._lib.EVP_CIPHER_CTX_cipher(ctx)
        block_size = self._lib.EVP_CIPHER_block_size(cipher)
        buf = self._ffi.new("unsigned char[]", block_size)
        outlen = self._ffi.new("int *")
        res = self._lib.EVP_EncryptFinal_ex(ctx, buf, outlen)
        assert res != 0
        res = self._lib.EVP_CIPHER_CTX_cleanup(ctx)
        assert res != 0
        return self._ffi.buffer(buf)[:outlen[0]]


api = API()
