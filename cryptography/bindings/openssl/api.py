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

import cffi


class API(object):
    """
    OpenSSL API wrapper.
    """

    def __init__(self):
        ffi = cffi.FFI()
        self._populate_ffi(ffi)
        self._ffi = ffi
        self._lib = ffi.verify("""
        #include <openssl/evp.h>
        #include <openssl/opensslv.h>
        """)
        self._lib.OpenSSL_add_all_algorithms()

    def _populate_ffi(self, ffi):
        ffi.cdef("""
        typedef struct {
            ...;
        } EVP_CIPHER_CTX;
        typedef ... EVP_CIPHER;
        typedef ... ENGINE;

        static char *const OPENSSL_VERSION_TEXT;

        void OpenSSL_add_all_algorithms();

        const EVP_CIPHER *EVP_get_cipherbyname(const char *);
        int EVP_EncryptInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *,
                               ENGINE *, unsigned char *, unsigned char *);
        int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *, int);
        int EVP_EncryptUpdate(EVP_CIPHER_CTX *, unsigned char *, int *,
                              unsigned char *, int);
        int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *, unsigned char *, int *);
        int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *);
        const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *);
        int EVP_CIPHER_block_size(const EVP_CIPHER *);
        """)

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
        # TODO: only use the key and initialization_vector as needed. Sometimes
        # this needs to be a DecryptInit, when?
        res = self._lib.EVP_EncryptInit_ex(
            ctx, evp_cipher, self._ffi.NULL, cipher.key,
            mode.initialization_vector
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
