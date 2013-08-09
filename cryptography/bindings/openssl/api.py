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

import cffi


class OpenSSLError(Exception):
    def __init__(self, api):
        e = api._lib.ERR_get_error()
        if e == 0:
            raise SystemError("Tried to create an OpenSSLError when there was "
                "None")
        msg = api._ffi.new("char[]", 120)
        api._lib.ERR_error_string(e, msg)
        super(OpenSSLError, self).__init__(api._ffi.string(msg))


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
        """)

    def _populate_ffi(self, ffi):
        ffi.cdef("""
        typedef struct {
            ...;
        } EVP_CIPHER_CTX;
        typedef ... EVP_CIPHER;
        typedef ... ENGINE;

        const EVP_CIPHER *EVP_get_cipherbyname(const char *);
        int EVP_EncryptInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *,
                               ENGINE *, unsigned char *, unsigned char *);
        int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *, int);
        int EVP_EncryptUpdate(EVP_CIPHER_CTX *, unsigned char *, int *,
                              unsigned char *, int);
        int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *, unsigned char *, int *);
        int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *);

        unsigned long ERR_get_error();
        """)

    def create_block_cipher_context(self, cipher, mode):
        ctx = self._ffi.new("EVP_CIPHER_CTX *")
        # TODO: compute name using a better algorithm
        ciphername = "{0}-{1}-{2}".format(cipher.name, len(cipher.key) * 8, mode.name)
        evp_cipher = self._lib.EVP_get_cipherbyname(ciphername.encode("ascii"))
        if evp_cipher == self._ffi.NULL:
            raise OpenSSLError(self)
        # TODO: only use the key and initialization_vector as needed. Sometimes
        # this needs to be a DecryptInit, when?
        res = self._lib.EVP_EncryptInit_ex(ctx, evp_cipher, self._ffi.NULL, cipher.key, mode.initialization_vector)
        if res == 0:
            raise OpenSSLError(self)
        # TODO: this should depend on mode.padding
        self._lib.EVP_CIPHER_CTX_set_padding(ctx, 0)
        return ctx

    def update_encrypt_context(self, ctx, plaintext):
        buf = self._ffi.new("unsigned char[]", len(plaintext))
        outlen = self._ffi.new("int *")
        res = self._lib.EVP_EncryptUpdate(ctx, buf, outlen, plaintext, len(plaintext))
        if res == 0:
            raise OpenSSLError(self)
        return self._ffi.buffer(buf)[:outlen[0]]

    def finalize_encrypt_context(self, ctx):
        # TODO: use real block size
        buf = self._ffi.new("unsigned char[]", 16)
        outlen = self._ffi.new("int *")
        res = self._lib.EVP_EncryptFinal_ex(ctx, buf, outlen)
        if res == 0:
            raise OpenSSLError(self)
        # TODO: this should also be called if the cipher isn't finalized.
        res = self._lib.EVP_CIPHER_CTX_cleanup(ctx)
        if res == 0:
            raise OpenSSLError(self)
        return self._ffi.buffer(buf)[:outlen[0]]


api = API()
