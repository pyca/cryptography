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

import re
import functools
import itertools

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm, InvalidTag
from cryptography.hazmat.backends.interfaces import (
    CipherBackend, HashBackend, HMACBackend, PKCS1Backend, PKCS8Backend
)
from cryptography.hazmat.primitives import interfaces
from cryptography.hazmat.primitives.ciphers.algorithms import (
    AES, Blowfish, Camellia, TripleDES, ARC4
)
from cryptography.hazmat.primitives.ciphers.modes import (
    CBC, CTR, ECB, OFB, CFB, GCM,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSA

from cryptography.hazmat.bindings.openssl.binding import Binding


@utils.register_interface(CipherBackend)
@utils.register_interface(HashBackend)
@utils.register_interface(HMACBackend)
@utils.register_interface(PKCS1Backend)
@utils.register_interface(PKCS8Backend)
class Backend(object):
    """
    OpenSSL API binding interfaces.
    """

    def __init__(self):
        self._binding = Binding()
        self._ffi = self._binding.ffi
        self._lib = self._binding.lib

        # adds all ciphers/digests for EVP
        self._lib.OpenSSL_add_all_algorithms()
        # registers available SSL/TLS ciphers and digests
        self._lib.SSL_library_init()
        # loads error strings for libcrypto and libssl functions
        self._lib.SSL_load_error_strings()

        self._cipher_registry = {}
        self._register_default_ciphers()

        self._asymmetric_registry = {}
        self._register_asymmetric_algorithms()

    def openssl_version_text(self):
        """
        Friendly string name of linked OpenSSL.

        Example: OpenSSL 1.0.1e 11 Feb 2013
        """
        return self._ffi.string(self._lib.OPENSSL_VERSION_TEXT).decode("ascii")

    def create_hmac_ctx(self, key, algorithm):
        return _HMACContext(self, key, algorithm)

    def hash_supported(self, algorithm):
        digest = self._lib.EVP_get_digestbyname(algorithm.name.encode("ascii"))
        return digest != self._ffi.NULL

    def hmac_supported(self, algorithm):
        return self.hash_supported(algorithm)

    def create_hash_ctx(self, algorithm):
        return _HashContext(self, algorithm)

    def create_pkcs1_encoder(self):
        return _PKCS1Encoder(self)

    def create_pkcs1_decoder(self):
        return _PKCS1Decoder(self)

    def create_pkcs8_encoder(self):
        return _PKCS8Encoder(self)

    def create_pkcs8_decoder(self):
        return _PKCS8Decoder(self)

    def cipher_supported(self, cipher, mode):
        try:
            adapter = self._cipher_registry[type(cipher), type(mode)]
        except KeyError:
            return False
        evp_cipher = adapter(self, cipher, mode)
        return self._ffi.NULL != evp_cipher

    def register_cipher_adapter(self, cipher_cls, mode_cls, adapter):
        if (cipher_cls, mode_cls) in self._cipher_registry:
            raise ValueError("Duplicate registration for: {0} {1}".format(
                cipher_cls, mode_cls)
            )
        self._cipher_registry[cipher_cls, mode_cls] = adapter

    def _register_default_ciphers(self):
        for cipher_cls, mode_cls in itertools.product(
            [AES, Camellia],
            [CBC, CTR, ECB, OFB, CFB],
        ):
            self.register_cipher_adapter(
                cipher_cls,
                mode_cls,
                GetCipherByName("{cipher.name}-{cipher.key_size}-{mode.name}")
            )
        for mode_cls in [CBC, CFB, OFB]:
            self.register_cipher_adapter(
                TripleDES,
                mode_cls,
                GetCipherByName("des-ede3-{mode.name}")
            )
        for mode_cls in [CBC, CFB, OFB, ECB]:
            self.register_cipher_adapter(
                Blowfish,
                mode_cls,
                GetCipherByName("bf-{mode.name}")
            )
        self.register_cipher_adapter(
            ARC4,
            type(None),
            GetCipherByName("rc4")
        )
        self.register_cipher_adapter(
            AES,
            GCM,
            GetCipherByName("{cipher.name}-{cipher.key_size}-{mode.name}")
        )

    def create_symmetric_encryption_ctx(self, cipher, mode):
        return _CipherContext(self, cipher, mode, _CipherContext._ENCRYPT)

    def create_symmetric_decryption_ctx(self, cipher, mode):
        return _CipherContext(self, cipher, mode, _CipherContext._DECRYPT)

    def _handle_error(self, mode):
        code = self._lib.ERR_get_error()
        if not code and isinstance(mode, GCM):
            raise InvalidTag
        assert code != 0
        lib = self._lib.ERR_GET_LIB(code)
        func = self._lib.ERR_GET_FUNC(code)
        reason = self._lib.ERR_GET_REASON(code)
        return self._handle_error_code(lib, func, reason)

    def _handle_error_code(self, lib, func, reason):
        if lib == self._lib.ERR_LIB_EVP:
            if func == self._lib.EVP_F_EVP_ENCRYPTFINAL_EX:
                if reason == self._lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH:
                    raise ValueError(
                        "The length of the provided data is not a multiple of "
                        "the block length"
                    )
            elif func == self._lib.EVP_F_EVP_DECRYPTFINAL_EX:
                if reason == self._lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH:
                    raise ValueError(
                        "The length of the provided data is not a multiple of "
                        "the block length"
                    )
        elif lib == self._lib.ERR_LIB_ASN1:
            if func and reason:
                raise ValueError(
                    "ASN.1 error"
                )
        elif lib == self._lib.ERR_LIB_PEM:
            if func and reason:
                raise ValueError(
                    "PEM error"
                )

        raise SystemError(
            "Unknown error code from OpenSSL, "
            "you should probably file a bug. "
            "lib={0}, func={1}, reason={2}".format(
                lib, func, reason
            )
        )

    def _get_evp_cipher(self, cipher, mode):
        registry = self._cipher_registry

        try:
            adapter = registry[type(cipher), type(mode)]
        except KeyError:
            raise UnsupportedAlgorithm(
                "cipher {0} in {1} mode is not supported "
                "by this backend".format(
                    cipher.name, mode.name if mode else mode)
            )

        evp_cipher = adapter(self, cipher, mode)
        if evp_cipher == self._ffi.NULL:
            raise UnsupportedAlgorithm(
                "cipher {0} in {1} mode is not supported "
                "by this backend".format(
                    cipher.name, mode.name if mode else mode)
            )

        return evp_cipher

    def _pem_password_cb(self, callback):
        """
        Wraps a callback(name, is_writing) into a

        typedef int pem_password_cb(char *buf, int size,
                                    int rwflag, void *userdata);

        suitable for decrypting PKCS8 files and so on
        """

        if callback is None:
            return self._ffi.NULL

        @functools.wraps(callback)
        def pem_password_cb(buf, size, writing, userdata):
            if userdata != self._ffi.NULL:
                name = self._ffi.string(userdata)
            else:
                name = None

            try:
                password = callback(name, writing == 1)
            except RuntimeError:
                return 0

            if len(password) >= size:
                return 0
            else:
                pw_buf = self._ffi.buffer(buf, size)
                pw_buf[:len(password)] = password
                return len(password)

        if callback:
            return self._ffi.callback("int (char *, int, int, void *)",
                                      pem_password_cb)
        else:
            return self._ffi.NULL

    def _register_asymmetric_algorithms(self):
        registry = self._asymmetric_registry

        registry[RSA] = (_RSAPublicKey, _RSAPrivateKey)

    def _evp_pkey_classes(self, evp_pkey):
        type = evp_pkey.type

        try:
            if type == self._lib.EVP_PKEY_RSA:
                pkey_type, skey_type = self._asymmetric_registry[RSA]
                return RSA, pkey_type, skey_type
        except KeyError:
            pass

        raise UnsupportedAlgorithm(type)

    def _public_key_from_evp_pkey(self, evp_pkey):
        """
        Turn an EVP_PKEY* into the correct flavour of PublicKey
        """

        asym_type, pkey_type, skey_type = self._evp_pkey_classes(evp_pkey)
        return asym_type.public_key_type(pkey_type(self, evp_pkey))

    def _private_key_from_evp_pkey(self, evp_pkey):
        """
        Turn an EVP_PKEY* into the correct flavour of PrivateKey
        """

        asym_type, pkey_type, skey_type = self._evp_pkey_classes(evp_pkey)
        return asym_type.private_key_type(skey_type(self, evp_pkey))


class GetCipherByName(object):
    def __init__(self, fmt):
        self._fmt = fmt

    def __call__(self, backend, cipher, mode):
        cipher_name = self._fmt.format(cipher=cipher, mode=mode).lower()
        return backend._lib.EVP_get_cipherbyname(cipher_name.encode("ascii"))


@utils.register_interface(interfaces.CipherContext)
@utils.register_interface(interfaces.AEADCipherContext)
@utils.register_interface(interfaces.AEADEncryptionContext)
class _CipherContext(object):
    _ENCRYPT = 1
    _DECRYPT = 0

    def __init__(self, backend, cipher, mode, operation):
        self._backend = backend
        self._cipher = cipher
        self._mode = mode
        self._operation = operation
        self._tag = None

        if isinstance(self._cipher, interfaces.BlockCipherAlgorithm):
            self._block_size = self._cipher.block_size
        else:
            self._block_size = 1

        ctx = self._backend._lib.EVP_CIPHER_CTX_new()
        ctx = self._backend._ffi.gc(
            ctx, self._backend._lib.EVP_CIPHER_CTX_free
        )

        evp_cipher = self._backend._get_evp_cipher(cipher, mode)

        if isinstance(mode, interfaces.ModeWithInitializationVector):
            iv_nonce = mode.initialization_vector
        elif isinstance(mode, interfaces.ModeWithNonce):
            iv_nonce = mode.nonce
        else:
            iv_nonce = self._backend._ffi.NULL
        # begin init with cipher and operation type
        res = self._backend._lib.EVP_CipherInit_ex(ctx, evp_cipher,
                                                   self._backend._ffi.NULL,
                                                   self._backend._ffi.NULL,
                                                   self._backend._ffi.NULL,
                                                   operation)
        assert res != 0
        # set the key length to handle variable key ciphers
        res = self._backend._lib.EVP_CIPHER_CTX_set_key_length(
            ctx, len(cipher.key)
        )
        assert res != 0
        if isinstance(mode, GCM):
            res = self._backend._lib.EVP_CIPHER_CTX_ctrl(
                ctx, self._backend._lib.EVP_CTRL_GCM_SET_IVLEN,
                len(iv_nonce), self._backend._ffi.NULL
            )
            assert res != 0
            if operation == self._DECRYPT:
                res = self._backend._lib.EVP_CIPHER_CTX_ctrl(
                    ctx, self._backend._lib.EVP_CTRL_GCM_SET_TAG,
                    len(mode.tag), mode.tag
                )
                assert res != 0

        # pass key/iv
        res = self._backend._lib.EVP_CipherInit_ex(
            ctx,
            self._backend._ffi.NULL,
            self._backend._ffi.NULL,
            cipher.key,
            iv_nonce,
            operation
        )
        assert res != 0
        # We purposely disable padding here as it's handled higher up in the
        # API.
        self._backend._lib.EVP_CIPHER_CTX_set_padding(ctx, 0)
        self._ctx = ctx

    def update(self, data):
        buf = self._backend._ffi.new("unsigned char[]",
                                     len(data) + self._block_size - 1)
        outlen = self._backend._ffi.new("int *")
        res = self._backend._lib.EVP_CipherUpdate(self._ctx, buf, outlen, data,
                                                  len(data))
        assert res != 0
        return self._backend._ffi.buffer(buf)[:outlen[0]]

    def finalize(self):
        buf = self._backend._ffi.new("unsigned char[]", self._block_size)
        outlen = self._backend._ffi.new("int *")
        res = self._backend._lib.EVP_CipherFinal_ex(self._ctx, buf, outlen)
        if res == 0:
            self._backend._handle_error(self._mode)

        if (isinstance(self._mode, GCM) and
           self._operation == self._ENCRYPT):
            block_byte_size = self._block_size // 8
            tag_buf = self._backend._ffi.new(
                "unsigned char[]", block_byte_size
            )
            res = self._backend._lib.EVP_CIPHER_CTX_ctrl(
                self._ctx, self._backend._lib.EVP_CTRL_GCM_GET_TAG,
                block_byte_size, tag_buf
            )
            assert res != 0
            self._tag = self._backend._ffi.buffer(tag_buf)[:]

        res = self._backend._lib.EVP_CIPHER_CTX_cleanup(self._ctx)
        assert res == 1
        return self._backend._ffi.buffer(buf)[:outlen[0]]

    def authenticate_additional_data(self, data):
        outlen = self._backend._ffi.new("int *")
        res = self._backend._lib.EVP_CipherUpdate(
            self._ctx, self._backend._ffi.NULL, outlen, data, len(data)
        )
        assert res != 0

    @property
    def tag(self):
        return self._tag


@utils.register_interface(interfaces.HashContext)
class _HashContext(object):
    def __init__(self, backend, algorithm, ctx=None):
        self.algorithm = algorithm

        self._backend = backend

        if ctx is None:
            ctx = self._backend._lib.EVP_MD_CTX_create()
            ctx = self._backend._ffi.gc(ctx,
                                        self._backend._lib.EVP_MD_CTX_destroy)
            evp_md = self._backend._lib.EVP_get_digestbyname(
                algorithm.name.encode("ascii"))
            if evp_md == self._backend._ffi.NULL:
                raise UnsupportedAlgorithm(
                    "{0} is not a supported hash on this backend".format(
                        algorithm.name)
                )
            res = self._backend._lib.EVP_DigestInit_ex(ctx, evp_md,
                                                       self._backend._ffi.NULL)
            assert res != 0

        self._ctx = ctx

    def copy(self):
        copied_ctx = self._backend._lib.EVP_MD_CTX_create()
        copied_ctx = self._backend._ffi.gc(
            copied_ctx, self._backend._lib.EVP_MD_CTX_destroy
        )
        res = self._backend._lib.EVP_MD_CTX_copy_ex(copied_ctx, self._ctx)
        assert res != 0
        return _HashContext(self._backend, self.algorithm, ctx=copied_ctx)

    def update(self, data):
        res = self._backend._lib.EVP_DigestUpdate(self._ctx, data, len(data))
        assert res != 0

    def finalize(self):
        buf = self._backend._ffi.new("unsigned char[]",
                                     self.algorithm.digest_size)
        res = self._backend._lib.EVP_DigestFinal_ex(self._ctx, buf,
                                                    self._backend._ffi.NULL)
        assert res != 0
        res = self._backend._lib.EVP_MD_CTX_cleanup(self._ctx)
        assert res == 1
        return self._backend._ffi.buffer(buf)[:]


@utils.register_interface(interfaces.HashContext)
class _HMACContext(object):
    def __init__(self, backend, key, algorithm, ctx=None):
        self.algorithm = algorithm
        self._backend = backend

        if ctx is None:
            ctx = self._backend._ffi.new("HMAC_CTX *")
            self._backend._lib.HMAC_CTX_init(ctx)
            ctx = self._backend._ffi.gc(
                ctx, self._backend._lib.HMAC_CTX_cleanup
            )
            evp_md = self._backend._lib.EVP_get_digestbyname(
                algorithm.name.encode('ascii'))
            if evp_md == self._backend._ffi.NULL:
                raise UnsupportedAlgorithm(
                    "{0} is not a supported hash on this backend".format(
                        algorithm.name)
                )
            res = self._backend._lib.Cryptography_HMAC_Init_ex(
                ctx, key, len(key), evp_md, self._backend._ffi.NULL
            )
            assert res != 0

        self._ctx = ctx
        self._key = key

    def copy(self):
        copied_ctx = self._backend._ffi.new("HMAC_CTX *")
        self._backend._lib.HMAC_CTX_init(copied_ctx)
        copied_ctx = self._backend._ffi.gc(
            copied_ctx, self._backend._lib.HMAC_CTX_cleanup
        )
        res = self._backend._lib.Cryptography_HMAC_CTX_copy(
            copied_ctx, self._ctx
        )
        assert res != 0
        return _HMACContext(
            self._backend, self._key, self.algorithm, ctx=copied_ctx
        )

    def update(self, data):
        res = self._backend._lib.Cryptography_HMAC_Update(
            self._ctx, data, len(data)
        )
        assert res != 0

    def finalize(self):
        buf = self._backend._ffi.new("unsigned char[]",
                                     self.algorithm.digest_size)
        buflen = self._backend._ffi.new("unsigned int *",
                                        self.algorithm.digest_size)
        res = self._backend._lib.Cryptography_HMAC_Final(
            self._ctx, buf, buflen
        )
        assert res != 0
        self._backend._lib.HMAC_CTX_cleanup(self._ctx)
        return self._backend._ffi.buffer(buf)[:]


class _RSAPublicKey(object):
    def __init__(self, backend, ctx):
        self._backend = backend
        self._ctx = ctx
        self._key = backend._lib.EVP_PKEY_get1_RSA(ctx)

        if self._key == backend._ffi.NULL:
            raise ValueError("context {0} is not an RSA key".format(ctx))

    @property
    def modulus(self):
        mod = self._backend._lib.BN_bn2hex(self._key.n)
        return int(self._backend._ffi.string(mod), 16)

    @property
    def public_exponent(self):
        exp = self._backend._lib.BN_bn2hex(self._key.e)
        return int(self._backend._ffi.string(exp), 16)

    @property
    def keysize(self):
        return self._backend._lib.BN_num_bits(self._key.n)


class _RSAPrivateKey(object):
    def __init__(self, backend, ctx):
        self._backend = backend
        self._ctx = ctx
        self._key = backend._lib.EVP_PKEY_get1_RSA(ctx)

        if self._key == backend._ffi.NULL:
            raise ValueError("context {0} is not an RSA key".format(ctx))

    @property
    def keysize(self):
        return self._backend._lib.BN_num_bits(self._key.n)


class _BasePEMCodec(object):
    def __init__(self, backend):
        self._backend = backend

    def _bio_mem_to_bytes(self, bio):
        data_p = backend._ffi.new("char**")
        bytes = backend._lib.BIO_get_mem_data(bio, data_p)
        assert bytes > 0
        data = backend._ffi.buffer(data_p[0], bytes)[:]
        return data

    def _password_callback(self, password):
        if password is None:
            password = b""

        def password_callback(name, verify):
            return password

        return self._backend._pem_password_cb(password_callback)

    def _load_pem(self, buffer, password, read_func):
        backend = self._backend

        buffer_char_p = backend._ffi.new("char[]", buffer)

        bio = backend._lib.BIO_new_mem_buf(
            buffer_char_p, len(buffer)
        )

        key_ctx = read_func(
            bio,
            backend._ffi.NULL,
            self._password_callback(password),
            backend._ffi.NULL
        )

        if key_ctx == backend._ffi.NULL:
            backend._handle_error(None)

        return key_ctx

    def _dump_public_pem(self, key_ctx, write_func):
        backend = self._backend

        bio = backend._lib.BIO_new(
            backend._lib.BIO_s_mem()
        )

        res = write_func(bio, key_ctx)

        if res == 0:
            backend._lib.BIO_free(bio)
            backend._handle_error(None)

        data = self._bio_mem_to_bytes(bio)
        backend._lib.BIO_free(bio)
        return data

    def _dump_private_pem(self, key_ctx, evp_cipher, password, write_func):
        backend = self._backend

        bio = backend._lib.BIO_new(
            backend._lib.BIO_s_mem()
        )

        res = write_func(
            bio,
            key_ctx,
            evp_cipher,
            backend._ffi.NULL,
            0,
            self._password_callback(password),
            backend._ffi.NULL,
        )

        if res == 0:
            backend._lib.BIO_free(bio)
            backend._handle_error(None)

        data = self._bio_mem_to_bytes(bio)
        backend._lib.BIO_free(bio)
        return data


class _BasePEMDecoder(_BasePEMCodec):
    def load_pem_public_key(self, buffer, password=None):
        evp_pkey = self._public_pem_to_evp_pkey(buffer, password)
        return backend._public_key_from_evp_pkey(evp_pkey)

    def load_pem_private_key(self, buffer, password):
        evp_pkey = self._private_pem_to_evp_pkey(buffer, password)
        return backend._private_key_from_evp_pkey(evp_pkey)


class _BasePEMEncoder(_BasePEMCodec):
    def dump_pem_public_key(self, public_key):
        return self._public_evp_pkey_to_pem(public_key._ctx._ctx)

    def dump_pem_private_key(self, private_key, cipher, mode, password):
        if not cipher and not mode:
            evp_cipher = self._backend._ffi.NULL
        else:
            evp_cipher = self._backend._get_evp_cipher(cipher, mode)

        return self._private_evp_pkey_to_pem(
            private_key._ctx._ctx,
            evp_cipher,
            password
        )


class _PKCS1Decoder(_BasePEMDecoder):
    _pem_begin_rx = re.compile((
        b"^-----BEGIN (ENCRYPTED )?"
        b"(?P<algo>(RSA|DSA|EC) )"
        b"(?P<type>PUBLIC KEY|PRIVATE KEY|CERTIFICATE)-----$"
    ),
        re.MULTILINE
    )

    def _pem_type(self, buffer):
        match = self._pem_begin_rx.search(buffer)

        if match:
            type_str = match.group("algo")
            key_type = match.group("type")

            if type_str and key_type:
                return type_str[:-1], key_type
            else:
                return None
        else:
            raise ValueError("Can not find PEM header")

    def _new_evp_pkey(self, key_ctx, set_func):
        evp_pkey = self._backend._lib.EVP_PKEY_new()

        if evp_pkey == backend._ffi.NULL:
            backend._handle_error(None)

        evp_pkey = self._backend._ffi.gc(
            evp_pkey,
            self._backend._lib.EVP_PKEY_free
        )

        res = set_func(evp_pkey, key_ctx)
        assert res == 1

        return evp_pkey

    def _public_pem_to_evp_pkey_funcs(self, buffer):
        pem_algorithm, pem_key_type = self._pem_type(buffer)

        if pem_algorithm == b"RSA":
            pem_func = backend._lib.PEM_read_bio_RSAPublicKey
            evp_pkey_set = backend._lib.EVP_PKEY_assign_RSA
        else:
            raise UnsupportedAlgorithm(pem_algorithm)

        return pem_func, evp_pkey_set

    def _private_pem_to_evp_pkey_funcs(self, buffer):
        pem_algorithm, pem_key_type = self._pem_type(buffer)

        if pem_algorithm == b"RSA":
            pem_func = backend._lib.PEM_read_bio_RSAPrivateKey
            evp_pkey_set = backend._lib.EVP_PKEY_assign_RSA
        else:
            raise UnsupportedAlgorithm(pem_algorithm)

        return pem_func, evp_pkey_set

    def _public_pem_to_evp_pkey(self, buffer, password):
        read_func, set_func = self._public_pem_to_evp_pkey_funcs(buffer)
        key_ctx = self._load_pem(buffer, password, read_func)
        return self._new_evp_pkey(key_ctx, set_func)

    def _private_pem_to_evp_pkey(self, buffer, password):
        read_func, set_func = self._private_pem_to_evp_pkey_funcs(buffer)
        key_ctx = self._load_pem(buffer, password, read_func)
        return self._new_evp_pkey(key_ctx, set_func)


class _PKCS1Encoder(_BasePEMEncoder):
    def _public_evp_pkey_to_pem_funcs(self, evp_pkey):
        if evp_pkey.type == backend._lib.EVP_PKEY_RSA:
            pem_func = backend._lib.PEM_write_bio_RSAPublicKey
            ctx_func = backend._lib.EVP_PKEY_get1_RSA
        else:
            raise UnsupportedAlgorithm(evp_pkey.type)

        return pem_func, ctx_func

    def _private_evp_pkey_to_pem_funcs(self, evp_pkey):
        if evp_pkey.type == backend._lib.EVP_PKEY_RSA:
            pem_func = backend._lib.PEM_write_bio_RSAPrivateKey
            ctx_func = backend._lib.EVP_PKEY_get1_RSA
        else:
            raise UnsupportedAlgorithm(evp_pkey.type)

        return pem_func, ctx_func

    def _public_evp_pkey_to_pem(self, evp_pkey):
        write_func, get_func = self._public_evp_pkey_to_pem_funcs(evp_pkey)
        key_ctx = get_func(evp_pkey)
        return self._dump_public_pem(key_ctx, write_func)

    def _private_evp_pkey_to_pem(self, evp_pkey, evp_cipher, password):
        write_func, get_func = self._private_evp_pkey_to_pem_funcs(evp_pkey)
        key_ctx = get_func(evp_pkey)
        return self._dump_private_pem(key_ctx, evp_cipher, password,
                                      write_func)


class _PKCS8Decoder(_BasePEMDecoder):
    def _public_pem_to_evp_pkey(self, buffer, password):
        return self._load_pem(
            buffer, password,
            self._backend._lib.PEM_read_bio_PUBKEY
        )

    def _private_pem_to_evp_pkey(self, buffer, password):
        return self._load_pem(
            buffer, password,
            self._backend._lib.PEM_read_bio_PrivateKey
        )


class _PKCS8Encoder(_BasePEMEncoder):
    def _public_evp_pkey_to_pem(self, evp_pkey):
        return self._dump_public_pem(
            evp_pkey,
            self._backend._lib.PEM_write_bio_PUBKEY
        )

    def _private_evp_pkey_to_pem(self, evp_pkey, evp_cipher, password):
        return self._dump_private_pem(
            evp_pkey, evp_cipher, password,
            self._backend._lib.PEM_write_bio_PKCS8PrivateKey
        )

backend = Backend()
