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

import collections
import itertools
import math

import six

from cryptography import utils
from cryptography.exceptions import (
    AlreadyFinalized, InternalError, InvalidSignature, InvalidTag,
    UnsupportedAlgorithm, _Reasons
)
from cryptography.hazmat.backends.interfaces import (
    CMACBackend, CipherBackend, DSABackend, HMACBackend, HashBackend,
    PBKDF2HMACBackend, RSABackend
)
from cryptography.hazmat.bindings.openssl.binding import Binding
from cryptography.hazmat.primitives import hashes, interfaces
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.asymmetric.padding import (
    MGF1, OAEP, PKCS1v15, PSS
)
from cryptography.hazmat.primitives.ciphers.algorithms import (
    AES, ARC4, Blowfish, CAST5, Camellia, IDEA, SEED, TripleDES
)
from cryptography.hazmat.primitives.ciphers.modes import (
    CBC, CFB, CFB8, CTR, ECB, GCM, OFB
)


_OpenSSLError = collections.namedtuple("_OpenSSLError",
                                       ["code", "lib", "func", "reason"])


@utils.register_interface(CipherBackend)
@utils.register_interface(CMACBackend)
@utils.register_interface(DSABackend)
@utils.register_interface(HashBackend)
@utils.register_interface(HMACBackend)
@utils.register_interface(PBKDF2HMACBackend)
@utils.register_interface(RSABackend)
class Backend(object):
    """
    OpenSSL API binding interfaces.
    """
    name = "openssl"

    def __init__(self):
        self._binding = Binding()
        self._ffi = self._binding.ffi
        self._lib = self._binding.lib

        self._binding.init_static_locks()

        # adds all ciphers/digests for EVP
        self._lib.OpenSSL_add_all_algorithms()
        # registers available SSL/TLS ciphers and digests
        self._lib.SSL_library_init()
        # loads error strings for libcrypto and libssl functions
        self._lib.SSL_load_error_strings()

        self._cipher_registry = {}
        self._register_default_ciphers()
        self.activate_osrandom_engine()

    def activate_builtin_random(self):
        # Obtain a new structural reference.
        e = self._lib.ENGINE_get_default_RAND()
        if e != self._ffi.NULL:
            self._lib.ENGINE_unregister_RAND(e)
            # Reset the RNG to use the new engine.
            self._lib.RAND_cleanup()
            # decrement the structural reference from get_default_RAND
            res = self._lib.ENGINE_finish(e)
            assert res == 1

    def activate_osrandom_engine(self):
        # Unregister and free the current engine.
        self.activate_builtin_random()
        # Fetches an engine by id and returns it. This creates a structural
        # reference.
        e = self._lib.ENGINE_by_id(self._lib.Cryptography_osrandom_engine_id)
        assert e != self._ffi.NULL
        # Initialize the engine for use. This adds a functional reference.
        res = self._lib.ENGINE_init(e)
        assert res == 1
        # Set the engine as the default RAND provider.
        res = self._lib.ENGINE_set_default_RAND(e)
        assert res == 1
        # Decrement the structural ref incremented by ENGINE_by_id.
        res = self._lib.ENGINE_free(e)
        assert res == 1
        # Decrement the functional ref incremented by ENGINE_init.
        res = self._lib.ENGINE_finish(e)
        assert res == 1
        # Reset the RNG to use the new engine.
        self._lib.RAND_cleanup()

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
        for mode_cls in [CBC, CTR, ECB, OFB, CFB, CFB8]:
            self.register_cipher_adapter(
                AES,
                mode_cls,
                GetCipherByName("{cipher.name}-{cipher.key_size}-{mode.name}")
            )
        for mode_cls in [CBC, CTR, ECB, OFB, CFB]:
            self.register_cipher_adapter(
                Camellia,
                mode_cls,
                GetCipherByName("{cipher.name}-{cipher.key_size}-{mode.name}")
            )
        for mode_cls in [CBC, CFB, CFB8, OFB]:
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
        for mode_cls in [CBC, CFB, OFB, ECB]:
            self.register_cipher_adapter(
                SEED,
                mode_cls,
                GetCipherByName("seed-{mode.name}")
            )
        for cipher_cls, mode_cls in itertools.product(
            [CAST5, IDEA],
            [CBC, OFB, CFB, ECB],
        ):
            self.register_cipher_adapter(
                cipher_cls,
                mode_cls,
                GetCipherByName("{cipher.name}-{mode.name}")
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

    def pbkdf2_hmac_supported(self, algorithm):
        if self._lib.Cryptography_HAS_PBKDF2_HMAC:
            return self.hmac_supported(algorithm)
        else:
            # OpenSSL < 1.0.0 has an explicit PBKDF2-HMAC-SHA1 function,
            # so if the PBKDF2_HMAC function is missing we only support
            # SHA1 via PBKDF2_HMAC_SHA1.
            return isinstance(algorithm, hashes.SHA1)

    def derive_pbkdf2_hmac(self, algorithm, length, salt, iterations,
                           key_material):
        buf = self._ffi.new("char[]", length)
        if self._lib.Cryptography_HAS_PBKDF2_HMAC:
            evp_md = self._lib.EVP_get_digestbyname(
                algorithm.name.encode("ascii"))
            assert evp_md != self._ffi.NULL
            res = self._lib.PKCS5_PBKDF2_HMAC(
                key_material,
                len(key_material),
                salt,
                len(salt),
                iterations,
                evp_md,
                length,
                buf
            )
            assert res == 1
        else:
            if not isinstance(algorithm, hashes.SHA1):
                raise UnsupportedAlgorithm(
                    "This version of OpenSSL only supports PBKDF2HMAC with "
                    "SHA1",
                    _Reasons.UNSUPPORTED_HASH
                )
            res = self._lib.PKCS5_PBKDF2_HMAC_SHA1(
                key_material,
                len(key_material),
                salt,
                len(salt),
                iterations,
                length,
                buf
            )
            assert res == 1

        return self._ffi.buffer(buf)[:]

    def _err_string(self, code):
        err_buf = self._ffi.new("char[]", 256)
        self._lib.ERR_error_string_n(code, err_buf, 256)
        return self._ffi.string(err_buf, 256)[:]

    def _consume_errors(self):
        errors = []
        while True:
            code = self._lib.ERR_get_error()
            if code == 0:
                break

            lib = self._lib.ERR_GET_LIB(code)
            func = self._lib.ERR_GET_FUNC(code)
            reason = self._lib.ERR_GET_REASON(code)

            errors.append(_OpenSSLError(code, lib, func, reason))
        return errors

    def _unknown_error(self, error):
        return InternalError(
            "Unknown error code {0} from OpenSSL, "
            "you should probably file a bug. {1}".format(
                error.code, self._err_string(error.code)
            )
        )

    def _bn_to_int(self, bn):
        if six.PY3:
            # Python 3 has constant time from_bytes, so use that.

            bn_num_bytes = (self._lib.BN_num_bits(bn) + 7) // 8
            bin_ptr = self._ffi.new("unsigned char[]", bn_num_bytes)
            bin_len = self._lib.BN_bn2bin(bn, bin_ptr)
            assert bin_len > 0
            assert bin_ptr != self._ffi.NULL
            return int.from_bytes(self._ffi.buffer(bin_ptr)[:bin_len], "big")

        else:
            # Under Python 2 the best we can do is hex()

            hex_cdata = self._lib.BN_bn2hex(bn)
            assert hex_cdata != self._ffi.NULL
            hex_str = self._ffi.string(hex_cdata)
            self._lib.OPENSSL_free(hex_cdata)
            return int(hex_str, 16)

    def _int_to_bn(self, num, bn=None):
        """
        Converts a python integer to a BIGNUM. The returned BIGNUM will not
        be garbage collected (to support adding them to structs that take
        ownership of the object). Be sure to register it for GC if it will
        be discarded after use.
        """

        if bn is None:
            bn = self._ffi.NULL

        if six.PY3:
            # Python 3 has constant time to_bytes, so use that.

            binary = num.to_bytes(int(num.bit_length() / 8.0 + 1), "big")
            bn_ptr = self._lib.BN_bin2bn(binary, len(binary), bn)
            assert bn_ptr != self._ffi.NULL
            return bn_ptr

        else:
            # Under Python 2 the best we can do is hex()

            hex_num = hex(num).rstrip("L").lstrip("0x").encode("ascii") or b"0"
            bn_ptr = self._ffi.new("BIGNUM **")
            bn_ptr[0] = bn
            res = self._lib.BN_hex2bn(bn_ptr, hex_num)
            assert res != 0
            assert bn_ptr[0] != self._ffi.NULL
            return bn_ptr[0]

    def generate_rsa_private_key(self, public_exponent, key_size):
        if public_exponent < 3:
            raise ValueError("public_exponent must be >= 3")

        if public_exponent & 1 == 0:
            raise ValueError("public_exponent must be odd")

        if key_size < 512:
            raise ValueError("key_size must be at least 512-bits")

        ctx = self._lib.RSA_new()
        assert ctx != self._ffi.NULL
        ctx = self._ffi.gc(ctx, self._lib.RSA_free)

        bn = self._int_to_bn(public_exponent)
        bn = self._ffi.gc(bn, self._lib.BN_free)

        res = self._lib.RSA_generate_key_ex(
            ctx, key_size, bn, self._ffi.NULL
        )
        assert res == 1

        return self._rsa_cdata_to_private_key(ctx)

    def _new_evp_pkey(self):
        evp_pkey = self._lib.EVP_PKEY_new()
        assert evp_pkey != self._ffi.NULL
        return self._ffi.gc(evp_pkey, self._lib.EVP_PKEY_free)

    def _rsa_private_key_to_evp_pkey(self, private_key):
        evp_pkey = self._new_evp_pkey()
        rsa_cdata = self._rsa_cdata_from_private_key(private_key)

        res = self._lib.EVP_PKEY_assign_RSA(evp_pkey, rsa_cdata)
        assert res == 1

        return evp_pkey

    def _rsa_public_key_to_evp_pkey(self, public_key):
        evp_pkey = self._new_evp_pkey()
        rsa_cdata = self._rsa_cdata_from_public_key(public_key)

        res = self._lib.EVP_PKEY_assign_RSA(evp_pkey, rsa_cdata)
        assert res == 1

        return evp_pkey

    def _rsa_cdata_to_private_key(self, cdata):
        return rsa.RSAPrivateKey(
            p=self._bn_to_int(cdata.p),
            q=self._bn_to_int(cdata.q),
            dmp1=self._bn_to_int(cdata.dmp1),
            dmq1=self._bn_to_int(cdata.dmq1),
            iqmp=self._bn_to_int(cdata.iqmp),
            private_exponent=self._bn_to_int(cdata.d),
            public_exponent=self._bn_to_int(cdata.e),
            modulus=self._bn_to_int(cdata.n),
        )

    def _rsa_cdata_from_private_key(self, private_key):
        # Does not GC the RSA cdata. You *must* make sure it's freed
        # correctly yourself!
        ctx = self._lib.RSA_new()
        assert ctx != self._ffi.NULL
        ctx.p = self._int_to_bn(private_key.p)
        ctx.q = self._int_to_bn(private_key.q)
        ctx.d = self._int_to_bn(private_key.d)
        ctx.e = self._int_to_bn(private_key.e)
        ctx.n = self._int_to_bn(private_key.n)
        ctx.dmp1 = self._int_to_bn(private_key.dmp1)
        ctx.dmq1 = self._int_to_bn(private_key.dmq1)
        ctx.iqmp = self._int_to_bn(private_key.iqmp)
        res = self._lib.RSA_blinding_on(ctx, self._ffi.NULL)
        assert res == 1

        return ctx

    def _rsa_cdata_from_public_key(self, public_key):
        # Does not GC the RSA cdata. You *must* make sure it's freed
        # correctly yourself!

        ctx = self._lib.RSA_new()
        assert ctx != self._ffi.NULL
        ctx.e = self._int_to_bn(public_key.e)
        ctx.n = self._int_to_bn(public_key.n)
        res = self._lib.RSA_blinding_on(ctx, self._ffi.NULL)
        assert res == 1

        return ctx

    def create_rsa_signature_ctx(self, private_key, padding, algorithm):
        return _RSASignatureContext(self, private_key, padding, algorithm)

    def create_rsa_verification_ctx(self, public_key, signature, padding,
                                    algorithm):
        return _RSAVerificationContext(self, public_key, signature, padding,
                                       algorithm)

    def mgf1_hash_supported(self, algorithm):
        if self._lib.Cryptography_HAS_MGF1_MD:
            return self.hash_supported(algorithm)
        else:
            return isinstance(algorithm, hashes.SHA1)

    def generate_dsa_parameters(self, key_size):
        if key_size not in (1024, 2048, 3072):
            raise ValueError(
                "Key size must be 1024 or 2048 or 3072 bits")

        if (self._lib.OPENSSL_VERSION_NUMBER < 0x1000000f and
                key_size > 1024):
            raise ValueError(
                "Key size must be 1024 because OpenSSL < 1.0.0 doesn't "
                "support larger key sizes")

        ctx = self._lib.DSA_new()
        assert ctx != self._ffi.NULL
        ctx = self._ffi.gc(ctx, self._lib.DSA_free)

        res = self._lib.DSA_generate_parameters_ex(
            ctx, key_size, self._ffi.NULL, 0,
            self._ffi.NULL, self._ffi.NULL, self._ffi.NULL
        )

        assert res == 1

        return dsa.DSAParameters(
            modulus=self._bn_to_int(ctx.p),
            subgroup_order=self._bn_to_int(ctx.q),
            generator=self._bn_to_int(ctx.g)
        )

    def generate_dsa_private_key(self, parameters):
        ctx = self._lib.DSA_new()
        assert ctx != self._ffi.NULL
        ctx = self._ffi.gc(ctx, self._lib.DSA_free)
        ctx.p = self._int_to_bn(parameters.p)
        ctx.q = self._int_to_bn(parameters.q)
        ctx.g = self._int_to_bn(parameters.g)

        self._lib.DSA_generate_key(ctx)

        return dsa.DSAPrivateKey(
            modulus=self._bn_to_int(ctx.p),
            subgroup_order=self._bn_to_int(ctx.q),
            generator=self._bn_to_int(ctx.g),
            x=self._bn_to_int(ctx.priv_key),
            y=self._bn_to_int(ctx.pub_key)
        )

    def create_dsa_signature_ctx(self, private_key, algorithm):
        return _DSASignatureContext(self, private_key, algorithm)

    def create_dsa_verification_ctx(self, public_key, signature,
                                    algorithm):
        return _DSAVerificationContext(self, public_key, signature,
                                       algorithm)

    def _dsa_cdata_from_public_key(self, public_key):
        # Does not GC the DSA cdata. You *must* make sure it's freed
        # correctly yourself!
        ctx = self._lib.DSA_new()
        assert ctx != self._ffi.NULL
        parameters = public_key.parameters()
        ctx.p = self._int_to_bn(parameters.p)
        ctx.q = self._int_to_bn(parameters.q)
        ctx.g = self._int_to_bn(parameters.g)
        ctx.pub_key = self._int_to_bn(public_key.y)
        return ctx

    def _dsa_cdata_from_private_key(self, private_key):
        # Does not GC the DSA cdata. You *must* make sure it's freed
        # correctly yourself!
        ctx = self._lib.DSA_new()
        assert ctx != self._ffi.NULL
        parameters = private_key.parameters()
        ctx.p = self._int_to_bn(parameters.p)
        ctx.q = self._int_to_bn(parameters.q)
        ctx.g = self._int_to_bn(parameters.g)
        ctx.priv_key = self._int_to_bn(private_key.x)
        ctx.pub_key = self._int_to_bn(private_key.y)
        return ctx

    def dsa_hash_supported(self, algorithm):
        if self._lib.OPENSSL_VERSION_NUMBER < 0x1000000f:
            return isinstance(algorithm, hashes.SHA1)
        else:
            return self.hash_supported(algorithm)

    def dsa_parameters_supported(self, p, q, g):
        if self._lib.OPENSSL_VERSION_NUMBER < 0x1000000f:
            return (utils.bit_length(p) <= 1024 and utils.bit_length(q) <= 160)
        else:
            return True

    def decrypt_rsa(self, private_key, ciphertext, padding):
        key_size_bytes = int(math.ceil(private_key.key_size / 8.0))
        if key_size_bytes != len(ciphertext):
            raise ValueError("Ciphertext length must be equal to key size.")

        return self._enc_dec_rsa(private_key, ciphertext, padding)

    def encrypt_rsa(self, public_key, plaintext, padding):
        return self._enc_dec_rsa(public_key, plaintext, padding)

    def _enc_dec_rsa(self, key, data, padding):
        if isinstance(padding, PKCS1v15):
            padding_enum = self._lib.RSA_PKCS1_PADDING
        elif isinstance(padding, OAEP):
            padding_enum = self._lib.RSA_PKCS1_OAEP_PADDING
            if not isinstance(padding._mgf, MGF1):
                raise UnsupportedAlgorithm(
                    "Only MGF1 is supported by this backend",
                    _Reasons.UNSUPPORTED_MGF
                )

            if not isinstance(padding._mgf._algorithm, hashes.SHA1):
                raise UnsupportedAlgorithm(
                    "This backend supports only SHA1 inside MGF1 when "
                    "using OAEP",
                    _Reasons.UNSUPPORTED_HASH
                )

            if padding._label is not None and padding._label != b"":
                raise ValueError("This backend does not support OAEP labels")

            if not isinstance(padding._algorithm, hashes.SHA1):
                raise UnsupportedAlgorithm(
                    "This backend only supports SHA1 when using OAEP",
                    _Reasons.UNSUPPORTED_HASH
                )
        else:
            raise UnsupportedAlgorithm(
                "{0} is not supported by this backend".format(
                    padding.name
                ),
                _Reasons.UNSUPPORTED_PADDING
            )

        if self._lib.Cryptography_HAS_PKEY_CTX:
            return self._enc_dec_rsa_pkey_ctx(key, data, padding_enum)
        else:
            return self._enc_dec_rsa_098(key, data, padding_enum)

    def _enc_dec_rsa_pkey_ctx(self, key, data, padding_enum):
        if isinstance(key, rsa.RSAPublicKey):
            init = self._lib.EVP_PKEY_encrypt_init
            crypt = self._lib.Cryptography_EVP_PKEY_encrypt
            evp_pkey = self._rsa_public_key_to_evp_pkey(key)
        else:
            init = self._lib.EVP_PKEY_decrypt_init
            crypt = self._lib.Cryptography_EVP_PKEY_decrypt
            evp_pkey = self._rsa_private_key_to_evp_pkey(key)

        pkey_ctx = self._lib.EVP_PKEY_CTX_new(
            evp_pkey, self._ffi.NULL
        )
        assert pkey_ctx != self._ffi.NULL
        pkey_ctx = self._ffi.gc(pkey_ctx, self._lib.EVP_PKEY_CTX_free)
        res = init(pkey_ctx)
        assert res == 1
        res = self._lib.EVP_PKEY_CTX_set_rsa_padding(
            pkey_ctx, padding_enum)
        assert res > 0
        buf_size = self._lib.EVP_PKEY_size(evp_pkey)
        assert buf_size > 0
        outlen = self._ffi.new("size_t *", buf_size)
        buf = self._ffi.new("char[]", buf_size)
        res = crypt(
            pkey_ctx,
            buf,
            outlen,
            data,
            len(data)
        )
        if res <= 0:
            self._handle_rsa_enc_dec_error(key)

        return self._ffi.buffer(buf)[:outlen[0]]

    def _enc_dec_rsa_098(self, key, data, padding_enum):
        if isinstance(key, rsa.RSAPublicKey):
            crypt = self._lib.RSA_public_encrypt
            rsa_cdata = self._rsa_cdata_from_public_key(key)
        else:
            crypt = self._lib.RSA_private_decrypt
            rsa_cdata = self._rsa_cdata_from_private_key(key)

        rsa_cdata = self._ffi.gc(rsa_cdata, self._lib.RSA_free)
        key_size = self._lib.RSA_size(rsa_cdata)
        assert key_size > 0
        buf = self._ffi.new("unsigned char[]", key_size)
        res = crypt(
            len(data),
            data,
            buf,
            rsa_cdata,
            padding_enum
        )
        if res < 0:
            self._handle_rsa_enc_dec_error(key)

        return self._ffi.buffer(buf)[:res]

    def _handle_rsa_enc_dec_error(self, key):
        errors = self._consume_errors()
        assert errors
        assert errors[0].lib == self._lib.ERR_LIB_RSA
        if isinstance(key, rsa.RSAPublicKey):
            assert (errors[0].reason ==
                    self._lib.RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE)
            raise ValueError(
                "Data too long for key size. Encrypt less data or use a "
                "larger key size"
            )
        else:
            assert (
                errors[0].reason == self._lib.RSA_R_BLOCK_TYPE_IS_NOT_01 or
                errors[0].reason == self._lib.RSA_R_BLOCK_TYPE_IS_NOT_02
            )
            raise ValueError("Decryption failed")

    def cmac_algorithm_supported(self, algorithm):
        return (
            self._lib.Cryptography_HAS_CMAC == 1
            and self.cipher_supported(algorithm, CBC(
                b"\x00" * algorithm.block_size))
        )

    def create_cmac_ctx(self, algorithm):
        return _CMACContext(self, algorithm)


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

        registry = self._backend._cipher_registry
        try:
            adapter = registry[type(cipher), type(mode)]
        except KeyError:
            raise UnsupportedAlgorithm(
                "cipher {0} in {1} mode is not supported "
                "by this backend".format(
                    cipher.name, mode.name if mode else mode),
                _Reasons.UNSUPPORTED_CIPHER
            )

        evp_cipher = adapter(self._backend, cipher, mode)
        if evp_cipher == self._backend._ffi.NULL:
            raise UnsupportedAlgorithm(
                "cipher {0} in {1} mode is not supported "
                "by this backend".format(
                    cipher.name, mode.name if mode else mode),
                _Reasons.UNSUPPORTED_CIPHER
            )

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
        # OpenSSL 0.9.8e has an assertion in its EVP code that causes it
        # to SIGABRT if you call update with an empty byte string. This can be
        # removed when we drop support for 0.9.8e (CentOS/RHEL 5). This branch
        # should be taken only when length is zero and mode is not GCM because
        # AES GCM can return improper tag values if you don't call update
        # with empty plaintext when authenticating AAD for ...reasons.
        if len(data) == 0 and not isinstance(self._mode, GCM):
            return b""

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
            errors = self._backend._consume_errors()

            if not errors and isinstance(self._mode, GCM):
                raise InvalidTag

            assert errors

            if errors[0][1:] == (
                self._backend._lib.ERR_LIB_EVP,
                self._backend._lib.EVP_F_EVP_ENCRYPTFINAL_EX,
                self._backend._lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH
            ) or errors[0][1:] == (
                self._backend._lib.ERR_LIB_EVP,
                self._backend._lib.EVP_F_EVP_DECRYPTFINAL_EX,
                self._backend._lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH
            ):
                raise ValueError(
                    "The length of the provided data is not a multiple of "
                    "the block length."
                )
            else:
                raise self._backend._unknown_error(errors[0])

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
                        algorithm.name),
                    _Reasons.UNSUPPORTED_HASH
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
                                     self._backend._lib.EVP_MAX_MD_SIZE)
        outlen = self._backend._ffi.new("unsigned int *")
        res = self._backend._lib.EVP_DigestFinal_ex(self._ctx, buf, outlen)
        assert res != 0
        assert outlen[0] == self.algorithm.digest_size
        res = self._backend._lib.EVP_MD_CTX_cleanup(self._ctx)
        assert res == 1
        return self._backend._ffi.buffer(buf)[:outlen[0]]


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
                        algorithm.name),
                    _Reasons.UNSUPPORTED_HASH
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
                                     self._backend._lib.EVP_MAX_MD_SIZE)
        outlen = self._backend._ffi.new("unsigned int *")
        res = self._backend._lib.Cryptography_HMAC_Final(
            self._ctx, buf, outlen
        )
        assert res != 0
        assert outlen[0] == self.algorithm.digest_size
        self._backend._lib.HMAC_CTX_cleanup(self._ctx)
        return self._backend._ffi.buffer(buf)[:outlen[0]]


def _get_rsa_pss_salt_length(pss, key_size, digest_size):
    if pss._mgf._salt_length is not None:
        salt = pss._mgf._salt_length
    else:
        salt = pss._salt_length

    if salt is MGF1.MAX_LENGTH or salt is PSS.MAX_LENGTH:
        # bit length - 1 per RFC 3447
        emlen = int(math.ceil((key_size - 1) / 8.0))
        salt_length = emlen - digest_size - 2
        assert salt_length >= 0
        return salt_length
    else:
        return salt


@utils.register_interface(interfaces.AsymmetricSignatureContext)
class _RSASignatureContext(object):
    def __init__(self, backend, private_key, padding, algorithm):
        self._backend = backend
        self._private_key = private_key

        if not isinstance(padding, interfaces.AsymmetricPadding):
            raise TypeError(
                "Expected provider of interfaces.AsymmetricPadding")

        if isinstance(padding, PKCS1v15):
            if self._backend._lib.Cryptography_HAS_PKEY_CTX:
                self._finalize_method = self._finalize_pkey_ctx
                self._padding_enum = self._backend._lib.RSA_PKCS1_PADDING
            else:
                self._finalize_method = self._finalize_pkcs1
        elif isinstance(padding, PSS):
            if not isinstance(padding._mgf, MGF1):
                raise UnsupportedAlgorithm(
                    "Only MGF1 is supported by this backend",
                    _Reasons.UNSUPPORTED_MGF
                )

            # Size of key in bytes - 2 is the maximum
            # PSS signature length (salt length is checked later)
            key_size_bytes = int(math.ceil(private_key.key_size / 8.0))
            if key_size_bytes - algorithm.digest_size - 2 < 0:
                raise ValueError("Digest too large for key size. Use a larger "
                                 "key.")

            if not self._backend.mgf1_hash_supported(padding._mgf._algorithm):
                raise UnsupportedAlgorithm(
                    "When OpenSSL is older than 1.0.1 then only SHA1 is "
                    "supported with MGF1.",
                    _Reasons.UNSUPPORTED_HASH
                )

            if self._backend._lib.Cryptography_HAS_PKEY_CTX:
                self._finalize_method = self._finalize_pkey_ctx
                self._padding_enum = self._backend._lib.RSA_PKCS1_PSS_PADDING
            else:
                self._finalize_method = self._finalize_pss
        else:
            raise UnsupportedAlgorithm(
                "{0} is not supported by this backend".format(padding.name),
                _Reasons.UNSUPPORTED_PADDING
            )

        self._padding = padding
        self._algorithm = algorithm
        self._hash_ctx = _HashContext(backend, self._algorithm)

    def update(self, data):
        if self._hash_ctx is None:
            raise AlreadyFinalized("Context has already been finalized")

        self._hash_ctx.update(data)

    def finalize(self):
        if self._hash_ctx is None:
            raise AlreadyFinalized("Context has already been finalized")

        evp_pkey = self._backend._rsa_private_key_to_evp_pkey(
            self._private_key)

        evp_md = self._backend._lib.EVP_get_digestbyname(
            self._algorithm.name.encode("ascii"))
        assert evp_md != self._backend._ffi.NULL
        pkey_size = self._backend._lib.EVP_PKEY_size(evp_pkey)
        assert pkey_size > 0

        return self._finalize_method(evp_pkey, pkey_size, evp_md)

    def _finalize_pkey_ctx(self, evp_pkey, pkey_size, evp_md):
        pkey_ctx = self._backend._lib.EVP_PKEY_CTX_new(
            evp_pkey, self._backend._ffi.NULL
        )
        assert pkey_ctx != self._backend._ffi.NULL
        pkey_ctx = self._backend._ffi.gc(pkey_ctx,
                                         self._backend._lib.EVP_PKEY_CTX_free)
        res = self._backend._lib.EVP_PKEY_sign_init(pkey_ctx)
        assert res == 1
        res = self._backend._lib.EVP_PKEY_CTX_set_signature_md(
            pkey_ctx, evp_md)
        assert res > 0

        res = self._backend._lib.EVP_PKEY_CTX_set_rsa_padding(
            pkey_ctx, self._padding_enum)
        assert res > 0
        if isinstance(self._padding, PSS):
            res = self._backend._lib.EVP_PKEY_CTX_set_rsa_pss_saltlen(
                pkey_ctx,
                _get_rsa_pss_salt_length(
                    self._padding,
                    self._private_key.key_size,
                    self._hash_ctx.algorithm.digest_size
                )
            )
            assert res > 0

            if self._backend._lib.Cryptography_HAS_MGF1_MD:
                # MGF1 MD is configurable in OpenSSL 1.0.1+
                mgf1_md = self._backend._lib.EVP_get_digestbyname(
                    self._padding._mgf._algorithm.name.encode("ascii"))
                assert mgf1_md != self._backend._ffi.NULL
                res = self._backend._lib.EVP_PKEY_CTX_set_rsa_mgf1_md(
                    pkey_ctx, mgf1_md
                )
                assert res > 0
        data_to_sign = self._hash_ctx.finalize()
        self._hash_ctx = None
        buflen = self._backend._ffi.new("size_t *")
        res = self._backend._lib.EVP_PKEY_sign(
            pkey_ctx,
            self._backend._ffi.NULL,
            buflen,
            data_to_sign,
            len(data_to_sign)
        )
        assert res == 1
        buf = self._backend._ffi.new("unsigned char[]", buflen[0])
        res = self._backend._lib.EVP_PKEY_sign(
            pkey_ctx, buf, buflen, data_to_sign, len(data_to_sign))
        if res != 1:
            errors = self._backend._consume_errors()
            assert errors[0].lib == self._backend._lib.ERR_LIB_RSA
            reason = None
            if (errors[0].reason ==
                    self._backend._lib.RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE):
                reason = ("Salt length too long for key size. Try using "
                          "MAX_LENGTH instead.")
            elif (errors[0].reason ==
                    self._backend._lib.RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY):
                reason = "Digest too large for key size. Use a larger key."
            assert reason is not None
            raise ValueError(reason)

        return self._backend._ffi.buffer(buf)[:]

    def _finalize_pkcs1(self, evp_pkey, pkey_size, evp_md):
        sig_buf = self._backend._ffi.new("char[]", pkey_size)
        sig_len = self._backend._ffi.new("unsigned int *")
        res = self._backend._lib.EVP_SignFinal(
            self._hash_ctx._ctx,
            sig_buf,
            sig_len,
            evp_pkey
        )
        self._hash_ctx.finalize()
        self._hash_ctx = None
        if res == 0:
            errors = self._backend._consume_errors()
            assert errors[0].lib == self._backend._lib.ERR_LIB_RSA
            assert (errors[0].reason ==
                    self._backend._lib.RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY)
            raise ValueError("Digest too large for key size. Use a larger "
                             "key.")

        return self._backend._ffi.buffer(sig_buf)[:sig_len[0]]

    def _finalize_pss(self, evp_pkey, pkey_size, evp_md):
        data_to_sign = self._hash_ctx.finalize()
        self._hash_ctx = None
        padded = self._backend._ffi.new("unsigned char[]", pkey_size)
        rsa_cdata = self._backend._lib.EVP_PKEY_get1_RSA(evp_pkey)
        assert rsa_cdata != self._backend._ffi.NULL
        rsa_cdata = self._backend._ffi.gc(rsa_cdata,
                                          self._backend._lib.RSA_free)
        res = self._backend._lib.RSA_padding_add_PKCS1_PSS(
            rsa_cdata,
            padded,
            data_to_sign,
            evp_md,
            _get_rsa_pss_salt_length(
                self._padding,
                self._private_key.key_size,
                len(data_to_sign)
            )
        )
        if res != 1:
            errors = self._backend._consume_errors()
            assert errors[0].lib == self._backend._lib.ERR_LIB_RSA
            assert (errors[0].reason ==
                    self._backend._lib.RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE)
            raise ValueError("Salt length too long for key size. Try using "
                             "MAX_LENGTH instead.")

        sig_buf = self._backend._ffi.new("char[]", pkey_size)
        sig_len = self._backend._lib.RSA_private_encrypt(
            pkey_size,
            padded,
            sig_buf,
            rsa_cdata,
            self._backend._lib.RSA_NO_PADDING
        )
        assert sig_len != -1
        return self._backend._ffi.buffer(sig_buf)[:sig_len]


@utils.register_interface(interfaces.AsymmetricVerificationContext)
class _RSAVerificationContext(object):
    def __init__(self, backend, public_key, signature, padding, algorithm):
        self._backend = backend
        self._public_key = public_key
        self._signature = signature

        if not isinstance(padding, interfaces.AsymmetricPadding):
            raise TypeError(
                "Expected provider of interfaces.AsymmetricPadding")

        if isinstance(padding, PKCS1v15):
            if self._backend._lib.Cryptography_HAS_PKEY_CTX:
                self._verify_method = self._verify_pkey_ctx
                self._padding_enum = self._backend._lib.RSA_PKCS1_PADDING
            else:
                self._verify_method = self._verify_pkcs1
        elif isinstance(padding, PSS):
            if not isinstance(padding._mgf, MGF1):
                raise UnsupportedAlgorithm(
                    "Only MGF1 is supported by this backend",
                    _Reasons.UNSUPPORTED_MGF
                )

            # Size of key in bytes - 2 is the maximum
            # PSS signature length (salt length is checked later)
            key_size_bytes = int(math.ceil(public_key.key_size / 8.0))
            if key_size_bytes - algorithm.digest_size - 2 < 0:
                raise ValueError(
                    "Digest too large for key size. Check that you have the "
                    "correct key and digest algorithm."
                )

            if not self._backend.mgf1_hash_supported(padding._mgf._algorithm):
                raise UnsupportedAlgorithm(
                    "When OpenSSL is older than 1.0.1 then only SHA1 is "
                    "supported with MGF1.",
                    _Reasons.UNSUPPORTED_HASH
                )

            if self._backend._lib.Cryptography_HAS_PKEY_CTX:
                self._verify_method = self._verify_pkey_ctx
                self._padding_enum = self._backend._lib.RSA_PKCS1_PSS_PADDING
            else:
                self._verify_method = self._verify_pss
        else:
            raise UnsupportedAlgorithm(
                "{0} is not supported by this backend".format(padding.name),
                _Reasons.UNSUPPORTED_PADDING
            )

        self._padding = padding
        self._algorithm = algorithm
        self._hash_ctx = _HashContext(backend, self._algorithm)

    def update(self, data):
        if self._hash_ctx is None:
            raise AlreadyFinalized("Context has already been finalized")

        self._hash_ctx.update(data)

    def verify(self):
        if self._hash_ctx is None:
            raise AlreadyFinalized("Context has already been finalized")

        evp_pkey = self._backend._rsa_public_key_to_evp_pkey(
            self._public_key)

        evp_md = self._backend._lib.EVP_get_digestbyname(
            self._algorithm.name.encode("ascii"))
        assert evp_md != self._backend._ffi.NULL

        self._verify_method(evp_pkey, evp_md)

    def _verify_pkey_ctx(self, evp_pkey, evp_md):
        pkey_ctx = self._backend._lib.EVP_PKEY_CTX_new(
            evp_pkey, self._backend._ffi.NULL
        )
        assert pkey_ctx != self._backend._ffi.NULL
        pkey_ctx = self._backend._ffi.gc(pkey_ctx,
                                         self._backend._lib.EVP_PKEY_CTX_free)
        res = self._backend._lib.EVP_PKEY_verify_init(pkey_ctx)
        assert res == 1
        res = self._backend._lib.EVP_PKEY_CTX_set_signature_md(
            pkey_ctx, evp_md)
        assert res > 0

        res = self._backend._lib.EVP_PKEY_CTX_set_rsa_padding(
            pkey_ctx, self._padding_enum)
        assert res > 0
        if isinstance(self._padding, PSS):
            res = self._backend._lib.EVP_PKEY_CTX_set_rsa_pss_saltlen(
                pkey_ctx,
                _get_rsa_pss_salt_length(
                    self._padding,
                    self._public_key.key_size,
                    self._hash_ctx.algorithm.digest_size
                )
            )
            assert res > 0
            if self._backend._lib.Cryptography_HAS_MGF1_MD:
                # MGF1 MD is configurable in OpenSSL 1.0.1+
                mgf1_md = self._backend._lib.EVP_get_digestbyname(
                    self._padding._mgf._algorithm.name.encode("ascii"))
                assert mgf1_md != self._backend._ffi.NULL
                res = self._backend._lib.EVP_PKEY_CTX_set_rsa_mgf1_md(
                    pkey_ctx, mgf1_md
                )
                assert res > 0

        data_to_verify = self._hash_ctx.finalize()
        self._hash_ctx = None
        res = self._backend._lib.EVP_PKEY_verify(
            pkey_ctx,
            self._signature,
            len(self._signature),
            data_to_verify,
            len(data_to_verify)
        )
        # The previous call can return negative numbers in the event of an
        # error. This is not a signature failure but we need to fail if it
        # occurs.
        assert res >= 0
        if res == 0:
            errors = self._backend._consume_errors()
            assert errors
            raise InvalidSignature

    def _verify_pkcs1(self, evp_pkey, evp_md):
        res = self._backend._lib.EVP_VerifyFinal(
            self._hash_ctx._ctx,
            self._signature,
            len(self._signature),
            evp_pkey
        )
        self._hash_ctx.finalize()
        self._hash_ctx = None
        # The previous call can return negative numbers in the event of an
        # error. This is not a signature failure but we need to fail if it
        # occurs.
        assert res >= 0
        if res == 0:
            errors = self._backend._consume_errors()
            assert errors
            raise InvalidSignature

    def _verify_pss(self, evp_pkey, evp_md):
        pkey_size = self._backend._lib.EVP_PKEY_size(evp_pkey)
        assert pkey_size > 0
        rsa_cdata = self._backend._lib.EVP_PKEY_get1_RSA(evp_pkey)
        assert rsa_cdata != self._backend._ffi.NULL
        rsa_cdata = self._backend._ffi.gc(rsa_cdata,
                                          self._backend._lib.RSA_free)
        buf = self._backend._ffi.new("unsigned char[]", pkey_size)
        res = self._backend._lib.RSA_public_decrypt(
            len(self._signature),
            self._signature,
            buf,
            rsa_cdata,
            self._backend._lib.RSA_NO_PADDING
        )
        if res != pkey_size:
            errors = self._backend._consume_errors()
            assert errors
            raise InvalidSignature

        data_to_verify = self._hash_ctx.finalize()
        self._hash_ctx = None
        res = self._backend._lib.RSA_verify_PKCS1_PSS(
            rsa_cdata,
            data_to_verify,
            evp_md,
            buf,
            _get_rsa_pss_salt_length(
                self._padding,
                self._public_key.key_size,
                len(data_to_verify)
            )
        )
        if res != 1:
            errors = self._backend._consume_errors()
            assert errors
            raise InvalidSignature


@utils.register_interface(interfaces.AsymmetricVerificationContext)
class _DSAVerificationContext(object):
    def __init__(self, backend, public_key, signature, algorithm):
        self._backend = backend
        self._public_key = public_key
        self._signature = signature
        self._algorithm = algorithm

        self._hash_ctx = _HashContext(backend, self._algorithm)

    def update(self, data):
        if self._hash_ctx is None:
            raise AlreadyFinalized("Context has already been finalized")

        self._hash_ctx.update(data)

    def verify(self):
        if self._hash_ctx is None:
            raise AlreadyFinalized("Context has already been finalized")

        self._dsa_cdata = self._backend._dsa_cdata_from_public_key(
            self._public_key)
        self._dsa_cdata = self._backend._ffi.gc(self._dsa_cdata,
                                                self._backend._lib.DSA_free)

        data_to_verify = self._hash_ctx.finalize()
        self._hash_ctx = None

        # The first parameter passed to DSA_verify is unused by OpenSSL but
        # must be an integer.
        res = self._backend._lib.DSA_verify(
            0, data_to_verify, len(data_to_verify), self._signature,
            len(self._signature), self._dsa_cdata)

        if res != 1:
            errors = self._backend._consume_errors()
            assert errors
            if res == -1:
                assert errors[0].lib == self._backend._lib.ERR_LIB_ASN1

            raise InvalidSignature


@utils.register_interface(interfaces.AsymmetricSignatureContext)
class _DSASignatureContext(object):
    def __init__(self, backend, private_key, algorithm):
        self._backend = backend
        self._private_key = private_key
        self._algorithm = algorithm
        self._hash_ctx = _HashContext(backend, self._algorithm)
        self._dsa_cdata = self._backend._dsa_cdata_from_private_key(
            self._private_key)
        self._dsa_cdata = self._backend._ffi.gc(self._dsa_cdata,
                                                self._backend._lib.DSA_free)

    def update(self, data):
        if self._hash_ctx is None:
            raise AlreadyFinalized("Context has already been finalized")

        self._hash_ctx.update(data)

    def finalize(self):
        if self._hash_ctx is None:
            raise AlreadyFinalized("Context has already been finalized")

        data_to_sign = self._hash_ctx.finalize()
        self._hash_ctx = None
        sig_buf_len = self._backend._lib.DSA_size(self._dsa_cdata)
        sig_buf = self._backend._ffi.new("unsigned char[]", sig_buf_len)
        buflen = self._backend._ffi.new("unsigned int *")

        # The first parameter passed to DSA_sign is unused by OpenSSL but
        # must be an integer.
        res = self._backend._lib.DSA_sign(
            0, data_to_sign, len(data_to_sign), sig_buf,
            buflen, self._dsa_cdata)
        assert res == 1
        assert buflen[0]

        return self._backend._ffi.buffer(sig_buf)[:buflen[0]]


@utils.register_interface(interfaces.CMACContext)
class _CMACContext(object):
    def __init__(self, backend, algorithm, ctx=None):
        if not backend.cmac_algorithm_supported(algorithm):
            raise UnsupportedAlgorithm("This backend does not support CMAC",
                                       _Reasons.UNSUPPORTED_CIPHER)

        self._backend = backend
        self._key = algorithm.key
        self._algorithm = algorithm
        self._output_length = algorithm.block_size // 8

        if ctx is None:
            registry = self._backend._cipher_registry
            adapter = registry[type(algorithm), CBC]

            evp_cipher = adapter(self._backend, algorithm, CBC)

            ctx = self._backend._lib.CMAC_CTX_new()

            assert ctx != self._backend._ffi.NULL
            ctx = self._backend._ffi.gc(ctx, self._backend._lib.CMAC_CTX_free)

            self._backend._lib.CMAC_Init(
                ctx, self._key, len(self._key),
                evp_cipher, self._backend._ffi.NULL
            )

        self._ctx = ctx

    def update(self, data):
        res = self._backend._lib.CMAC_Update(self._ctx, data, len(data))
        assert res == 1

    def finalize(self):
        buf = self._backend._ffi.new("unsigned char[]", self._output_length)
        length = self._backend._ffi.new("size_t *", self._output_length)
        res = self._backend._lib.CMAC_Final(
            self._ctx, buf, length
        )
        assert res == 1

        self._ctx = None

        return self._backend._ffi.buffer(buf)[:]

    def copy(self):
        copied_ctx = self._backend._lib.CMAC_CTX_new()
        copied_ctx = self._backend._ffi.gc(
            copied_ctx, self._backend._lib.CMAC_CTX_free
        )
        res = self._backend._lib.CMAC_CTX_copy(
            copied_ctx, self._ctx
        )
        assert res == 1
        return _CMACContext(
            self._backend, self._algorithm, ctx=copied_ctx
        )


backend = Backend()
