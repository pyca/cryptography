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
import warnings

import six

from cryptography import utils
from cryptography.exceptions import (
    AlreadyFinalized, InternalError, InvalidSignature, InvalidTag,
    UnsupportedAlgorithm, _Reasons
)
from cryptography.hazmat.backends.interfaces import (
    CMACBackend, CipherBackend, DSABackend, EllipticCurveBackend, HMACBackend,
    HashBackend, PBKDF2HMACBackend, PKCS8SerializationBackend, RSABackend,
    TraditionalOpenSSLSerializationBackend
)
from cryptography.hazmat.bindings.openssl.binding import Binding
from cryptography.hazmat.primitives import hashes, interfaces
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import (
    MGF1, OAEP, PKCS1v15, PSS
)
from cryptography.hazmat.primitives.ciphers.algorithms import (
    AES, ARC4, Blowfish, CAST5, Camellia, IDEA, SEED, TripleDES
)
from cryptography.hazmat.primitives.ciphers.modes import (
    CBC, CFB, CFB8, CTR, ECB, GCM, OFB
)
from cryptography.hazmat.primitives.interfaces import (
    RSAPrivateKeyWithNumbers, RSAPublicKeyWithNumbers
)


_MemoryBIO = collections.namedtuple("_MemoryBIO", ["bio", "char_ptr"])
_OpenSSLError = collections.namedtuple("_OpenSSLError",
                                       ["code", "lib", "func", "reason"])


@utils.register_interface(CipherBackend)
@utils.register_interface(CMACBackend)
@utils.register_interface(DSABackend)
@utils.register_interface(EllipticCurveBackend)
@utils.register_interface(HashBackend)
@utils.register_interface(HMACBackend)
@utils.register_interface(PBKDF2HMACBackend)
@utils.register_interface(PKCS8SerializationBackend)
@utils.register_interface(RSABackend)
@utils.register_interface(TraditionalOpenSSLSerializationBackend)
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
        Friendly string name of the loaded OpenSSL library. This is not
        necessarily the same version as it was compiled against.

        Example: OpenSSL 1.0.1e 11 Feb 2013
        """
        return self._ffi.string(
            self._lib.SSLeay_version(self._lib.SSLEAY_VERSION)
        ).decode("ascii")

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
        if self._evp_cipher_supported(cipher, mode):
            return True
        elif isinstance(mode, CTR) and isinstance(cipher, AES):
            return True
        else:
            return False

    def _evp_cipher_supported(self, cipher, mode):
        try:
            adapter = self._cipher_registry[type(cipher), type(mode)]
        except KeyError:
            return False
        evp_cipher = adapter(self, cipher, mode)
        return self._ffi.NULL != evp_cipher

    def register_cipher_adapter(self, cipher_cls, mode_cls, adapter):
        if (cipher_cls, mode_cls) in self._cipher_registry:
            raise ValueError("Duplicate registration for: {0} {1}.".format(
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
        self.register_cipher_adapter(
            TripleDES,
            ECB,
            GetCipherByName("des-ede3")
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
        if (isinstance(mode, CTR) and isinstance(cipher, AES)
                and not self._evp_cipher_supported(cipher, mode)):
            # This is needed to provide support for AES CTR mode in OpenSSL
            # 0.9.8. It can be removed when we drop 0.9.8 support (RHEL 5
            # extended life ends 2020).
            return _AESCTRCipherContext(self, cipher, mode)
        else:
            return _CipherContext(self, cipher, mode, _CipherContext._ENCRYPT)

    def create_symmetric_decryption_ctx(self, cipher, mode):
        if (isinstance(mode, CTR) and isinstance(cipher, AES)
                and not self._evp_cipher_supported(cipher, mode)):
            # This is needed to provide support for AES CTR mode in OpenSSL
            # 0.9.8. It can be removed when we drop 0.9.8 support (RHEL 5
            # extended life ends 2020).
            return _AESCTRCipherContext(self, cipher, mode)
        else:
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
                    "SHA1.",
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
            "you should probably file a bug. {1}.".format(
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
        rsa._verify_rsa_parameters(public_exponent, key_size)

        rsa_cdata = self._lib.RSA_new()
        assert rsa_cdata != self._ffi.NULL
        rsa_cdata = self._ffi.gc(rsa_cdata, self._lib.RSA_free)

        bn = self._int_to_bn(public_exponent)
        bn = self._ffi.gc(bn, self._lib.BN_free)

        res = self._lib.RSA_generate_key_ex(
            rsa_cdata, key_size, bn, self._ffi.NULL
        )
        assert res == 1

        return _RSAPrivateKey(self, rsa_cdata)

    def generate_rsa_parameters_supported(self, public_exponent, key_size):
        return (public_exponent >= 3 and public_exponent & 1 != 0 and
                key_size >= 512)

    def load_rsa_private_numbers(self, numbers):
        rsa._check_private_key_components(
            numbers.p,
            numbers.q,
            numbers.d,
            numbers.dmp1,
            numbers.dmq1,
            numbers.iqmp,
            numbers.public_numbers.e,
            numbers.public_numbers.n
        )
        rsa_cdata = self._lib.RSA_new()
        assert rsa_cdata != self._ffi.NULL
        rsa_cdata = self._ffi.gc(rsa_cdata, self._lib.RSA_free)
        rsa_cdata.p = self._int_to_bn(numbers.p)
        rsa_cdata.q = self._int_to_bn(numbers.q)
        rsa_cdata.d = self._int_to_bn(numbers.d)
        rsa_cdata.dmp1 = self._int_to_bn(numbers.dmp1)
        rsa_cdata.dmq1 = self._int_to_bn(numbers.dmq1)
        rsa_cdata.iqmp = self._int_to_bn(numbers.iqmp)
        rsa_cdata.e = self._int_to_bn(numbers.public_numbers.e)
        rsa_cdata.n = self._int_to_bn(numbers.public_numbers.n)
        res = self._lib.RSA_blinding_on(rsa_cdata, self._ffi.NULL)
        assert res == 1

        return _RSAPrivateKey(self, rsa_cdata)

    def load_rsa_public_numbers(self, numbers):
        rsa._check_public_key_components(numbers.e, numbers.n)
        rsa_cdata = self._lib.RSA_new()
        assert rsa_cdata != self._ffi.NULL
        rsa_cdata = self._ffi.gc(rsa_cdata, self._lib.RSA_free)
        rsa_cdata.e = self._int_to_bn(numbers.e)
        rsa_cdata.n = self._int_to_bn(numbers.n)
        res = self._lib.RSA_blinding_on(rsa_cdata, self._ffi.NULL)
        assert res == 1

        return _RSAPublicKey(self, rsa_cdata)

    def _bytes_to_bio(self, data):
        """
        Return a _MemoryBIO namedtuple of (BIO, char*).

        The char* is the storage for the BIO and it must stay alive until the
        BIO is finished with.
        """
        data_char_p = self._ffi.new("char[]", data)
        bio = self._lib.BIO_new_mem_buf(
            data_char_p, len(data)
        )
        assert bio != self._ffi.NULL

        return _MemoryBIO(self._ffi.gc(bio, self._lib.BIO_free), data_char_p)

    def _evp_pkey_to_private_key(self, evp_pkey):
        """
        Return the appropriate type of PrivateKey given an evp_pkey cdata
        pointer.
        """

        type = evp_pkey.type

        if type == self._lib.EVP_PKEY_RSA:
            rsa_cdata = self._lib.EVP_PKEY_get1_RSA(evp_pkey)
            assert rsa_cdata != self._ffi.NULL
            rsa_cdata = self._ffi.gc(rsa_cdata, self._lib.RSA_free)
            return _RSAPrivateKey(self, rsa_cdata)
        elif type == self._lib.EVP_PKEY_DSA:
            dsa_cdata = self._lib.EVP_PKEY_get1_DSA(evp_pkey)
            assert dsa_cdata != self._ffi.NULL
            dsa_cdata = self._ffi.gc(dsa_cdata, self._lib.DSA_free)
            return self._dsa_cdata_to_private_key(dsa_cdata)
        else:
            raise UnsupportedAlgorithm("Unsupported key type.")

    def _dsa_cdata_to_private_key(self, cdata):
        return dsa.DSAPrivateKey(
            modulus=self._bn_to_int(cdata.p),
            subgroup_order=self._bn_to_int(cdata.q),
            generator=self._bn_to_int(cdata.g),
            x=self._bn_to_int(cdata.priv_key),
            y=self._bn_to_int(cdata.pub_key)
        )

    def _pem_password_cb(self, password):
        """
        Generate a pem_password_cb function pointer that copied the password to
        OpenSSL as required and returns the number of bytes copied.

        typedef int pem_password_cb(char *buf, int size,
                                    int rwflag, void *userdata);

        Useful for decrypting PKCS8 files and so on.

        Returns a tuple of (cdata function pointer, callback function).
        """

        def pem_password_cb(buf, size, writing, userdata):
            pem_password_cb.called += 1

            if not password or len(password) >= size:
                return 0
            else:
                pw_buf = self._ffi.buffer(buf, size)
                pw_buf[:len(password)] = password
                return len(password)

        pem_password_cb.called = 0

        return (
            self._ffi.callback("int (char *, int, int, void *)",
                               pem_password_cb),
            pem_password_cb
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
        warnings.warn(
            "create_rsa_signature_ctx is deprecated and will be removed in a "
            "future version.",
            utils.DeprecatedIn05,
            stacklevel=2
        )
        rsa_cdata = self._rsa_cdata_from_private_key(private_key)
        rsa_cdata = self._ffi.gc(rsa_cdata, self._lib.RSA_free)
        key = _RSAPrivateKey(self, rsa_cdata)
        return _RSASignatureContext(self, key, padding, algorithm)

    def create_rsa_verification_ctx(self, public_key, signature, padding,
                                    algorithm):
        warnings.warn(
            "create_rsa_verification_ctx is deprecated and will be removed in "
            "a future version.",
            utils.DeprecatedIn05,
            stacklevel=2
        )
        rsa_cdata = self._rsa_cdata_from_public_key(public_key)
        rsa_cdata = self._ffi.gc(rsa_cdata, self._lib.RSA_free)
        key = _RSAPublicKey(self, rsa_cdata)
        return _RSAVerificationContext(self, key, signature, padding,
                                       algorithm)

    def mgf1_hash_supported(self, algorithm):
        if self._lib.Cryptography_HAS_MGF1_MD:
            return self.hash_supported(algorithm)
        else:
            return isinstance(algorithm, hashes.SHA1)

    def rsa_padding_supported(self, padding):
        if isinstance(padding, PKCS1v15):
            return True
        elif isinstance(padding, PSS) and isinstance(padding._mgf, MGF1):
            return self.mgf1_hash_supported(padding._mgf._algorithm)
        elif isinstance(padding, OAEP) and isinstance(padding._mgf, MGF1):
            return isinstance(padding._mgf._algorithm, hashes.SHA1)
        else:
            return False

    def generate_dsa_parameters(self, key_size):
        if key_size not in (1024, 2048, 3072):
            raise ValueError(
                "Key size must be 1024 or 2048 or 3072 bits.")

        if (self._lib.OPENSSL_VERSION_NUMBER < 0x1000000f and
                key_size > 1024):
            raise ValueError(
                "Key size must be 1024 because OpenSSL < 1.0.0 doesn't "
                "support larger key sizes.")

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
        warnings.warn(
            "decrypt_rsa is deprecated and will be removed in a future "
            "version.",
            utils.DeprecatedIn05,
            stacklevel=2
        )
        rsa_cdata = self._rsa_cdata_from_private_key(private_key)
        rsa_cdata = self._ffi.gc(rsa_cdata, self._lib.RSA_free)
        key = _RSAPrivateKey(self, rsa_cdata)
        return key.decrypt(ciphertext, padding)

    def encrypt_rsa(self, public_key, plaintext, padding):
        warnings.warn(
            "encrypt_rsa is deprecated and will be removed in a future "
            "version.",
            utils.DeprecatedIn05,
            stacklevel=2
        )
        rsa_cdata = self._rsa_cdata_from_public_key(public_key)
        rsa_cdata = self._ffi.gc(rsa_cdata, self._lib.RSA_free)
        key = _RSAPublicKey(self, rsa_cdata)
        return key.encrypt(plaintext, padding)

    def _enc_dec_rsa(self, key, data, padding):
        if isinstance(padding, PKCS1v15):
            padding_enum = self._lib.RSA_PKCS1_PADDING
        elif isinstance(padding, OAEP):
            padding_enum = self._lib.RSA_PKCS1_OAEP_PADDING
            if not isinstance(padding._mgf, MGF1):
                raise UnsupportedAlgorithm(
                    "Only MGF1 is supported by this backend.",
                    _Reasons.UNSUPPORTED_MGF
                )

            if not isinstance(padding._mgf._algorithm, hashes.SHA1):
                raise UnsupportedAlgorithm(
                    "This backend supports only SHA1 inside MGF1 when "
                    "using OAEP.",
                    _Reasons.UNSUPPORTED_HASH
                )

            if padding._label is not None and padding._label != b"":
                raise ValueError("This backend does not support OAEP labels.")

            if not isinstance(padding._algorithm, hashes.SHA1):
                raise UnsupportedAlgorithm(
                    "This backend only supports SHA1 when using OAEP.",
                    _Reasons.UNSUPPORTED_HASH
                )
        else:
            raise UnsupportedAlgorithm(
                "{0} is not supported by this backend.".format(
                    padding.name
                ),
                _Reasons.UNSUPPORTED_PADDING
            )

        if self._lib.Cryptography_HAS_PKEY_CTX:
            return self._enc_dec_rsa_pkey_ctx(key, data, padding_enum)
        else:
            return self._enc_dec_rsa_098(key, data, padding_enum)

    def _enc_dec_rsa_pkey_ctx(self, key, data, padding_enum):
        evp_pkey = key._evp_pkey

        if isinstance(key, _RSAPublicKey):
            init = self._lib.EVP_PKEY_encrypt_init
            crypt = self._lib.Cryptography_EVP_PKEY_encrypt
        else:
            init = self._lib.EVP_PKEY_decrypt_init
            crypt = self._lib.Cryptography_EVP_PKEY_decrypt

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
        rsa_cdata = key._rsa_cdata

        if isinstance(key, _RSAPublicKey):
            crypt = self._lib.RSA_public_encrypt
        else:
            crypt = self._lib.RSA_private_decrypt

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
        if isinstance(key, _RSAPublicKey):
            assert (errors[0].reason ==
                    self._lib.RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE)
            raise ValueError(
                "Data too long for key size. Encrypt less data or use a "
                "larger key size."
            )
        else:
            assert (
                errors[0].reason == self._lib.RSA_R_BLOCK_TYPE_IS_NOT_01 or
                errors[0].reason == self._lib.RSA_R_BLOCK_TYPE_IS_NOT_02
            )
            raise ValueError("Decryption failed.")

    def cmac_algorithm_supported(self, algorithm):
        return (
            self._lib.Cryptography_HAS_CMAC == 1
            and self.cipher_supported(algorithm, CBC(
                b"\x00" * algorithm.block_size))
        )

    def create_cmac_ctx(self, algorithm):
        return _CMACContext(self, algorithm)

    def load_traditional_openssl_pem_private_key(self, data, password):
        # OpenSSLs API for loading PKCS#8 certs can also load the traditional
        # format so we just use that for both of them.

        return self.load_pkcs8_pem_private_key(data, password)

    def load_pkcs8_pem_private_key(self, data, password):
        mem_bio = self._bytes_to_bio(data)

        password_callback, password_func = self._pem_password_cb(password)

        evp_pkey = self._lib.PEM_read_bio_PrivateKey(
            mem_bio.bio,
            self._ffi.NULL,
            password_callback,
            self._ffi.NULL
        )

        if evp_pkey == self._ffi.NULL:
            errors = self._consume_errors()
            if not errors:
                raise ValueError("Could not unserialize key data.")

            if (
                errors[0][1:] == (
                    self._lib.ERR_LIB_PEM,
                    self._lib.PEM_F_PEM_DO_HEADER,
                    self._lib.PEM_R_BAD_PASSWORD_READ
                )
            ) or (
                errors[0][1:] == (
                    self._lib.ERR_LIB_PEM,
                    self._lib.PEM_F_PEM_READ_BIO_PRIVATEKEY,
                    self._lib.PEM_R_BAD_PASSWORD_READ
                )
            ):
                assert not password
                raise TypeError(
                    "Password was not given but private key is encrypted.")

            elif errors[0][1:] == (
                self._lib.ERR_LIB_EVP,
                self._lib.EVP_F_EVP_DECRYPTFINAL_EX,
                self._lib.EVP_R_BAD_DECRYPT
            ):
                raise ValueError(
                    "Bad decrypt. Incorrect password?"
                )

            elif errors[0][1:] in (
                (
                    self._lib.ERR_LIB_PEM,
                    self._lib.PEM_F_PEM_GET_EVP_CIPHER_INFO,
                    self._lib.PEM_R_UNSUPPORTED_ENCRYPTION
                ),

                (
                    self._lib.ERR_LIB_EVP,
                    self._lib.EVP_F_EVP_PBE_CIPHERINIT,
                    self._lib.EVP_R_UNKNOWN_PBE_ALGORITHM
                )
            ):
                raise UnsupportedAlgorithm(
                    "PEM data is encrypted with an unsupported cipher",
                    _Reasons.UNSUPPORTED_CIPHER
                )

            elif any(
                error[1:] == (
                    self._lib.ERR_LIB_EVP,
                    self._lib.EVP_F_EVP_PKCS82PKEY,
                    self._lib.EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM
                )
                for error in errors
            ):
                raise UnsupportedAlgorithm(
                    "Unsupported public key algorithm.",
                    _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
                )

            else:
                assert errors[0][1] in (
                    self._lib.ERR_LIB_EVP,
                    self._lib.ERR_LIB_PEM,
                    self._lib.ERR_LIB_ASN1,
                )
                raise ValueError("Could not unserialize key data.")

        evp_pkey = self._ffi.gc(evp_pkey, self._lib.EVP_PKEY_free)

        if password is not None and password_func.called == 0:
            raise TypeError(
                "Password was given but private key is not encrypted.")

        assert (
            (password is not None and password_func.called == 1) or
            password is None
        )

        return self._evp_pkey_to_private_key(evp_pkey)

    def elliptic_curve_supported(self, curve):
        if self._lib.Cryptography_HAS_EC != 1:
            return False

        curves = self._supported_curves()
        return curve.name.encode("ascii") in curves

    def elliptic_curve_signature_algorithm_supported(
        self, signature_algorithm, curve
    ):
        if self._lib.Cryptography_HAS_EC != 1:
            return False

        # We only support ECDSA right now.
        if not isinstance(signature_algorithm, ec.ECDSA):
            return False

        # Before 0.9.8m OpenSSL can't cope with digests longer than the curve.
        if (
            self._lib.OPENSSL_VERSION_NUMBER < 0x009080df and
            curve.key_size < signature_algorithm.algorithm.digest_size * 8
        ):
            return False

        return self.elliptic_curve_supported(curve)

    def _supported_curves(self):
        if self._lib.Cryptography_HAS_EC != 1:
            return []

        num_curves = self._lib.EC_get_builtin_curves(self._ffi.NULL, 0)
        curve_array = self._ffi.new("EC_builtin_curve[]", num_curves)
        num_curves_assigned = self._lib.EC_get_builtin_curves(
            curve_array, num_curves)
        assert num_curves == num_curves_assigned

        curves = [
            self._ffi.string(self._lib.OBJ_nid2sn(curve.nid)).decode()
            for curve in curve_array
        ]

        curve_aliases = {
            "prime192v1": "secp192r1",
            "prime256v1": "secp256r1"
        }
        return [
            curve_aliases.get(curve, curve)
            for curve in curves
        ]

    def _create_ecdsa_signature_ctx(self, private_key, ecdsa):
        return _ECDSASignatureContext(self, private_key, ecdsa.algorithm)

    def _create_ecdsa_verification_ctx(self, public_key, signature, ecdsa):
        return _ECDSAVerificationContext(self, public_key, signature,
                                         ecdsa.algorithm)

    def generate_elliptic_curve_private_key(self, curve):
        """
        Generate a new private key on the named curve.
        """

        curve_nid = self._elliptic_curve_to_nid(curve)

        ctx = self._lib.EC_KEY_new_by_curve_name(curve_nid)
        assert ctx != self._ffi.NULL
        ctx = self._ffi.gc(ctx, self._lib.EC_KEY_free)

        res = self._lib.EC_KEY_generate_key(ctx)
        assert res == 1

        res = self._lib.EC_KEY_check_key(ctx)
        assert res == 1

        return _EllipticCurvePrivateKey(self, ctx, curve)

    def elliptic_curve_private_key_from_numbers(self, numbers):
        ec_key = self._ec_key_cdata_from_private_numbers(numbers)
        return _EllipticCurvePrivateKey(self, ec_key,
                                        numbers.public_numbers.curve)

    def elliptic_curve_public_key_from_numbers(self, numbers):
        ec_key = self._ec_key_cdata_from_public_numbers(numbers)
        return _EllipticCurvePublicKey(self, ec_key, numbers.curve)

    def _elliptic_curve_to_nid(self, curve):
        """
        Get the NID for a curve name.
        """

        curve_aliases = {
            "secp192r1": "prime192v1",
            "secp256r1": "prime256v1"
        }

        curve_name = curve_aliases.get(curve.name, curve.name)

        curve_nid = self._lib.OBJ_sn2nid(curve_name.encode())
        if curve_nid == self._lib.NID_undef:
            raise UnsupportedAlgorithm(
                "{0} is not a supported elliptic curve".format(curve.name),
                _Reasons.UNSUPPORTED_ELLIPTIC_CURVE
            )
        return curve_nid

    def _ec_key_cdata_from_private_numbers(self, numbers):
        """
        Build an EC_KEY from a private key object.
        """

        public = numbers.public_numbers

        curve_nid = self._elliptic_curve_to_nid(public.curve)

        ctx = self._lib.EC_KEY_new_by_curve_name(curve_nid)
        assert ctx != self._ffi.NULL
        ctx = self._ffi.gc(ctx, self._lib.EC_KEY_free)

        ctx = self._ec_key_set_public_key_affine_coordinates(
            ctx, public.x, public.y)

        res = self._lib.EC_KEY_set_private_key(
            ctx, self._int_to_bn(numbers.private_value))
        assert res == 1

        return ctx

    def _ec_key_cdata_from_public_numbers(self, numbers):
        """
        Build an EC_KEY from a public key object.
        """

        curve_nid = self._elliptic_curve_to_nid(numbers.curve)

        ctx = self._lib.EC_KEY_new_by_curve_name(curve_nid)
        assert ctx != self._ffi.NULL
        ctx = self._ffi.gc(ctx, self._lib.EC_KEY_free)

        ctx = self._ec_key_set_public_key_affine_coordinates(
            ctx, numbers.x, numbers.y)

        return ctx

    def _public_ec_key_from_private_ec_key(self, private_key_cdata):
        """
        Copy the public portions out of one EC key into a new one.
        """

        group = self._lib.EC_KEY_get0_group(private_key_cdata)
        assert group != self._ffi.NULL

        curve_nid = self._lib.EC_GROUP_get_curve_name(group)

        ctx = self._lib.EC_KEY_new_by_curve_name(curve_nid)
        assert ctx != self._ffi.NULL
        ctx = self._ffi.gc(ctx, self._lib.EC_KEY_free)

        point = self._lib.EC_KEY_get0_public_key(private_key_cdata)
        assert point != self._ffi.NULL

        res = self._lib.EC_KEY_set_public_key(ctx, point)
        assert res == 1

        return ctx

    def _ec_key_set_public_key_affine_coordinates(self, ctx, x, y):
        """
        This is a port of EC_KEY_set_public_key_affine_coordinates that was
        added in 1.0.1.

        Sets the public key point in the EC_KEY context to the affine x and y
        values.
        """

        assert ctx != self._ffi.NULL

        bn_x = self._int_to_bn(x)
        bn_y = self._int_to_bn(y)

        nid_two_field = self._lib.OBJ_sn2nid(b"characteristic-two-field")
        assert nid_two_field != self._lib.NID_undef

        bn_ctx = self._lib.BN_CTX_new()
        assert bn_ctx != self._ffi.NULL
        bn_ctx = self._ffi.gc(bn_ctx, self._lib.BN_CTX_free)

        group = self._lib.EC_KEY_get0_group(ctx)
        assert group != self._ffi.NULL

        point = self._lib.EC_POINT_new(group)
        assert point != self._ffi.NULL
        point = self._ffi.gc(point, self._lib.EC_POINT_free)

        method = self._lib.EC_GROUP_method_of(group)
        assert method != self._ffi.NULL

        nid = self._lib.EC_METHOD_get_field_type(method)
        assert nid != self._lib.NID_undef

        check_x = self._lib.BN_CTX_get(bn_ctx)
        check_y = self._lib.BN_CTX_get(bn_ctx)

        if nid == nid_two_field and self._lib.Cryptography_HAS_EC2M:
            set_func = self._lib.EC_POINT_set_affine_coordinates_GF2m
            get_func = self._lib.EC_POINT_get_affine_coordinates_GF2m
        else:
            set_func = self._lib.EC_POINT_set_affine_coordinates_GFp
            get_func = self._lib.EC_POINT_get_affine_coordinates_GFp

        assert set_func and get_func

        res = set_func(group, point, bn_x, bn_y, bn_ctx)
        assert res == 1

        res = get_func(group, point, check_x, check_y, bn_ctx)
        assert res == 1

        assert (
            self._lib.BN_cmp(bn_x, check_x) == 0 and
            self._lib.BN_cmp(bn_y, check_y) == 0
        )

        res = self._lib.EC_KEY_set_public_key(ctx, point)
        assert res == 1

        res = self._lib.EC_KEY_check_key(ctx)
        assert res == 1

        return ctx


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
                "by this backend.".format(
                    cipher.name, mode.name if mode else mode),
                _Reasons.UNSUPPORTED_CIPHER
            )

        evp_cipher = adapter(self._backend, cipher, mode)
        if evp_cipher == self._backend._ffi.NULL:
            raise UnsupportedAlgorithm(
                "cipher {0} in {1} mode is not supported "
                "by this backend.".format(
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


@utils.register_interface(interfaces.CipherContext)
class _AESCTRCipherContext(object):
    """
    This is needed to provide support for AES CTR mode in OpenSSL 0.9.8. It can
    be removed when we drop 0.9.8 support (RHEL5 extended life ends 2020).
    """
    def __init__(self, backend, cipher, mode):
        self._backend = backend

        self._key = self._backend._ffi.new("AES_KEY *")
        assert self._key != self._backend._ffi.NULL
        res = self._backend._lib.AES_set_encrypt_key(
            cipher.key, len(cipher.key) * 8, self._key
        )
        assert res == 0
        self._ecount = self._backend._ffi.new("char[]", 16)
        self._nonce = self._backend._ffi.new("char[16]", mode.nonce)
        self._num = self._backend._ffi.new("unsigned int *", 0)

    def update(self, data):
        buf = self._backend._ffi.new("unsigned char[]", len(data))
        self._backend._lib.AES_ctr128_encrypt(
            data, buf, len(data), self._key, self._nonce,
            self._ecount, self._num
        )
        return self._backend._ffi.buffer(buf)[:]

    def finalize(self):
        self._key = None
        self._ecount = None
        self._nonce = None
        self._num = None
        return b""


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
                    "{0} is not a supported hash on this backend.".format(
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
                    "{0} is not a supported hash on this backend.".format(
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
                "Expected provider of interfaces.AsymmetricPadding.")

        self._pkey_size = self._backend._lib.EVP_PKEY_size(
            self._private_key._evp_pkey
        )

        if isinstance(padding, PKCS1v15):
            if self._backend._lib.Cryptography_HAS_PKEY_CTX:
                self._finalize_method = self._finalize_pkey_ctx
                self._padding_enum = self._backend._lib.RSA_PKCS1_PADDING
            else:
                self._finalize_method = self._finalize_pkcs1
        elif isinstance(padding, PSS):
            if not isinstance(padding._mgf, MGF1):
                raise UnsupportedAlgorithm(
                    "Only MGF1 is supported by this backend.",
                    _Reasons.UNSUPPORTED_MGF
                )

            # Size of key in bytes - 2 is the maximum
            # PSS signature length (salt length is checked later)
            assert self._pkey_size > 0
            if self._pkey_size - algorithm.digest_size - 2 < 0:
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
                "{0} is not supported by this backend.".format(padding.name),
                _Reasons.UNSUPPORTED_PADDING
            )

        self._padding = padding
        self._algorithm = algorithm
        self._hash_ctx = hashes.Hash(self._algorithm, self._backend)

    def update(self, data):
        self._hash_ctx.update(data)

    def finalize(self):
        evp_md = self._backend._lib.EVP_get_digestbyname(
            self._algorithm.name.encode("ascii"))
        assert evp_md != self._backend._ffi.NULL

        return self._finalize_method(evp_md)

    def _finalize_pkey_ctx(self, evp_md):
        pkey_ctx = self._backend._lib.EVP_PKEY_CTX_new(
            self._private_key._evp_pkey, self._backend._ffi.NULL
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

    def _finalize_pkcs1(self, evp_md):
        if self._hash_ctx._ctx is None:
            raise AlreadyFinalized("Context has already been finalized.")

        sig_buf = self._backend._ffi.new("char[]", self._pkey_size)
        sig_len = self._backend._ffi.new("unsigned int *")
        res = self._backend._lib.EVP_SignFinal(
            self._hash_ctx._ctx._ctx,
            sig_buf,
            sig_len,
            self._private_key._evp_pkey
        )
        self._hash_ctx.finalize()
        if res == 0:
            errors = self._backend._consume_errors()
            assert errors[0].lib == self._backend._lib.ERR_LIB_RSA
            assert (errors[0].reason ==
                    self._backend._lib.RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY)
            raise ValueError("Digest too large for key size. Use a larger "
                             "key.")

        return self._backend._ffi.buffer(sig_buf)[:sig_len[0]]

    def _finalize_pss(self, evp_md):
        data_to_sign = self._hash_ctx.finalize()
        padded = self._backend._ffi.new("unsigned char[]", self._pkey_size)
        res = self._backend._lib.RSA_padding_add_PKCS1_PSS(
            self._private_key._rsa_cdata,
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

        sig_buf = self._backend._ffi.new("char[]", self._pkey_size)
        sig_len = self._backend._lib.RSA_private_encrypt(
            self._pkey_size,
            padded,
            sig_buf,
            self._private_key._rsa_cdata,
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
                "Expected provider of interfaces.AsymmetricPadding.")

        self._pkey_size = self._backend._lib.EVP_PKEY_size(
            self._public_key._evp_pkey
        )

        if isinstance(padding, PKCS1v15):
            if self._backend._lib.Cryptography_HAS_PKEY_CTX:
                self._verify_method = self._verify_pkey_ctx
                self._padding_enum = self._backend._lib.RSA_PKCS1_PADDING
            else:
                self._verify_method = self._verify_pkcs1
        elif isinstance(padding, PSS):
            if not isinstance(padding._mgf, MGF1):
                raise UnsupportedAlgorithm(
                    "Only MGF1 is supported by this backend.",
                    _Reasons.UNSUPPORTED_MGF
                )

            # Size of key in bytes - 2 is the maximum
            # PSS signature length (salt length is checked later)
            assert self._pkey_size > 0
            if self._pkey_size - algorithm.digest_size - 2 < 0:
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
                "{0} is not supported by this backend.".format(padding.name),
                _Reasons.UNSUPPORTED_PADDING
            )

        self._padding = padding
        self._algorithm = algorithm
        self._hash_ctx = hashes.Hash(self._algorithm, self._backend)

    def update(self, data):
        self._hash_ctx.update(data)

    def verify(self):
        evp_md = self._backend._lib.EVP_get_digestbyname(
            self._algorithm.name.encode("ascii"))
        assert evp_md != self._backend._ffi.NULL

        self._verify_method(evp_md)

    def _verify_pkey_ctx(self, evp_md):
        pkey_ctx = self._backend._lib.EVP_PKEY_CTX_new(
            self._public_key._evp_pkey, self._backend._ffi.NULL
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

    def _verify_pkcs1(self, evp_md):
        if self._hash_ctx._ctx is None:
            raise AlreadyFinalized("Context has already been finalized.")

        res = self._backend._lib.EVP_VerifyFinal(
            self._hash_ctx._ctx._ctx,
            self._signature,
            len(self._signature),
            self._public_key._evp_pkey
        )
        self._hash_ctx.finalize()
        # The previous call can return negative numbers in the event of an
        # error. This is not a signature failure but we need to fail if it
        # occurs.
        assert res >= 0
        if res == 0:
            errors = self._backend._consume_errors()
            assert errors
            raise InvalidSignature

    def _verify_pss(self, evp_md):
        buf = self._backend._ffi.new("unsigned char[]", self._pkey_size)
        res = self._backend._lib.RSA_public_decrypt(
            len(self._signature),
            self._signature,
            buf,
            self._public_key._rsa_cdata,
            self._backend._lib.RSA_NO_PADDING
        )
        if res != self._pkey_size:
            errors = self._backend._consume_errors()
            assert errors
            raise InvalidSignature

        data_to_verify = self._hash_ctx.finalize()
        res = self._backend._lib.RSA_verify_PKCS1_PSS(
            self._public_key._rsa_cdata,
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

        self._hash_ctx = hashes.Hash(self._algorithm, self._backend)

    def update(self, data):
        self._hash_ctx.update(data)

    def verify(self):
        self._dsa_cdata = self._backend._dsa_cdata_from_public_key(
            self._public_key)
        self._dsa_cdata = self._backend._ffi.gc(self._dsa_cdata,
                                                self._backend._lib.DSA_free)

        data_to_verify = self._hash_ctx.finalize()

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
        self._hash_ctx = hashes.Hash(self._algorithm, self._backend)
        self._dsa_cdata = self._backend._dsa_cdata_from_private_key(
            self._private_key)
        self._dsa_cdata = self._backend._ffi.gc(self._dsa_cdata,
                                                self._backend._lib.DSA_free)

    def update(self, data):
        self._hash_ctx.update(data)

    def finalize(self):
        data_to_sign = self._hash_ctx.finalize()
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
            raise UnsupportedAlgorithm("This backend does not support CMAC.",
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


def _truncate_digest_for_ecdsa(ec_key_cdata, digest, backend):
    _lib = backend._lib
    _ffi = backend._ffi

    digest_len = len(digest)

    group = _lib.EC_KEY_get0_group(ec_key_cdata)

    bn_ctx = _lib.BN_CTX_new()
    assert bn_ctx != _ffi.NULL
    bn_ctx = _ffi.gc(bn_ctx, _lib.BN_CTX_free)

    order = _lib.BN_CTX_get(bn_ctx)
    assert order != _ffi.NULL

    res = _lib.EC_GROUP_get_order(group, order, bn_ctx)
    assert res == 1

    order_bits = _lib.BN_num_bits(order)

    if 8 * digest_len > order_bits:
        digest_len = (order_bits + 7) // 8
        digest = digest[:digest_len]

    if 8 * digest_len > order_bits:
        rshift = 8 - (order_bits & 0x7)
        assert rshift > 0 and rshift < 8

        mask = 0xFF >> rshift << rshift

        # Set the bottom rshift bits to 0
        digest = digest[:-1] + six.int2byte(six.byte2int(digest[-1]) & mask)

    return digest


@utils.register_interface(interfaces.AsymmetricSignatureContext)
class _ECDSASignatureContext(object):
    def __init__(self, backend, private_key, algorithm):
        self._backend = backend
        self._private_key = private_key
        self._digest = hashes.Hash(algorithm, backend)

    def update(self, data):
        self._digest.update(data)

    def finalize(self):
        ec_key = self._private_key._ec_key

        digest = self._digest.finalize()

        digest = _truncate_digest_for_ecdsa(ec_key, digest, self._backend)

        max_size = self._backend._lib.ECDSA_size(ec_key)
        assert max_size > 0

        sigbuf = self._backend._ffi.new("char[]", max_size)
        siglen_ptr = self._backend._ffi.new("unsigned int[]", 1)
        res = self._backend._lib.ECDSA_sign(
            0,
            digest,
            len(digest),
            sigbuf,
            siglen_ptr,
            ec_key
        )
        assert res == 1
        return self._backend._ffi.buffer(sigbuf)[:siglen_ptr[0]]


@utils.register_interface(interfaces.AsymmetricVerificationContext)
class _ECDSAVerificationContext(object):
    def __init__(self, backend, public_key, signature, algorithm):
        self._backend = backend
        self._public_key = public_key
        self._signature = signature
        self._digest = hashes.Hash(algorithm, backend)

    def update(self, data):
        self._digest.update(data)

    def verify(self):
        ec_key = self._public_key._ec_key

        digest = self._digest.finalize()

        digest = _truncate_digest_for_ecdsa(ec_key, digest, self._backend)

        res = self._backend._lib.ECDSA_verify(
            0,
            digest,
            len(digest),
            self._signature,
            len(self._signature),
            ec_key
        )
        if res != 1:
            self._backend._consume_errors()
            raise InvalidSignature
        return True


@utils.register_interface(interfaces.EllipticCurvePrivateKey)
class _EllipticCurvePrivateKey(object):
    def __init__(self, backend, ec_key_cdata, curve):
        self._backend = backend
        self._ec_key = ec_key_cdata
        self._curve = curve

    @property
    def curve(self):
        return self._curve

    def signer(self, signature_algorithm):
        if isinstance(signature_algorithm, ec.ECDSA):
            return self._backend._create_ecdsa_signature_ctx(
                self, signature_algorithm)
        else:
            raise UnsupportedAlgorithm(
                "Unsupported elliptic curve signature algorithm.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def public_key(self):
        public_ec_key = self._backend._public_ec_key_from_private_ec_key(
            self._ec_key
        )

        return _EllipticCurvePublicKey(
            self._backend, public_ec_key, self._curve)


@utils.register_interface(interfaces.EllipticCurvePublicKey)
class _EllipticCurvePublicKey(object):
    def __init__(self, backend, ec_key_cdata, curve):
        self._backend = backend
        self._ec_key = ec_key_cdata
        self._curve = curve

    @property
    def curve(self):
        return self._curve

    def verifier(self, signature, signature_algorithm):
        if isinstance(signature_algorithm, ec.ECDSA):
            return self._backend._create_ecdsa_verification_ctx(
                self, signature, signature_algorithm)
        else:
            raise UnsupportedAlgorithm(
                "Unsupported elliptic curve signature algorithm.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)


@utils.register_interface(RSAPrivateKeyWithNumbers)
class _RSAPrivateKey(object):
    def __init__(self, backend, rsa_cdata):
        self._backend = backend
        self._rsa_cdata = rsa_cdata

        evp_pkey = self._backend._lib.EVP_PKEY_new()
        assert evp_pkey != self._backend._ffi.NULL
        evp_pkey = self._backend._ffi.gc(
            evp_pkey, self._backend._lib.EVP_PKEY_free
        )
        res = self._backend._lib.EVP_PKEY_set1_RSA(evp_pkey, rsa_cdata)
        assert res == 1
        self._evp_pkey = evp_pkey

        self.key_size = self._backend._lib.BN_num_bits(self._rsa_cdata.n)

    def signer(self, padding, algorithm):
        return _RSASignatureContext(self._backend, self, padding, algorithm)

    def decrypt(self, ciphertext, padding):
        key_size_bytes = int(math.ceil(self.key_size / 8.0))
        if key_size_bytes != len(ciphertext):
            raise ValueError("Ciphertext length must be equal to key size.")

        return self._backend._enc_dec_rsa(self, ciphertext, padding)

    def public_key(self):
        ctx = self._backend._lib.RSA_new()
        assert ctx != self._backend._ffi.NULL
        ctx = self._backend._ffi.gc(ctx, self._backend._lib.RSA_free)
        ctx.e = self._backend._lib.BN_dup(self._rsa_cdata.e)
        ctx.n = self._backend._lib.BN_dup(self._rsa_cdata.n)
        res = self._backend._lib.RSA_blinding_on(ctx, self._backend._ffi.NULL)
        assert res == 1
        return _RSAPublicKey(self._backend, ctx)

    def private_numbers(self):
        return rsa.RSAPrivateNumbers(
            p=self._backend._bn_to_int(self._rsa_cdata.p),
            q=self._backend._bn_to_int(self._rsa_cdata.q),
            d=self._backend._bn_to_int(self._rsa_cdata.d),
            dmp1=self._backend._bn_to_int(self._rsa_cdata.dmp1),
            dmq1=self._backend._bn_to_int(self._rsa_cdata.dmq1),
            iqmp=self._backend._bn_to_int(self._rsa_cdata.iqmp),
            public_numbers=rsa.RSAPublicNumbers(
                e=self._backend._bn_to_int(self._rsa_cdata.e),
                n=self._backend._bn_to_int(self._rsa_cdata.n),
            )
        )


@utils.register_interface(RSAPublicKeyWithNumbers)
class _RSAPublicKey(object):
    def __init__(self, backend, rsa_cdata):
        self._backend = backend
        self._rsa_cdata = rsa_cdata

        evp_pkey = self._backend._lib.EVP_PKEY_new()
        assert evp_pkey != self._backend._ffi.NULL
        evp_pkey = self._backend._ffi.gc(
            evp_pkey, self._backend._lib.EVP_PKEY_free
        )
        res = self._backend._lib.EVP_PKEY_set1_RSA(evp_pkey, rsa_cdata)
        assert res == 1
        self._evp_pkey = evp_pkey

        self.key_size = self._backend._lib.BN_num_bits(self._rsa_cdata.n)

    def verifier(self, signature, padding, algorithm):
        return _RSAVerificationContext(
            self._backend, self, signature, padding, algorithm
        )

    def encrypt(self, plaintext, padding):
        return self._backend._enc_dec_rsa(self, plaintext, padding)

    def public_numbers(self):
        return rsa.RSAPublicNumbers(
            e=self._backend._bn_to_int(self._rsa_cdata.e),
            n=self._backend._bn_to_int(self._rsa_cdata.n),
        )


backend = Backend()
