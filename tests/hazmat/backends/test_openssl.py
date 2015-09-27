# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os
import subprocess
import sys
import textwrap

import pretend

import pytest

from cryptography import utils
from cryptography.exceptions import InternalError, _Reasons
from cryptography.hazmat.backends.interfaces import RSABackend
from cryptography.hazmat.backends.openssl.backend import (
    Backend, backend
)
from cryptography.hazmat.backends.openssl.ec import _sn_to_elliptic_curve
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding
from cryptography.hazmat.primitives.ciphers import (
    BlockCipherAlgorithm, Cipher, CipherAlgorithm
)
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC, CTR, Mode

from ..primitives.fixtures_dsa import DSA_KEY_2048
from ..primitives.fixtures_rsa import RSA_KEY_2048, RSA_KEY_512
from ..primitives.test_ec import _skip_curve_unsupported
from ...utils import load_vectors_from_file, raises_unsupported_algorithm


def skip_if_libre_ssl(openssl_version):
    if u'LibreSSL' in openssl_version:
        pytest.skip("LibreSSL hard-codes RAND_bytes to use arc4random.")


class TestLibreSkip(object):
    def test_skip_no(self):
        assert skip_if_libre_ssl(u"OpenSSL 0.9.8zf 19 Mar 2015") is None

    def test_skip_yes(self):
        with pytest.raises(pytest.skip.Exception):
            skip_if_libre_ssl(u"LibreSSL 2.1.6")


@utils.register_interface(Mode)
class DummyMode(object):
    name = "dummy-mode"

    def validate_for_algorithm(self, algorithm):
        pass


@utils.register_interface(CipherAlgorithm)
class DummyCipher(object):
    name = "dummy-cipher"
    key_size = None


@utils.register_interface(padding.AsymmetricPadding)
class DummyPadding(object):
    name = "dummy-cipher"


@utils.register_interface(hashes.HashAlgorithm)
class DummyHash(object):
    name = "dummy-hash"
    block_size = None
    digest_size = None


class DummyMGF(object):
    _salt_length = 0


class TestOpenSSL(object):
    def test_backend_exists(self):
        assert backend

    def test_openssl_version_text(self):
        """
        This test checks the value of OPENSSL_VERSION_TEXT.

        Unfortunately, this define does not appear to have a
        formal content definition, so for now we'll test to see
        if it starts with OpenSSL or LibreSSL as that appears
        to be true for every OpenSSL-alike.
        """
        assert (
            backend.openssl_version_text().startswith("OpenSSL") or
            backend.openssl_version_text().startswith("LibreSSL")
        )

    def test_supports_cipher(self):
        assert backend.cipher_supported(None, None) is False

    def test_aes_ctr_always_available(self):
        # AES CTR should always be available in both 0.9.8 and 1.0.0+
        assert backend.cipher_supported(AES(b"\x00" * 16),
                                        CTR(b"\x00" * 16)) is True

    def test_register_duplicate_cipher_adapter(self):
        with pytest.raises(ValueError):
            backend.register_cipher_adapter(AES, CBC, None)

    @pytest.mark.parametrize("mode", [DummyMode(), None])
    def test_nonexistent_cipher(self, mode):
        b = Backend()
        b.register_cipher_adapter(
            DummyCipher,
            type(mode),
            lambda backend, cipher, mode: backend._ffi.NULL
        )
        cipher = Cipher(
            DummyCipher(), mode, backend=b,
        )
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_CIPHER):
            cipher.encryptor()

    def test_openssl_assert(self):
        backend.openssl_assert(True)
        with pytest.raises(InternalError):
            backend.openssl_assert(False)

    def test_consume_errors(self):
        for i in range(10):
            backend._lib.ERR_put_error(backend._lib.ERR_LIB_EVP, 0, 0,
                                       b"test_openssl.py", -1)

        assert backend._lib.ERR_peek_error() != 0

        errors = backend._consume_errors()

        assert backend._lib.ERR_peek_error() == 0
        assert len(errors) == 10

    def test_ssl_ciphers_registered(self):
        meth = backend._lib.TLSv1_method()
        ctx = backend._lib.SSL_CTX_new(meth)
        assert ctx != backend._ffi.NULL
        backend._lib.SSL_CTX_free(ctx)

    def test_evp_ciphers_registered(self):
        cipher = backend._lib.EVP_get_cipherbyname(b"aes-256-cbc")
        assert cipher != backend._ffi.NULL

    def test_error_strings_loaded(self):
        # returns a value in a static buffer
        err = backend._lib.ERR_error_string(101183626, backend._ffi.NULL)
        assert backend._ffi.string(err) == (
            b"error:0607F08A:digital envelope routines:EVP_EncryptFinal_ex:"
            b"data not multiple of block length"
        )

    def test_unknown_error_in_cipher_finalize(self):
        cipher = Cipher(AES(b"\0" * 16), CBC(b"\0" * 16), backend=backend)
        enc = cipher.encryptor()
        enc.update(b"\0")
        backend._lib.ERR_put_error(0, 0, 1,
                                   b"test_openssl.py", -1)
        with pytest.raises(InternalError):
            enc.finalize()

    def test_derive_pbkdf2_raises_unsupported_on_old_openssl(self):
        if backend.pbkdf2_hmac_supported(hashes.SHA256()):
            pytest.skip("Requires an older OpenSSL")
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            backend.derive_pbkdf2_hmac(hashes.SHA256(), 10, b"", 1000, b"")

    @pytest.mark.skipif(
        backend._lib.OPENSSL_VERSION_NUMBER >= 0x1000000f,
        reason="Requires an older OpenSSL. Must be < 1.0.0"
    )
    def test_large_key_size_on_old_openssl(self):
        with pytest.raises(ValueError):
            dsa.generate_parameters(2048, backend=backend)

        with pytest.raises(ValueError):
            dsa.generate_parameters(3072, backend=backend)

    @pytest.mark.skipif(
        backend._lib.OPENSSL_VERSION_NUMBER < 0x1000000f,
        reason="Requires a newer OpenSSL. Must be >= 1.0.0"
    )
    def test_large_key_size_on_new_openssl(self):
        parameters = dsa.generate_parameters(2048, backend)
        param_num = parameters.parameter_numbers()
        assert utils.bit_length(param_num.p) == 2048
        parameters = dsa.generate_parameters(3072, backend)
        param_num = parameters.parameter_numbers()
        assert utils.bit_length(param_num.p) == 3072

    def test_int_to_bn(self):
        value = (2 ** 4242) - 4242
        bn = backend._int_to_bn(value)
        assert bn != backend._ffi.NULL
        bn = backend._ffi.gc(bn, backend._lib.BN_free)

        assert bn
        assert backend._bn_to_int(bn) == value

    def test_int_to_bn_inplace(self):
        value = (2 ** 4242) - 4242
        bn_ptr = backend._lib.BN_new()
        assert bn_ptr != backend._ffi.NULL
        bn_ptr = backend._ffi.gc(bn_ptr, backend._lib.BN_free)
        bn = backend._int_to_bn(value, bn_ptr)

        assert bn == bn_ptr
        assert backend._bn_to_int(bn_ptr) == value

    def test_bn_to_int(self):
        bn = backend._int_to_bn(0)
        assert backend._bn_to_int(bn) == 0

    def test_actual_osrandom_bytes(self, monkeypatch):
        skip_if_libre_ssl(backend.openssl_version_text())
        sample_data = (b"\x01\x02\x03\x04" * 4)
        length = len(sample_data)

        def notrandom(size):
            assert size == length
            return sample_data
        monkeypatch.setattr(os, "urandom", notrandom)
        buf = backend._ffi.new("char[]", length)
        backend._lib.RAND_bytes(buf, length)
        assert backend._ffi.buffer(buf)[0:length] == sample_data


class TestOpenSSLRandomEngine(object):
    def teardown_method(self, method):
        # we need to reset state to being default. backend is a shared global
        # for all these tests.
        backend.activate_osrandom_engine()
        current_default = backend._lib.ENGINE_get_default_RAND()
        name = backend._lib.ENGINE_get_name(current_default)
        assert name == backend._binding._osrandom_engine_name

    def test_osrandom_engine_is_default(self, tmpdir):
        engine_printer = textwrap.dedent(
            """
            import sys
            from cryptography.hazmat.backends.openssl.backend import backend

            e = backend._lib.ENGINE_get_default_RAND()
            name = backend._lib.ENGINE_get_name(e)
            sys.stdout.write(backend._ffi.string(name).decode('ascii'))
            res = backend._lib.ENGINE_free(e)
            assert res == 1
            """
        )
        engine_name = tmpdir.join('engine_name')

        # If we're running tests via ``python setup.py test`` in a clean
        # environment then all of our dependencies are going to be installed
        # into either the current directory or the .eggs directory. However the
        # subprocess won't know to activate these dependencies, so we'll get it
        # to do so by passing our entire sys.path into the subprocess via the
        # PYTHONPATH environment variable.
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(sys.path)

        with engine_name.open('w') as out:
            subprocess.check_call(
                [sys.executable, "-c", engine_printer],
                env=env,
                stdout=out
            )

        osrandom_engine_name = backend._ffi.string(
            backend._binding._osrandom_engine_name
        )

        assert engine_name.read().encode('ascii') == osrandom_engine_name

    def test_osrandom_sanity_check(self):
        # This test serves as a check against catastrophic failure.
        buf = backend._ffi.new("char[]", 500)
        res = backend._lib.RAND_bytes(buf, 500)
        assert res == 1
        assert backend._ffi.buffer(buf)[:] != "\x00" * 500

    def test_activate_osrandom_no_default(self):
        backend.activate_builtin_random()
        e = backend._lib.ENGINE_get_default_RAND()
        assert e == backend._ffi.NULL
        backend.activate_osrandom_engine()
        e = backend._lib.ENGINE_get_default_RAND()
        name = backend._lib.ENGINE_get_name(e)
        assert name == backend._binding._osrandom_engine_name
        res = backend._lib.ENGINE_free(e)
        assert res == 1

    def test_activate_builtin_random(self):
        e = backend._lib.ENGINE_get_default_RAND()
        assert e != backend._ffi.NULL
        name = backend._lib.ENGINE_get_name(e)
        assert name == backend._binding._osrandom_engine_name
        res = backend._lib.ENGINE_free(e)
        assert res == 1
        backend.activate_builtin_random()
        e = backend._lib.ENGINE_get_default_RAND()
        assert e == backend._ffi.NULL

    def test_activate_builtin_random_already_active(self):
        backend.activate_builtin_random()
        e = backend._lib.ENGINE_get_default_RAND()
        assert e == backend._ffi.NULL
        backend.activate_builtin_random()
        e = backend._lib.ENGINE_get_default_RAND()
        assert e == backend._ffi.NULL

    def test_activate_osrandom_already_default(self):
        e = backend._lib.ENGINE_get_default_RAND()
        name = backend._lib.ENGINE_get_name(e)
        assert name == backend._binding._osrandom_engine_name
        res = backend._lib.ENGINE_free(e)
        assert res == 1
        backend.activate_osrandom_engine()
        e = backend._lib.ENGINE_get_default_RAND()
        name = backend._lib.ENGINE_get_name(e)
        assert name == backend._binding._osrandom_engine_name
        res = backend._lib.ENGINE_free(e)
        assert res == 1


class TestOpenSSLRSA(object):
    def test_generate_rsa_parameters_supported(self):
        assert backend.generate_rsa_parameters_supported(1, 1024) is False
        assert backend.generate_rsa_parameters_supported(4, 1024) is False
        assert backend.generate_rsa_parameters_supported(3, 1024) is True
        assert backend.generate_rsa_parameters_supported(3, 511) is False

    def test_generate_bad_public_exponent(self):
        with pytest.raises(ValueError):
            backend.generate_rsa_private_key(public_exponent=1, key_size=2048)

        with pytest.raises(ValueError):
            backend.generate_rsa_private_key(public_exponent=4, key_size=2048)

    def test_cant_generate_insecure_tiny_key(self):
        with pytest.raises(ValueError):
            backend.generate_rsa_private_key(public_exponent=65537,
                                             key_size=511)

        with pytest.raises(ValueError):
            backend.generate_rsa_private_key(public_exponent=65537,
                                             key_size=256)

    @pytest.mark.skipif(
        backend._lib.OPENSSL_VERSION_NUMBER >= 0x1000100f,
        reason="Requires an older OpenSSL. Must be < 1.0.1"
    )
    def test_non_sha1_pss_mgf1_hash_algorithm_on_old_openssl(self):
        private_key = RSA_KEY_512.private_key(backend)
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            private_key.signer(
                padding.PSS(
                    mgf=padding.MGF1(
                        algorithm=hashes.SHA256(),
                    ),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA1()
            )
        public_key = private_key.public_key()
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            public_key.verifier(
                b"sig",
                padding.PSS(
                    mgf=padding.MGF1(
                        algorithm=hashes.SHA256(),
                    ),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA1()
            )

    def test_rsa_padding_unsupported_pss_mgf1_hash(self):
        assert backend.rsa_padding_supported(
            padding.PSS(mgf=padding.MGF1(DummyHash()), salt_length=0)
        ) is False

    def test_rsa_padding_unsupported(self):
        assert backend.rsa_padding_supported(DummyPadding()) is False

    def test_rsa_padding_supported_pkcs1v15(self):
        assert backend.rsa_padding_supported(padding.PKCS1v15()) is True

    def test_rsa_padding_supported_pss(self):
        assert backend.rsa_padding_supported(
            padding.PSS(mgf=padding.MGF1(hashes.SHA1()), salt_length=0)
        ) is True

    def test_rsa_padding_supported_oaep(self):
        assert backend.rsa_padding_supported(
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            ),
        ) is True

    def test_rsa_padding_unsupported_mgf(self):
        assert backend.rsa_padding_supported(
            padding.OAEP(
                mgf=DummyMGF(),
                algorithm=hashes.SHA1(),
                label=None
            ),
        ) is False

        assert backend.rsa_padding_supported(
            padding.PSS(mgf=DummyMGF(), salt_length=0)
        ) is False

    def test_unsupported_mgf1_hash_algorithm_decrypt(self):
        private_key = RSA_KEY_512.private_key(backend)
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            private_key.decrypt(
                b"0" * 64,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
            )

    def test_unsupported_oaep_hash_algorithm_decrypt(self):
        private_key = RSA_KEY_512.private_key(backend)
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            private_key.decrypt(
                b"0" * 64,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

    def test_unsupported_oaep_label_decrypt(self):
        private_key = RSA_KEY_512.private_key(backend)
        with pytest.raises(ValueError):
            private_key.decrypt(
                b"0" * 64,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=b"label"
                )
            )


@pytest.mark.skipif(
    backend._lib.OPENSSL_VERSION_NUMBER <= 0x10001000,
    reason="Requires an OpenSSL version >= 1.0.1"
)
class TestOpenSSLCMAC(object):
    def test_unsupported_cipher(self):
        @utils.register_interface(BlockCipherAlgorithm)
        class FakeAlgorithm(object):
            block_size = 64

        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_CIPHER):
            backend.create_cmac_ctx(FakeAlgorithm())


class TestOpenSSLCreateX509CSR(object):
    @pytest.mark.skipif(
        backend._lib.OPENSSL_VERSION_NUMBER >= 0x10001000,
        reason="Requires an older OpenSSL. Must be < 1.0.1"
    )
    def test_unsupported_dsa_keys(self):
        private_key = DSA_KEY_2048.private_key(backend)

        with pytest.raises(NotImplementedError):
            backend.create_x509_csr(object(), private_key, hashes.SHA1())

    @pytest.mark.skipif(
        backend._lib.OPENSSL_VERSION_NUMBER >= 0x10001000,
        reason="Requires an older OpenSSL. Must be < 1.0.1"
    )
    def test_unsupported_ec_keys(self):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        private_key = ec.generate_private_key(ec.SECP256R1(), backend)

        with pytest.raises(NotImplementedError):
            backend.create_x509_csr(object(), private_key, hashes.SHA1())


class TestOpenSSLSignX509Certificate(object):
    def test_requires_certificate_builder(self):
        private_key = RSA_KEY_2048.private_key(backend)

        with pytest.raises(TypeError):
            backend.create_x509_certificate(object(), private_key, DummyHash())


class TestOpenSSLSerialisationWithOpenSSL(object):
    def test_pem_password_cb_buffer_too_small(self):
        ffi_cb, cb = backend._pem_password_cb(b"aa")
        assert cb(None, 1, False, None) == 0

    def test_unsupported_evp_pkey_type(self):
        key = pretend.stub(type="unsupported")
        with raises_unsupported_algorithm(None):
            backend._evp_pkey_to_private_key(key)
        with raises_unsupported_algorithm(None):
            backend._evp_pkey_to_public_key(key)

    def test_very_long_pem_serialization_password(self):
        password = "x" * 1024

        with pytest.raises(ValueError):
            load_vectors_from_file(
                os.path.join(
                    "asymmetric", "Traditional_OpenSSL_Serialization",
                    "key1.pem"
                ),
                lambda pemfile: (
                    backend.load_pem_private_key(
                        pemfile.read().encode(), password
                    )
                )
            )


class DummyLibrary(object):
    Cryptography_HAS_EC = 0


class TestOpenSSLEllipticCurve(object):
    def test_elliptic_curve_supported(self, monkeypatch):
        monkeypatch.setattr(backend, "_lib", DummyLibrary())

        assert backend.elliptic_curve_supported(None) is False

    def test_elliptic_curve_signature_algorithm_supported(self, monkeypatch):
        monkeypatch.setattr(backend, "_lib", DummyLibrary())

        assert backend.elliptic_curve_signature_algorithm_supported(
            None, None
        ) is False

    def test_sn_to_elliptic_curve_not_supported(self):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_ELLIPTIC_CURVE):
            _sn_to_elliptic_curve(backend, b"fake")


@pytest.mark.requires_backend_interface(interface=RSABackend)
class TestRSAPEMSerialization(object):
    def test_password_length_limit(self):
        password = b"x" * 1024
        key = RSA_KEY_2048.private_key(backend)
        with pytest.raises(ValueError):
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(password)
            )
