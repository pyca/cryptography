# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.exceptions import (
    UnsupportedAlgorithm, _Reasons
)
from cryptography.hazmat.backends.interfaces import (
    CMACBackend, CipherBackend, DERSerializationBackend, DSABackend,
    EllipticCurveBackend, HMACBackend, HashBackend, PBKDF2HMACBackend,
    PEMSerializationBackend, RSABackend, X509Backend
)
from cryptography.hazmat.backends.multibackend import MultiBackend
from cryptography.hazmat.primitives import cmac, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ...utils import raises_unsupported_algorithm


@utils.register_interface(CipherBackend)
class DummyCipherBackend(object):
    def __init__(self, supported_ciphers):
        self._ciphers = supported_ciphers

    def cipher_supported(self, cipher, mode):
        return (type(cipher), type(mode)) in self._ciphers

    def create_symmetric_encryption_ctx(self, cipher, mode):
        if not self.cipher_supported(cipher, mode):
            raise UnsupportedAlgorithm("", _Reasons.UNSUPPORTED_CIPHER)

    def create_symmetric_decryption_ctx(self, cipher, mode):
        if not self.cipher_supported(cipher, mode):
            raise UnsupportedAlgorithm("", _Reasons.UNSUPPORTED_CIPHER)


@utils.register_interface(HashBackend)
class DummyHashBackend(object):
    def __init__(self, supported_algorithms):
        self._algorithms = supported_algorithms

    def hash_supported(self, algorithm):
        return type(algorithm) in self._algorithms

    def create_hash_ctx(self, algorithm):
        if not self.hash_supported(algorithm):
            raise UnsupportedAlgorithm("", _Reasons.UNSUPPORTED_HASH)


@utils.register_interface(HMACBackend)
class DummyHMACBackend(object):
    def __init__(self, supported_algorithms):
        self._algorithms = supported_algorithms

    def hmac_supported(self, algorithm):
        return type(algorithm) in self._algorithms

    def create_hmac_ctx(self, key, algorithm):
        if not self.hmac_supported(algorithm):
            raise UnsupportedAlgorithm("", _Reasons.UNSUPPORTED_HASH)


@utils.register_interface(PBKDF2HMACBackend)
class DummyPBKDF2HMACBackend(object):
    def __init__(self, supported_algorithms):
        self._algorithms = supported_algorithms

    def pbkdf2_hmac_supported(self, algorithm):
        return type(algorithm) in self._algorithms

    def derive_pbkdf2_hmac(self, algorithm, length, salt, iterations,
                           key_material):
        if not self.pbkdf2_hmac_supported(algorithm):
            raise UnsupportedAlgorithm("", _Reasons.UNSUPPORTED_HASH)


@utils.register_interface(RSABackend)
class DummyRSABackend(object):
    def generate_rsa_private_key(self, public_exponent, key_size):
        pass

    def rsa_padding_supported(self, padding):
        pass

    def generate_rsa_parameters_supported(self, public_exponent, key_size):
        pass

    def load_rsa_private_numbers(self, numbers):
        pass

    def load_rsa_public_numbers(self, numbers):
        pass


@utils.register_interface(DSABackend)
class DummyDSABackend(object):
    def generate_dsa_parameters(self, key_size):
        pass

    def generate_dsa_private_key(self, parameters):
        pass

    def generate_dsa_private_key_and_parameters(self, key_size):
        pass

    def dsa_hash_supported(self, algorithm):
        pass

    def dsa_parameters_supported(self, p, q, g):
        pass

    def load_dsa_private_numbers(self, numbers):
        pass

    def load_dsa_public_numbers(self, numbers):
        pass

    def load_dsa_parameter_numbers(self, numbers):
        pass


@utils.register_interface(CMACBackend)
class DummyCMACBackend(object):
    def __init__(self, supported_algorithms):
        self._algorithms = supported_algorithms

    def cmac_algorithm_supported(self, algorithm):
        return type(algorithm) in self._algorithms

    def create_cmac_ctx(self, algorithm):
        if not self.cmac_algorithm_supported(algorithm):
            raise UnsupportedAlgorithm("", _Reasons.UNSUPPORTED_CIPHER)


@utils.register_interface(EllipticCurveBackend)
class DummyEllipticCurveBackend(object):
    def __init__(self, supported_curves):
        self._curves = supported_curves

    def elliptic_curve_supported(self, curve):
        return any(
            isinstance(curve, curve_type)
            for curve_type in self._curves
        )

    def elliptic_curve_signature_algorithm_supported(
        self, signature_algorithm, curve
    ):
        return (
            isinstance(signature_algorithm, ec.ECDSA) and
            any(
                isinstance(curve, curve_type)
                for curve_type in self._curves
            )
        )

    def generate_elliptic_curve_private_key(self, curve):
        if not self.elliptic_curve_supported(curve):
            raise UnsupportedAlgorithm(_Reasons.UNSUPPORTED_ELLIPTIC_CURVE)

    def load_elliptic_curve_private_numbers(self, numbers):
        if not self.elliptic_curve_supported(numbers.public_numbers.curve):
            raise UnsupportedAlgorithm(_Reasons.UNSUPPORTED_ELLIPTIC_CURVE)

    def load_elliptic_curve_public_numbers(self, numbers):
        if not self.elliptic_curve_supported(numbers.curve):
            raise UnsupportedAlgorithm(_Reasons.UNSUPPORTED_ELLIPTIC_CURVE)


@utils.register_interface(PEMSerializationBackend)
class DummyPEMSerializationBackend(object):
    def load_pem_private_key(self, data, password):
        pass

    def load_pem_public_key(self, data):
        pass


@utils.register_interface(DERSerializationBackend)
class DummyDERSerializationBackend(object):
    def load_der_private_key(self, data, password):
        pass

    def load_der_public_key(self, data):
        pass


@utils.register_interface(X509Backend)
class DummyX509Backend(object):
    def load_pem_x509_certificate(self, data):
        pass

    def load_der_x509_certificate(self, data):
        pass

    def load_pem_x509_csr(self, data):
        pass

    def load_der_x509_csr(self, data):
        pass

    def create_x509_csr(self, builder, private_key, algorithm):
        pass

    def create_x509_certificate(self, builder, private_key, algorithm):
        pass


class TestMultiBackend(object):
    def test_ciphers(self):
        backend = MultiBackend([
            DummyHashBackend([]),
            DummyCipherBackend([
                (algorithms.AES, modes.CBC),
            ])
        ])
        assert backend.cipher_supported(
            algorithms.AES(b"\x00" * 16), modes.CBC(b"\x00" * 16)
        )
        assert not backend.cipher_supported(
            algorithms.TripleDES(b"\x00" * 16), modes.CBC(b"\x00" * 16)
        )

        cipher = Cipher(
            algorithms.AES(b"\x00" * 16),
            modes.CBC(b"\x00" * 16),
            backend=backend
        )
        cipher.encryptor()
        cipher.decryptor()

        cipher = Cipher(
            algorithms.Camellia(b"\x00" * 16),
            modes.CBC(b"\x00" * 16),
            backend=backend
        )
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_CIPHER):
            cipher.encryptor()
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_CIPHER):
            cipher.decryptor()

    def test_hashes(self):
        backend = MultiBackend([
            DummyHashBackend([hashes.MD5])
        ])
        assert backend.hash_supported(hashes.MD5())
        assert not backend.hash_supported(hashes.SHA256())

        hashes.Hash(hashes.MD5(), backend=backend)

        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            hashes.Hash(hashes.SHA1(), backend=backend)

    def test_hmac(self):
        backend = MultiBackend([
            DummyHMACBackend([hashes.MD5])
        ])
        assert backend.hmac_supported(hashes.MD5())
        assert not backend.hmac_supported(hashes.SHA256())

        hmac.HMAC(b"", hashes.MD5(), backend=backend)

        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            hmac.HMAC(b"", hashes.SHA1(), backend=backend)

    def test_pbkdf2(self):
        backend = MultiBackend([
            DummyPBKDF2HMACBackend([hashes.MD5])
        ])
        assert backend.pbkdf2_hmac_supported(hashes.MD5())

        backend.derive_pbkdf2_hmac(hashes.MD5(), 10, b"", 10, b"")

        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            backend.derive_pbkdf2_hmac(hashes.SHA1(), 10, b"", 10, b"")

    def test_rsa(self):
        backend = MultiBackend([
            DummyRSABackend()
        ])

        backend.generate_rsa_private_key(
            key_size=1024, public_exponent=65537
        )

        backend.rsa_padding_supported(padding.PKCS1v15())

        backend.generate_rsa_parameters_supported(65537, 1024)

        backend.load_rsa_private_numbers("private_numbers")

        backend.load_rsa_public_numbers("public_numbers")

        backend = MultiBackend([])
        with raises_unsupported_algorithm(
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            backend.generate_rsa_private_key(key_size=1024, public_exponent=3)

        with raises_unsupported_algorithm(
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            backend.rsa_padding_supported(padding.PKCS1v15())

        with raises_unsupported_algorithm(
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            backend.generate_rsa_parameters_supported(65537, 1024)

        with raises_unsupported_algorithm(
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            backend.load_rsa_private_numbers("private_numbers")

        with raises_unsupported_algorithm(
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            backend.load_rsa_public_numbers("public_numbers")

    def test_dsa(self):
        backend = MultiBackend([
            DummyDSABackend()
        ])

        backend.generate_dsa_parameters(key_size=1024)

        parameters = object()
        backend.generate_dsa_private_key(parameters)
        backend.generate_dsa_private_key_and_parameters(key_size=1024)

        backend.dsa_hash_supported(hashes.SHA1())
        backend.dsa_parameters_supported(1, 2, 3)
        backend.load_dsa_private_numbers("numbers")
        backend.load_dsa_public_numbers("numbers")
        backend.load_dsa_parameter_numbers("numbers")

        backend = MultiBackend([])
        with raises_unsupported_algorithm(
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            backend.generate_dsa_parameters(key_size=1024)

        with raises_unsupported_algorithm(
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            backend.generate_dsa_private_key(parameters)

        with raises_unsupported_algorithm(
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            backend.generate_dsa_private_key_and_parameters(key_size=1024)

        with raises_unsupported_algorithm(
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            backend.dsa_hash_supported(hashes.SHA1())

        with raises_unsupported_algorithm(
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            backend.dsa_parameters_supported('p', 'q', 'g')

        with raises_unsupported_algorithm(
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            backend.load_dsa_private_numbers("numbers")

        with raises_unsupported_algorithm(
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            backend.load_dsa_public_numbers("numbers")

        with raises_unsupported_algorithm(
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            backend.load_dsa_parameter_numbers("numbers")

    def test_cmac(self):
        backend = MultiBackend([
            DummyCMACBackend([algorithms.AES])
        ])

        fake_key = b"\x00" * 16

        assert backend.cmac_algorithm_supported(algorithms.AES(fake_key))
        assert not backend.cmac_algorithm_supported(
            algorithms.TripleDES(fake_key)
        )

        cmac.CMAC(algorithms.AES(fake_key), backend)

        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_CIPHER):
            cmac.CMAC(algorithms.TripleDES(fake_key), backend)

    def test_elliptic_curve(self):
        backend = MultiBackend([
            DummyEllipticCurveBackend([
                ec.SECT283K1
            ])
        ])

        assert backend.elliptic_curve_supported(ec.SECT283K1()) is True

        assert backend.elliptic_curve_signature_algorithm_supported(
            ec.ECDSA(hashes.SHA256()),
            ec.SECT283K1()
        ) is True

        backend.generate_elliptic_curve_private_key(ec.SECT283K1())

        backend.load_elliptic_curve_private_numbers(
            ec.EllipticCurvePrivateNumbers(
                1,
                ec.EllipticCurvePublicNumbers(
                    2,
                    3,
                    ec.SECT283K1()
                )
            )
        )

        backend.load_elliptic_curve_public_numbers(
            ec.EllipticCurvePublicNumbers(
                2,
                3,
                ec.SECT283K1()
            )
        )

        assert backend.elliptic_curve_supported(ec.SECT163K1()) is False

        assert backend.elliptic_curve_signature_algorithm_supported(
            ec.ECDSA(hashes.SHA256()),
            ec.SECT163K1()
        ) is False

        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_ELLIPTIC_CURVE):
            backend.generate_elliptic_curve_private_key(ec.SECT163K1())

        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_ELLIPTIC_CURVE):
            backend.load_elliptic_curve_private_numbers(
                ec.EllipticCurvePrivateNumbers(
                    1,
                    ec.EllipticCurvePublicNumbers(
                        2,
                        3,
                        ec.SECT163K1()
                    )
                )
            )

        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_ELLIPTIC_CURVE):
            backend.load_elliptic_curve_public_numbers(
                ec.EllipticCurvePublicNumbers(
                    2,
                    3,
                    ec.SECT163K1()
                )
            )

    def test_pem_serialization_backend(self):
        backend = MultiBackend([DummyPEMSerializationBackend()])

        backend.load_pem_private_key(b"keydata", None)
        backend.load_pem_public_key(b"keydata")

        backend = MultiBackend([])
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_SERIALIZATION):
            backend.load_pem_private_key(b"keydata", None)
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_SERIALIZATION):
            backend.load_pem_public_key(b"keydata")

    def test_der_serialization_backend(self):
        backend = MultiBackend([DummyDERSerializationBackend()])

        backend.load_der_private_key(b"keydata", None)
        backend.load_der_public_key(b"keydata")

        backend = MultiBackend([])
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_SERIALIZATION):
            backend.load_der_private_key(b"keydata", None)
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_SERIALIZATION):
            backend.load_der_public_key(b"keydata")

    def test_x509_backend(self):
        backend = MultiBackend([DummyX509Backend()])

        backend.load_pem_x509_certificate(b"certdata")
        backend.load_der_x509_certificate(b"certdata")
        backend.load_pem_x509_csr(b"reqdata")
        backend.load_der_x509_csr(b"reqdata")
        backend.create_x509_csr(object(), b"privatekey", hashes.SHA1())
        backend.create_x509_certificate(object(), b"privatekey", hashes.SHA1())

        backend = MultiBackend([])
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_X509):
            backend.load_pem_x509_certificate(b"certdata")
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_X509):
            backend.load_der_x509_certificate(b"certdata")
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_X509):
            backend.load_pem_x509_csr(b"reqdata")
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_X509):
            backend.load_der_x509_csr(b"reqdata")
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_X509):
            backend.create_x509_csr(object(), b"privatekey", hashes.SHA1())
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_X509):
            backend.create_x509_certificate(
                object(), b"privatekey", hashes.SHA1()
            )
