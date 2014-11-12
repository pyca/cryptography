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

import pytest

from cryptography.exceptions import _Reasons
from cryptography.hazmat.backends.multibackend import MultiBackend
from cryptography.hazmat.primitives import cmac, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.tests.backends.dummy import (
    DummyCipherBackend, DummyHashBackend, DummyHMACBackend,
    DummyPBKDF2HMACBackend, DummyRSABackend, DummyDSABackend, DummyCMACBackend,
    DummyEllipticCurveBackend, DummyPKCS8SerializationBackend,
    DummyTraditionalOpenSSLSerializationBackend, DummyPEMSerializationBackend
)
from cryptography.tests.utils import raises_unsupported_algorithm


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

        hashes.Hash(hashes.MD5(), backend=backend)

        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            hashes.Hash(hashes.SHA1(), backend=backend)

    def test_hmac(self):
        backend = MultiBackend([
            DummyHMACBackend([hashes.MD5])
        ])
        assert backend.hmac_supported(hashes.MD5())

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

        assert backend.cmac_algorithm_supported(
            algorithms.AES(fake_key)) is True

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

    def test_deprecated_elliptic_curve(self):
        backend = MultiBackend([
            DummyEllipticCurveBackend([
                ec.SECT283K1
            ])
        ])

        assert backend.elliptic_curve_signature_algorithm_supported(
            ec.ECDSA(hashes.SHA256()),
            ec.SECT163K1()
        ) is False

        pub_numbers = ec.EllipticCurvePublicNumbers(2, 3, ec.SECT283K1())
        numbers = ec.EllipticCurvePrivateNumbers(1, pub_numbers)

        pytest.deprecated_call(
            backend.elliptic_curve_private_key_from_numbers,
            numbers
        )
        pytest.deprecated_call(
            backend.elliptic_curve_public_key_from_numbers,
            pub_numbers
        )

        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_ELLIPTIC_CURVE):
            backend.elliptic_curve_private_key_from_numbers(
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
            backend.elliptic_curve_public_key_from_numbers(
                ec.EllipticCurvePublicNumbers(
                    2,
                    3,
                    ec.SECT163K1()
                )
            )

    def test_pkcs8_serialization_backend(self):
        backend = MultiBackend([DummyPKCS8SerializationBackend()])

        backend.load_pkcs8_pem_private_key(b"keydata", None)

        backend = MultiBackend([])
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_SERIALIZATION):
            backend.load_pkcs8_pem_private_key(b"keydata", None)

    def test_traditional_openssl_serialization_backend(self):
        backend = MultiBackend([DummyTraditionalOpenSSLSerializationBackend()])

        backend.load_traditional_openssl_pem_private_key(b"keydata", None)

        backend = MultiBackend([])
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_SERIALIZATION):
            backend.load_traditional_openssl_pem_private_key(b"keydata", None)

    def test_pem_serialization_backend(self):
        backend = MultiBackend([DummyPEMSerializationBackend()])

        backend.load_pem_private_key(b"keydata", None)
        backend.load_pem_public_key(b"keydata")

        backend = MultiBackend([])
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_SERIALIZATION):
            backend.load_pem_private_key(b"keydata", None)
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_SERIALIZATION):
            backend.load_pem_public_key(b"keydata")
