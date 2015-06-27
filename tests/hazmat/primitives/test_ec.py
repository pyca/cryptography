# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import itertools
import os

import pytest

from cryptography import exceptions, utils
from cryptography.hazmat.backends.interfaces import (
    EllipticCurveBackend, PEMSerializationBackend
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_rfc6979_signature
)

from ...utils import (
    load_fips_ecdsa_key_pair_vectors, load_fips_ecdsa_signing_vectors,
    load_vectors_from_file, raises_unsupported_algorithm
)

_HASH_TYPES = {
    "SHA-1": hashes.SHA1,
    "SHA-224": hashes.SHA224,
    "SHA-256": hashes.SHA256,
    "SHA-384": hashes.SHA384,
    "SHA-512": hashes.SHA512,
}


def _skip_ecdsa_vector(backend, curve_type, hash_type):
    if not backend.elliptic_curve_signature_algorithm_supported(
        ec.ECDSA(hash_type()),
        curve_type()
    ):
        pytest.skip(
            "ECDSA not supported with this hash {0} and curve {1}".format(
                hash_type().name, curve_type().name
            )
        )


def _skip_curve_unsupported(backend, curve):
    if not backend.elliptic_curve_supported(curve):
        pytest.skip(
            "Curve {0} is not supported by this backend {1}".format(
                curve.name, backend
            )
        )


@utils.register_interface(ec.EllipticCurve)
class DummyCurve(object):
    name = "dummy-curve"
    key_size = 1


@utils.register_interface(ec.EllipticCurveSignatureAlgorithm)
class DummySignatureAlgorithm(object):
    algorithm = None


@utils.register_interface(serialization.KeySerializationEncryption)
class DummyKeyEncryption(object):
    pass


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
def test_skip_curve_unsupported(backend):
    with pytest.raises(pytest.skip.Exception):
        _skip_curve_unsupported(backend, DummyCurve())


def test_ec_numbers():
    numbers = ec.EllipticCurvePrivateNumbers(
        1,
        ec.EllipticCurvePublicNumbers(
            2, 3, DummyCurve()
        )
    )

    assert numbers.private_value == 1
    assert numbers.public_numbers.x == 2
    assert numbers.public_numbers.y == 3
    assert isinstance(numbers.public_numbers.curve, DummyCurve)

    with pytest.raises(TypeError):
        ec.EllipticCurvePrivateNumbers(
            None,
            ec.EllipticCurvePublicNumbers(
                2, 3, DummyCurve()
            )
        )

    with pytest.raises(TypeError):
        ec.EllipticCurvePrivateNumbers(
            1,
            ec.EllipticCurvePublicNumbers(
                None, 3, DummyCurve()
            )
        )

    with pytest.raises(TypeError):
        ec.EllipticCurvePrivateNumbers(
            1,
            ec.EllipticCurvePublicNumbers(
                2, None, DummyCurve()
            )
        )

    with pytest.raises(TypeError):
        ec.EllipticCurvePrivateNumbers(
            1,
            ec.EllipticCurvePublicNumbers(
                2, 3, None
            )
        )

    with pytest.raises(TypeError):
        ec.EllipticCurvePrivateNumbers(
            1,
            None
        )


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
class TestECWithNumbers(object):
    @pytest.mark.parametrize(
        ("vector", "hash_type"),
        list(itertools.product(
            load_vectors_from_file(
                os.path.join(
                    "asymmetric", "ECDSA", "FIPS_186-3", "KeyPair.rsp"),
                load_fips_ecdsa_key_pair_vectors
            ),
            _HASH_TYPES.values()
        ))
    )
    def test_with_numbers(self, backend, vector, hash_type):
        curve_type = ec._CURVE_TYPES[vector['curve']]

        _skip_ecdsa_vector(backend, curve_type, hash_type)

        key = ec.EllipticCurvePrivateNumbers(
            vector['d'],
            ec.EllipticCurvePublicNumbers(
                vector['x'],
                vector['y'],
                curve_type()
            )
        ).private_key(backend)
        assert key

        priv_num = key.private_numbers()
        assert priv_num.private_value == vector['d']
        assert priv_num.public_numbers.x == vector['x']
        assert priv_num.public_numbers.y == vector['y']
        assert curve_type().name == priv_num.public_numbers.curve.name


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
class TestECDSAVectors(object):
    @pytest.mark.parametrize(
        ("vector", "hash_type"),
        list(itertools.product(
            load_vectors_from_file(
                os.path.join(
                    "asymmetric", "ECDSA", "FIPS_186-3", "KeyPair.rsp"),
                load_fips_ecdsa_key_pair_vectors
            ),
            _HASH_TYPES.values()
        ))
    )
    def test_signing_with_example_keys(self, backend, vector, hash_type):
        curve_type = ec._CURVE_TYPES[vector['curve']]

        _skip_ecdsa_vector(backend, curve_type, hash_type)

        key = ec.EllipticCurvePrivateNumbers(
            vector['d'],
            ec.EllipticCurvePublicNumbers(
                vector['x'],
                vector['y'],
                curve_type()
            )
        ).private_key(backend)
        assert key

        pkey = key.public_key()
        assert pkey

        signer = key.signer(ec.ECDSA(hash_type()))
        signer.update(b"YELLOW SUBMARINE")
        signature = signer.finalize()

        verifier = pkey.verifier(signature, ec.ECDSA(hash_type()))
        verifier.update(b"YELLOW SUBMARINE")
        verifier.verify()

    @pytest.mark.parametrize(
        "curve", ec._CURVE_TYPES.values()
    )
    def test_generate_vector_curves(self, backend, curve):
        _skip_curve_unsupported(backend, curve())

        key = ec.generate_private_key(curve(), backend)
        assert key
        assert isinstance(key.curve, curve)
        assert key.curve.key_size

        pkey = key.public_key()
        assert pkey
        assert isinstance(pkey.curve, curve)
        assert key.curve.key_size == pkey.curve.key_size

    def test_generate_unknown_curve(self, backend):
        with raises_unsupported_algorithm(
            exceptions._Reasons.UNSUPPORTED_ELLIPTIC_CURVE
        ):
            ec.generate_private_key(DummyCurve(), backend)

        assert backend.elliptic_curve_signature_algorithm_supported(
            ec.ECDSA(hashes.SHA256()),
            DummyCurve()
        ) is False

    def test_unknown_signature_algoritm(self, backend):
        _skip_curve_unsupported(backend, ec.SECP192R1())

        key = ec.generate_private_key(ec.SECP192R1(), backend)

        with raises_unsupported_algorithm(
            exceptions._Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            key.signer(DummySignatureAlgorithm())

        with raises_unsupported_algorithm(
            exceptions._Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            key.public_key().verifier(b"", DummySignatureAlgorithm())

        assert backend.elliptic_curve_signature_algorithm_supported(
            DummySignatureAlgorithm(),
            ec.SECP192R1()
        ) is False

    def test_load_invalid_ec_key_from_numbers(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())

        numbers = ec.EllipticCurvePrivateNumbers(
            357646505660320080863666618182642070958081774038609089496899025506,
            ec.EllipticCurvePublicNumbers(
                47250808410327023131573602008345894927686381772325561185532964,
                1120253292479243545483756778742719537373113335231773536789915,
                ec.SECP256R1(),
            )
        )
        with pytest.raises(ValueError):
            numbers.private_key(backend)

        numbers = ec.EllipticCurvePrivateNumbers(
            357646505660320080863666618182642070958081774038609089496899025506,
            ec.EllipticCurvePublicNumbers(
                -4725080841032702313157360200834589492768638177232556118553296,
                1120253292479243545483756778742719537373113335231773536789915,
                ec.SECP256R1(),
            )
        )
        with pytest.raises(ValueError):
            numbers.private_key(backend)

        numbers = ec.EllipticCurvePrivateNumbers(
            357646505660320080863666618182642070958081774038609089496899025506,
            ec.EllipticCurvePublicNumbers(
                47250808410327023131573602008345894927686381772325561185532964,
                -1120253292479243545483756778742719537373113335231773536789915,
                ec.SECP256R1(),
            )
        )
        with pytest.raises(ValueError):
            numbers.private_key(backend)

    @pytest.mark.parametrize(
        "vector",
        itertools.chain(
            load_vectors_from_file(
                os.path.join(
                    "asymmetric", "ECDSA", "FIPS_186-3", "SigGen.txt"),
                load_fips_ecdsa_signing_vectors
            ),
            load_vectors_from_file(
                os.path.join(
                    "asymmetric", "ECDSA", "SECP256K1", "SigGen.txt"),
                load_fips_ecdsa_signing_vectors
            ),
        )
    )
    def test_signatures(self, backend, vector):
        hash_type = _HASH_TYPES[vector['digest_algorithm']]
        curve_type = ec._CURVE_TYPES[vector['curve']]

        _skip_ecdsa_vector(backend, curve_type, hash_type)

        key = ec.EllipticCurvePublicNumbers(
            vector['x'],
            vector['y'],
            curve_type()
        ).public_key(backend)

        signature = encode_rfc6979_signature(vector['r'], vector['s'])

        verifier = key.verifier(
            signature,
            ec.ECDSA(hash_type())
        )
        verifier.update(vector['message'])
        assert verifier.verify()

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join(
                "asymmetric", "ECDSA", "FIPS_186-3", "SigVer.rsp"),
            load_fips_ecdsa_signing_vectors
        )
    )
    def test_signature_failures(self, backend, vector):
        hash_type = _HASH_TYPES[vector['digest_algorithm']]
        curve_type = ec._CURVE_TYPES[vector['curve']]

        _skip_ecdsa_vector(backend, curve_type, hash_type)

        key = ec.EllipticCurvePublicNumbers(
            vector['x'],
            vector['y'],
            curve_type()
        ).public_key(backend)

        signature = encode_rfc6979_signature(vector['r'], vector['s'])

        verifier = key.verifier(
            signature,
            ec.ECDSA(hash_type())
        )
        verifier.update(vector['message'])

        if vector["fail"] is True:
            with pytest.raises(exceptions.InvalidSignature):
                verifier.verify()
        else:
            verifier.verify()


class TestECNumbersEquality(object):
    def test_public_numbers_eq(self):
        pub = ec.EllipticCurvePublicNumbers(1, 2, ec.SECP192R1())
        assert pub == ec.EllipticCurvePublicNumbers(1, 2, ec.SECP192R1())

    def test_public_numbers_ne(self):
        pub = ec.EllipticCurvePublicNumbers(1, 2, ec.SECP192R1())
        assert pub != ec.EllipticCurvePublicNumbers(1, 2, ec.SECP384R1())
        assert pub != ec.EllipticCurvePublicNumbers(1, 3, ec.SECP192R1())
        assert pub != ec.EllipticCurvePublicNumbers(2, 2, ec.SECP192R1())
        assert pub != object()

    def test_private_numbers_eq(self):
        pub = ec.EllipticCurvePublicNumbers(1, 2, ec.SECP192R1())
        priv = ec.EllipticCurvePrivateNumbers(1, pub)
        assert priv == ec.EllipticCurvePrivateNumbers(
            1, ec.EllipticCurvePublicNumbers(1, 2, ec.SECP192R1())
        )

    def test_private_numbers_ne(self):
        pub = ec.EllipticCurvePublicNumbers(1, 2, ec.SECP192R1())
        priv = ec.EllipticCurvePrivateNumbers(1, pub)
        assert priv != ec.EllipticCurvePrivateNumbers(
            2, ec.EllipticCurvePublicNumbers(1, 2, ec.SECP192R1())
        )
        assert priv != ec.EllipticCurvePrivateNumbers(
            1, ec.EllipticCurvePublicNumbers(2, 2, ec.SECP192R1())
        )
        assert priv != ec.EllipticCurvePrivateNumbers(
            1, ec.EllipticCurvePublicNumbers(1, 3, ec.SECP192R1())
        )
        assert priv != ec.EllipticCurvePrivateNumbers(
            1, ec.EllipticCurvePublicNumbers(1, 2, ec.SECP521R1())
        )
        assert priv != object()


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
@pytest.mark.requires_backend_interface(interface=PEMSerializationBackend)
class TestECSerialization(object):
    @pytest.mark.parametrize(
        ("fmt", "password"),
        itertools.product(
            [
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.PrivateFormat.PKCS8
            ],
            [
                b"s",
                b"longerpassword",
                b"!*$&(@#$*&($T@%_somesymbols",
                b"\x01" * 1000,
            ]
        )
    )
    def test_private_bytes_encrypted_pem(self, backend, fmt, password):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key_bytes = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PKCS8", "ec_private_key.pem"),
            lambda pemfile: pemfile.read().encode()
        )
        key = serialization.load_pem_private_key(key_bytes, None, backend)
        serialized = key.private_bytes(
            serialization.Encoding.PEM,
            fmt,
            serialization.BestAvailableEncryption(password)
        )
        loaded_key = serialization.load_pem_private_key(
            serialized, password, backend
        )
        loaded_priv_num = loaded_key.private_numbers()
        priv_num = key.private_numbers()
        assert loaded_priv_num == priv_num

    @pytest.mark.parametrize(
        ("fmt", "password"),
        [
            [serialization.PrivateFormat.PKCS8, b"s"],
            [serialization.PrivateFormat.PKCS8, b"longerpassword"],
            [serialization.PrivateFormat.PKCS8, b"!*$&(@#$*&($T@%_somesymbol"],
            [serialization.PrivateFormat.PKCS8, b"\x01" * 1000]
        ]
    )
    def test_private_bytes_encrypted_der(self, backend, fmt, password):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key_bytes = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PKCS8", "ec_private_key.pem"),
            lambda pemfile: pemfile.read().encode()
        )
        key = serialization.load_pem_private_key(key_bytes, None, backend)
        serialized = key.private_bytes(
            serialization.Encoding.DER,
            fmt,
            serialization.BestAvailableEncryption(password)
        )
        loaded_key = serialization.load_der_private_key(
            serialized, password, backend
        )
        loaded_priv_num = loaded_key.private_numbers()
        priv_num = key.private_numbers()
        assert loaded_priv_num == priv_num

    @pytest.mark.parametrize(
        ("encoding", "fmt", "loader_func"),
        [
            [
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.load_pem_private_key
            ],
            [
                serialization.Encoding.DER,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.load_der_private_key
            ],
            [
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.load_pem_private_key
            ],
            [
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.load_der_private_key
            ],
        ]
    )
    def test_private_bytes_unencrypted(self, backend, encoding, fmt,
                                       loader_func):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key_bytes = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PKCS8", "ec_private_key.pem"),
            lambda pemfile: pemfile.read().encode()
        )
        key = serialization.load_pem_private_key(key_bytes, None, backend)
        serialized = key.private_bytes(
            encoding, fmt, serialization.NoEncryption()
        )
        loaded_key = loader_func(serialized, None, backend)
        loaded_priv_num = loaded_key.private_numbers()
        priv_num = key.private_numbers()
        assert loaded_priv_num == priv_num

    @pytest.mark.parametrize(
        ("key_path", "encoding", "loader_func"),
        [
            [
                os.path.join(
                    "asymmetric", "PEM_Serialization", "ec_private_key.pem"
                ),
                serialization.Encoding.PEM,
                serialization.load_pem_private_key
            ],
            [
                os.path.join(
                    "asymmetric", "DER_Serialization", "ec_private_key.der"
                ),
                serialization.Encoding.DER,
                serialization.load_der_private_key
            ],
        ]
    )
    def test_private_bytes_traditional_openssl_unencrypted(
        self, backend, key_path, encoding, loader_func
    ):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key_bytes = load_vectors_from_file(
            key_path, lambda pemfile: pemfile.read(), mode="rb"
        )
        key = loader_func(key_bytes, None, backend)
        serialized = key.private_bytes(
            encoding,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )
        assert serialized == key_bytes

    def test_private_bytes_traditional_der_encrypted_invalid(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PKCS8", "ec_private_key.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            )
        )
        with pytest.raises(ValueError):
            key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.BestAvailableEncryption(b"password")
            )

    def test_private_bytes_invalid_encoding(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PKCS8", "ec_private_key.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            )
        )
        with pytest.raises(TypeError):
            key.private_bytes(
                "notencoding",
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )

    def test_private_bytes_invalid_format(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PKCS8", "ec_private_key.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            )
        )
        with pytest.raises(TypeError):
            key.private_bytes(
                serialization.Encoding.PEM,
                "invalidformat",
                serialization.NoEncryption()
            )

    def test_private_bytes_invalid_encryption_algorithm(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PKCS8", "ec_private_key.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            )
        )
        with pytest.raises(TypeError):
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                "notanencalg"
            )

    def test_private_bytes_unsupported_encryption_type(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PKCS8", "ec_private_key.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            )
        )
        with pytest.raises(ValueError):
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                DummyKeyEncryption()
            )

    def test_public_bytes_from_derived_public_key(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PKCS8", "ec_private_key.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            )
        )
        public = key.public_key()
        pem = public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        parsed_public = serialization.load_pem_public_key(pem, backend)
        assert parsed_public


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
@pytest.mark.requires_backend_interface(interface=PEMSerializationBackend)
class TestEllipticCurvePEMPublicKeySerialization(object):
    @pytest.mark.parametrize(
        ("key_path", "loader_func", "encoding"),
        [
            (
                os.path.join(
                    "asymmetric", "PEM_Serialization", "ec_public_key.pem"
                ),
                serialization.load_pem_public_key,
                serialization.Encoding.PEM,
            ), (
                os.path.join(
                    "asymmetric", "DER_Serialization", "ec_public_key.der"
                ),
                serialization.load_der_public_key,
                serialization.Encoding.DER,
            )
        ]
    )
    def test_public_bytes_match(self, key_path, loader_func, encoding,
                                backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key_bytes = load_vectors_from_file(
            key_path, lambda pemfile: pemfile.read(), mode="rb"
        )
        key = loader_func(key_bytes, backend)
        serialized = key.public_bytes(
            encoding, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert serialized == key_bytes

    def test_public_bytes_invalid_encoding(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PEM_Serialization", "ec_public_key.pem"
            ),
            lambda pemfile: serialization.load_pem_public_key(
                pemfile.read().encode(), backend
            )
        )
        with pytest.raises(TypeError):
            key.public_bytes(
                "notencoding",
                serialization.PublicFormat.SubjectPublicKeyInfo
            )

    def test_public_bytes_invalid_format(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PEM_Serialization", "ec_public_key.pem"
            ),
            lambda pemfile: serialization.load_pem_public_key(
                pemfile.read().encode(), backend
            )
        )
        with pytest.raises(TypeError):
            key.public_bytes(serialization.Encoding.PEM, "invalidformat")

    def test_public_bytes_pkcs1_unsupported(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PEM_Serialization", "ec_public_key.pem"
            ),
            lambda pemfile: serialization.load_pem_public_key(
                pemfile.read().encode(), backend
            )
        )
        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.PKCS1
            )
