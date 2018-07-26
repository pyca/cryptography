# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii
import itertools
import os
from binascii import hexlify

import pytest

from cryptography import exceptions, utils
from cryptography.hazmat.backends.interfaces import (
    EllipticCurveBackend, PEMSerializationBackend
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed, encode_dss_signature
)
from cryptography.utils import CryptographyDeprecationWarning

from .fixtures_ec import EC_KEY_SECP384R1
from ...doubles import DummyKeySerializationEncryption
from ...utils import (
    load_fips_ecdsa_key_pair_vectors, load_fips_ecdsa_signing_vectors,
    load_kasvs_ecdh_vectors, load_nist_vectors, load_vectors_from_file,
    raises_unsupported_algorithm
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


def _skip_exchange_algorithm_unsupported(backend, algorithm, curve):
    if not backend.elliptic_curve_exchange_algorithm_supported(
        algorithm, curve
    ):
        pytest.skip(
            "Exchange with {0} curve is not supported by {1}".format(
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


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
def test_skip_curve_unsupported(backend):
    with pytest.raises(pytest.skip.Exception):
        _skip_curve_unsupported(backend, DummyCurve())


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
def test_skip_exchange_algorithm_unsupported(backend):
    with pytest.raises(pytest.skip.Exception):
        _skip_exchange_algorithm_unsupported(backend, ec.ECDH(), DummyCurve())


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
def test_skip_ecdsa_vector(backend):
    with pytest.raises(pytest.skip.Exception):
        _skip_ecdsa_vector(backend, DummyCurve, hashes.SHA256)


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
def test_derive_private_key_success(backend):
    curve = ec.SECP256K1()
    _skip_curve_unsupported(backend, curve)

    private_numbers = ec.generate_private_key(curve, backend).private_numbers()

    derived_key = ec.derive_private_key(
        private_numbers.private_value, curve, backend
    )

    assert private_numbers == derived_key.private_numbers()


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
def test_derive_private_key_errors(backend):
    curve = ec.SECP256K1()
    _skip_curve_unsupported(backend, curve)

    with pytest.raises(TypeError):
        ec.derive_private_key('one', curve, backend)

    with pytest.raises(TypeError):
        ec.derive_private_key(10, 'five', backend)

    with pytest.raises(ValueError):
        ec.derive_private_key(-7, curve, backend)


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


@pytest.mark.parametrize(
    ("private_value", "x", "y", "curve"),
    [
        (None, 2, 3, DummyCurve()),
        (1, None, 3, DummyCurve()),
        (1, 2, None, DummyCurve()),
        (1, 2, 3, None),
    ]
)
def test_invalid_ec_numbers_args(private_value, x, y, curve):
    with pytest.raises(TypeError):
        ec.EllipticCurvePrivateNumbers(
            private_value, ec.EllipticCurvePublicNumbers(x, y, curve)
        )


def test_invalid_private_numbers_public_numbers():
    with pytest.raises(TypeError):
        ec.EllipticCurvePrivateNumbers(1, None)


def test_encode_point():
    # secp256r1 point
    x = int(
        '233ea3b0027127084cd2cd336a13aeef69c598d8af61369a36454a17c6c22aec',
        16
    )
    y = int(
        '3ea2c10a84153862be4ec82940f0543f9ba866af9751a6ee79d38460b35f442e',
        16
    )
    pn = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    data = pn.encode_point()
    assert data == binascii.unhexlify(
        "04233ea3b0027127084cd2cd336a13aeef69c598d8af61369a36454a17c6c22ae"
        "c3ea2c10a84153862be4ec82940f0543f9ba866af9751a6ee79d38460b35f442e"
    )


def test_from_encoded_point():
    # secp256r1 point
    data = binascii.unhexlify(
        "04233ea3b0027127084cd2cd336a13aeef69c598d8af61369a36454a17c6c22ae"
        "c3ea2c10a84153862be4ec82940f0543f9ba866af9751a6ee79d38460b35f442e"
    )
    pn = ec.EllipticCurvePublicNumbers.from_encoded_point(
        ec.SECP256R1(), data
    )
    assert pn.x == int(
        '233ea3b0027127084cd2cd336a13aeef69c598d8af61369a36454a17c6c22aec',
        16
    )
    assert pn.y == int(
        '3ea2c10a84153862be4ec82940f0543f9ba866af9751a6ee79d38460b35f442e',
        16
    )


def test_from_encoded_point_invalid_length():
    bad_data = binascii.unhexlify(
        "04233ea3b0027127084cd2cd336a13aeef69c598d8af61369a36454a17c6c22ae"
        "c3ea2c10a84153862be4ec82940f0543f9ba866af9751a6ee79d38460"
    )
    with pytest.raises(ValueError):
        ec.EllipticCurvePublicNumbers.from_encoded_point(
            ec.SECP384R1(), bad_data
        )


def test_from_encoded_point_unsupported_point_type():
    # set to point type 2.
    unsupported_type = binascii.unhexlify(
        "02233ea3b0027127084cd2cd336a13aeef69c598d8af61369a36454a17c6c22a"
    )
    with pytest.raises(ValueError):
        ec.EllipticCurvePublicNumbers.from_encoded_point(
            ec.SECP256R1(), unsupported_type
        )


def test_from_encoded_point_not_a_curve():
    with pytest.raises(TypeError):
        ec.EllipticCurvePublicNumbers.from_encoded_point(
            "notacurve", b"\x04data"
        )


def test_ec_public_numbers_repr():
    pn = ec.EllipticCurvePublicNumbers(2, 3, ec.SECP256R1())
    assert repr(pn) == "<EllipticCurvePublicNumbers(curve=secp256r1, x=2, y=3>"


def test_ec_public_numbers_hash():
    pn1 = ec.EllipticCurvePublicNumbers(2, 3, ec.SECP256R1())
    pn2 = ec.EllipticCurvePublicNumbers(2, 3, ec.SECP256R1())
    pn3 = ec.EllipticCurvePublicNumbers(1, 3, ec.SECP256R1())

    assert hash(pn1) == hash(pn2)
    assert hash(pn1) != hash(pn3)


def test_ec_private_numbers_hash():
    numbers1 = ec.EllipticCurvePrivateNumbers(
        1, ec.EllipticCurvePublicNumbers(2, 3, DummyCurve())
    )
    numbers2 = ec.EllipticCurvePrivateNumbers(
        1, ec.EllipticCurvePublicNumbers(2, 3, DummyCurve())
    )
    numbers3 = ec.EllipticCurvePrivateNumbers(
        2, ec.EllipticCurvePublicNumbers(2, 3, DummyCurve())
    )

    assert hash(numbers1) == hash(numbers2)
    assert hash(numbers1) != hash(numbers3)


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
def test_ec_key_key_size(backend):
    curve = ec.SECP256R1()
    _skip_curve_unsupported(backend, curve)
    key = ec.generate_private_key(curve, backend)
    assert key.key_size == 256
    assert key.public_key().key_size == 256


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

        with pytest.warns(CryptographyDeprecationWarning):
            signer = key.signer(ec.ECDSA(hash_type()))
        signer.update(b"YELLOW SUBMARINE")
        signature = signer.finalize()

        with pytest.warns(CryptographyDeprecationWarning):
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
        ), pytest.warns(CryptographyDeprecationWarning):
            key.signer(DummySignatureAlgorithm())

        with raises_unsupported_algorithm(
            exceptions._Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            key.sign(b"somedata", DummySignatureAlgorithm())

        with raises_unsupported_algorithm(
            exceptions._Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ), pytest.warns(CryptographyDeprecationWarning):
            key.public_key().verifier(b"", DummySignatureAlgorithm())

        with raises_unsupported_algorithm(
            exceptions._Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            key.public_key().verify(
                b"signature", b"data", DummySignatureAlgorithm()
            )

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

    def test_load_invalid_public_ec_key_from_numbers(self, backend):
        _skip_curve_unsupported(backend, ec.SECP521R1())

        # Bad X coordinate
        numbers = ec.EllipticCurvePublicNumbers(
            int("000003647356b91f8ace114c7247ecf4f4a622553fc025e04a178f179ef27"
                "9090c184af678a4c78f635483bdd8aa544851c6ef291c1f0d6a241ebfd145"
                "77d1d30d9903ce", 16),
            int("000001499bc7e079322ea0fcfbd6b40103fa6a1536c2257b182db0df4b369"
                "6ec643adf100eb4f2025d1b873f82e5a475d6e4400ba777090eeb4563a115"
                "09e4c87319dc26", 16),
            ec.SECP521R1()
        )
        with pytest.raises(ValueError):
            numbers.public_key(backend)

        # Bad Y coordinate
        numbers = ec.EllipticCurvePublicNumbers(
            int("0000019aadc221cc0525118ab6d5aa1f64720603de0be128cbfea0b381ad8"
                "02a2facc6370bb58cf88b3f0c692bc654ee19d6cad198f10d4b681b396f20"
                "d2e40603fa945b", 16),
            int("0000025da392803a320717a08d4cb3dea932039badff363b71bdb8064e726"
                "6c7f4f4b748d4d425347fc33e3885d34b750fa7fcd5691f4d90c89522ce33"
                "feff5db10088a5", 16),
            ec.SECP521R1()
        )
        with pytest.raises(ValueError):
            numbers.public_key(backend)

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

        signature = encode_dss_signature(vector['r'], vector['s'])

        key.verify(
            signature,
            vector['message'],
            ec.ECDSA(hash_type())
        )

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

        signature = encode_dss_signature(vector['r'], vector['s'])

        if vector["fail"] is True:
            with pytest.raises(exceptions.InvalidSignature):
                key.verify(
                    signature,
                    vector['message'],
                    ec.ECDSA(hash_type())
                )
        else:
            key.verify(
                signature,
                vector['message'],
                ec.ECDSA(hash_type())
            )

    def test_sign(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        message = b"one little message"
        algorithm = ec.ECDSA(hashes.SHA1())
        private_key = ec.generate_private_key(ec.SECP256R1(), backend)
        signature = private_key.sign(message, algorithm)
        public_key = private_key.public_key()
        public_key.verify(signature, message, algorithm)

    def test_sign_prehashed(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        message = b"one little message"
        h = hashes.Hash(hashes.SHA1(), backend)
        h.update(message)
        data = h.finalize()
        algorithm = ec.ECDSA(Prehashed(hashes.SHA1()))
        private_key = ec.generate_private_key(ec.SECP256R1(), backend)
        signature = private_key.sign(data, algorithm)
        public_key = private_key.public_key()
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA1()))

    def test_sign_prehashed_digest_mismatch(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        message = b"one little message"
        h = hashes.Hash(hashes.SHA1(), backend)
        h.update(message)
        data = h.finalize()
        algorithm = ec.ECDSA(Prehashed(hashes.SHA256()))
        private_key = ec.generate_private_key(ec.SECP256R1(), backend)
        with pytest.raises(ValueError):
            private_key.sign(data, algorithm)

    def test_verify(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        message = b"one little message"
        algorithm = ec.ECDSA(hashes.SHA1())
        private_key = ec.generate_private_key(ec.SECP256R1(), backend)
        signature = private_key.sign(message, algorithm)
        public_key = private_key.public_key()
        public_key.verify(signature, message, algorithm)

    def test_verify_prehashed(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        message = b"one little message"
        algorithm = ec.ECDSA(hashes.SHA1())
        private_key = ec.generate_private_key(ec.SECP256R1(), backend)
        signature = private_key.sign(message, algorithm)
        h = hashes.Hash(hashes.SHA1(), backend)
        h.update(message)
        data = h.finalize()
        public_key = private_key.public_key()
        public_key.verify(
            signature, data, ec.ECDSA(Prehashed(hashes.SHA1()))
        )

    def test_verify_prehashed_digest_mismatch(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        message = b"one little message"
        private_key = ec.generate_private_key(ec.SECP256R1(), backend)
        h = hashes.Hash(hashes.SHA1(), backend)
        h.update(message)
        data = h.finalize()
        public_key = private_key.public_key()
        with pytest.raises(ValueError):
            public_key.verify(
                b"\x00" * 32, data, ec.ECDSA(Prehashed(hashes.SHA256()))
            )

    def test_prehashed_unsupported_in_signer_ctx(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        private_key = ec.generate_private_key(ec.SECP256R1(), backend)
        with pytest.raises(TypeError), \
                pytest.warns(CryptographyDeprecationWarning):
            private_key.signer(ec.ECDSA(Prehashed(hashes.SHA1())))

    def test_prehashed_unsupported_in_verifier_ctx(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        private_key = ec.generate_private_key(ec.SECP256R1(), backend)
        public_key = private_key.public_key()
        with pytest.raises(TypeError), \
                pytest.warns(CryptographyDeprecationWarning):
            public_key.verifier(
                b"0" * 64,
                ec.ECDSA(Prehashed(hashes.SHA1()))
            )


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
                DummyKeySerializationEncryption()
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

    def test_public_bytes_openssh(self, backend):
        _skip_curve_unsupported(backend, ec.SECP192R1())
        _skip_curve_unsupported(backend, ec.SECP256R1())

        key_bytes = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PEM_Serialization", "ec_public_key.pem"
            ),
            lambda pemfile: pemfile.read(), mode="rb"
        )
        key = serialization.load_pem_public_key(key_bytes, backend)

        ssh_bytes = key.public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        )
        assert ssh_bytes == (
            b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAy"
            b"NTYAAABBBCS8827s9rUZyxZTi/um01+oIlWrwLHOjQxRU9CDAndom00zVAw5BRrI"
            b"KtHB+SWD4P+sVJTARSq1mHt8kOIWrPc="
        )

        key = ec.generate_private_key(ec.SECP192R1(), backend).public_key()
        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.OpenSSH,
                serialization.PublicFormat.OpenSSH
            )

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


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
class TestECDSAVerification(object):
    def test_signature_not_bytes(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = ec.generate_private_key(ec.SECP256R1(), backend)
        public_key = key.public_key()
        with pytest.raises(TypeError), \
                pytest.warns(CryptographyDeprecationWarning):
            public_key.verifier(1234, ec.ECDSA(hashes.SHA256()))


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
class TestECDH(object):
    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join(
                "asymmetric", "ECDH",
                "KASValidityTest_ECCStaticUnified_NOKC_ZZOnly_init.fax"),
            load_kasvs_ecdh_vectors
        )
    )
    def test_key_exchange_with_vectors(self, backend, vector):
        _skip_exchange_algorithm_unsupported(
            backend, ec.ECDH(), ec._CURVE_TYPES[vector['curve']]
        )

        key_numbers = vector['IUT']
        private_numbers = ec.EllipticCurvePrivateNumbers(
            key_numbers['d'],
            ec.EllipticCurvePublicNumbers(
                key_numbers['x'],
                key_numbers['y'],
                ec._CURVE_TYPES[vector['curve']]()
            )
        )
        # Errno 5-7 indicates a bad public or private key, this doesn't test
        # the ECDH code at all
        if vector['fail'] and vector['errno'] in [5, 6, 7]:
            with pytest.raises(ValueError):
                private_numbers.private_key(backend)
            return
        else:
            private_key = private_numbers.private_key(backend)

        peer_numbers = vector['CAVS']
        public_numbers = ec.EllipticCurvePublicNumbers(
            peer_numbers['x'],
            peer_numbers['y'],
            ec._CURVE_TYPES[vector['curve']]()
        )
        # Errno 1 and 2 indicates a bad public key, this doesn't test the ECDH
        # code at all
        if vector['fail'] and vector['errno'] in [1, 2]:
            with pytest.raises(ValueError):
                public_numbers.public_key(backend)
            return
        else:
            peer_pubkey = public_numbers.public_key(backend)

        z = private_key.exchange(ec.ECDH(), peer_pubkey)
        z = int(hexlify(z).decode('ascii'), 16)
        # At this point fail indicates that one of the underlying keys was
        # changed. This results in a non-matching derived key.
        if vector['fail']:
            # Errno 8 indicates Z should be changed.
            assert vector['errno'] == 8
            assert z != vector['Z']
        else:
            assert z == vector['Z']

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("asymmetric", "ECDH", "brainpool.txt"),
            load_nist_vectors
        )
    )
    def test_brainpool_kex(self, backend, vector):
        curve = ec._CURVE_TYPES[vector['curve'].decode('ascii')]
        _skip_exchange_algorithm_unsupported(backend, ec.ECDH(), curve)
        key = ec.EllipticCurvePrivateNumbers(
            int(vector['da'], 16),
            ec.EllipticCurvePublicNumbers(
                int(vector['x_qa'], 16), int(vector['y_qa'], 16), curve()
            )
        ).private_key(backend)
        peer = ec.EllipticCurvePrivateNumbers(
            int(vector['db'], 16),
            ec.EllipticCurvePublicNumbers(
                int(vector['x_qb'], 16), int(vector['y_qb'], 16), curve()
            )
        ).private_key(backend)
        shared_secret = key.exchange(ec.ECDH(), peer.public_key())
        assert shared_secret == binascii.unhexlify(vector["x_z"])
        shared_secret_2 = peer.exchange(ec.ECDH(), key.public_key())
        assert shared_secret_2 == binascii.unhexlify(vector["x_z"])

    def test_exchange_unsupported_algorithm(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())

        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PKCS8", "ec_private_key.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            )
        )

        with raises_unsupported_algorithm(
            exceptions._Reasons.UNSUPPORTED_EXCHANGE_ALGORITHM
        ):
            key.exchange(None, key.public_key())

    def test_exchange_non_matching_curve(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        _skip_curve_unsupported(backend, ec.SECP384R1())

        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PKCS8", "ec_private_key.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            )
        )
        public_key = EC_KEY_SECP384R1.public_numbers.public_key(backend)

        with pytest.raises(ValueError):
            key.exchange(ec.ECDH(), public_key)
