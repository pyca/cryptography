# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import binascii
import copy
import dataclasses
import os

import pytest

from cryptography.exceptions import InvalidSignature, _Reasons
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MlDsa44PrivateKey,
    MlDsa44PublicKey,
    MlDsa65PrivateKey,
    MlDsa65PublicKey,
)

from ...doubles import DummyKeySerializationEncryption
from ...utils import (
    load_nist_vectors,
    load_vectors_from_file,
    raises_unsupported_algorithm,
)


@dataclasses.dataclass
class MlDsaVariant:
    private_key_class: type
    public_key_class: type
    pub_key_size: int
    sig_size: int
    seed_size: int


ML_DSA_VARIANTS = [
    pytest.param(
        MlDsaVariant(
            private_key_class=MlDsa44PrivateKey,
            public_key_class=MlDsa44PublicKey,
            pub_key_size=1312,
            sig_size=2420,
            seed_size=32,
        ),
        id="ML-DSA-44",
    ),
    pytest.param(
        MlDsaVariant(
            private_key_class=MlDsa65PrivateKey,
            public_key_class=MlDsa65PublicKey,
            pub_key_size=1952,
            sig_size=3309,
            seed_size=32,
        ),
        id="ML-DSA-65",
    ),
]


@pytest.mark.supported(
    only_if=lambda backend: not backend.mldsa_supported(),
    skip_message="Requires a backend without ML-DSA support",
)
def test_mldsa_unsupported(backend):
    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MlDsa44PublicKey.from_public_bytes(b"0" * 1312)

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MlDsa44PrivateKey.from_seed_bytes(b"0" * 32)

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MlDsa44PrivateKey.generate()

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MlDsa65PublicKey.from_public_bytes(b"0" * 1952)

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MlDsa65PrivateKey.from_seed_bytes(b"0" * 32)

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MlDsa65PrivateKey.generate()


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa_supported(),
    skip_message="Requires a backend with ML-DSA support",
)
class TestMlDsa:
    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_sign_verify(self, variant, backend):
        key = variant.private_key_class.generate()
        sig = key.sign(b"test data")
        key.public_key().verify(sig, b"test data")

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_sign_verify_empty_message(self, variant, backend):
        key = variant.private_key_class.generate()
        sig = key.sign(b"")
        key.public_key().verify(sig, b"")

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    @pytest.mark.parametrize(
        "ctx",
        [
            b"ctx",
            b"a" * 255,
        ],
    )
    def test_sign_verify_with_context(self, variant, backend, ctx):
        key = variant.private_key_class.generate()
        sig = key.sign(b"test data", ctx)
        key.public_key().verify(sig, b"test data", ctx)

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_empty_context_equivalence(self, variant, backend):
        key = variant.private_key_class.generate()
        pub = key.public_key()
        data = b"test data"
        sig = key.sign(data)
        pub.verify(sig, data, b"")
        sig2 = key.sign(data, b"")
        pub.verify(sig2, data)

    def test_kat_vectors_44(self, backend, subtests):
        vectors = load_vectors_from_file(
            os.path.join("asymmetric", "MLDSA", "kat_MLDSA_44_det_pure.rsp"),
            load_nist_vectors,
        )
        for vector in vectors:
            with subtests.test():
                xi = binascii.unhexlify(vector["xi"])
                pk = binascii.unhexlify(vector["pk"])
                msg = binascii.unhexlify(vector["msg"])
                ctx = binascii.unhexlify(vector["ctx"])
                sm = binascii.unhexlify(vector["sm"])
                expected_sig = sm[:2420]

                key = MlDsa44PrivateKey.from_seed_bytes(xi)
                assert key.private_bytes_raw() == xi
                assert key.public_key().public_bytes_raw() == pk

                pub = MlDsa44PublicKey.from_public_bytes(pk)
                pub.verify(expected_sig, msg, ctx)

    def test_kat_vectors_65(self, backend, subtests):
        vectors = load_vectors_from_file(
            os.path.join("asymmetric", "MLDSA", "kat_MLDSA_65_det_pure.rsp"),
            load_nist_vectors,
        )
        for vector in vectors:
            with subtests.test():
                xi = binascii.unhexlify(vector["xi"])
                pk = binascii.unhexlify(vector["pk"])
                msg = binascii.unhexlify(vector["msg"])
                ctx = binascii.unhexlify(vector["ctx"])
                sm = binascii.unhexlify(vector["sm"])
                expected_sig = sm[:3309]

                key = MlDsa65PrivateKey.from_seed_bytes(xi)
                assert key.private_bytes_raw() == xi
                assert key.public_key().public_bytes_raw() == pk

                pub = MlDsa65PublicKey.from_public_bytes(pk)
                pub.verify(expected_sig, msg, ctx)

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_private_bytes_raw_round_trip(self, variant, backend):
        key = variant.private_key_class.generate()
        seed = key.private_bytes_raw()
        assert len(seed) == variant.seed_size
        key2 = variant.private_key_class.from_seed_bytes(seed)
        assert key2.private_bytes_raw() == seed
        assert seed == key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

        pub = key.public_key()
        raw_pub = pub.public_bytes_raw()
        assert len(raw_pub) == variant.pub_key_size
        pub2 = variant.public_key_class.from_public_bytes(raw_pub)
        assert pub2.public_bytes_raw() == raw_pub

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    @pytest.mark.parametrize(
        ("encoding", "fmt", "encryption", "passwd", "load_func"),
        [
            (
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
                None,
                serialization.load_pem_private_key,
            ),
            (
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
                None,
                serialization.load_der_private_key,
            ),
            (
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(b"password"),
                b"password",
                serialization.load_pem_private_key,
            ),
            (
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(b"password"),
                b"password",
                serialization.load_der_private_key,
            ),
        ],
    )
    def test_round_trip_private_serialization(
        self, variant, encoding, fmt, encryption, passwd, load_func, backend
    ):
        key = variant.private_key_class.generate()
        serialized = key.private_bytes(encoding, fmt, encryption)
        loaded_key = load_func(serialized, passwd, backend)
        assert isinstance(loaded_key, variant.private_key_class)
        assert loaded_key.private_bytes_raw() == key.private_bytes_raw()
        sig = loaded_key.sign(b"test data")
        key.public_key().verify(sig, b"test data")

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    @pytest.mark.parametrize(
        ("encoding", "fmt", "load_func"),
        [
            (
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
                serialization.load_pem_public_key,
            ),
            (
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
                serialization.load_der_public_key,
            ),
        ],
    )
    def test_round_trip_public_serialization(
        self, variant, encoding, fmt, load_func, backend
    ):
        key = variant.private_key_class.generate()
        pub = key.public_key()
        serialized = pub.public_bytes(encoding, fmt)
        loaded_pub = load_func(serialized, backend)
        assert isinstance(loaded_pub, variant.public_key_class)
        assert loaded_pub == pub

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_invalid_signature(self, variant, backend):
        key = variant.private_key_class.generate()
        sig = key.sign(b"test data")
        with pytest.raises(InvalidSignature):
            key.public_key().verify(sig, b"wrong data")

        with pytest.raises(InvalidSignature):
            key.public_key().verify(b"0" * variant.sig_size, b"test data")

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_context_wrong_context(self, variant, backend):
        key = variant.private_key_class.generate()
        sig = key.sign(b"test data", b"ctx-a")
        with pytest.raises(InvalidSignature):
            key.public_key().verify(sig, b"test data", b"ctx-b")

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_context_too_long(self, variant, backend):
        key = variant.private_key_class.generate()
        with pytest.raises(ValueError):
            key.sign(b"data", b"x" * 256)
        with pytest.raises(ValueError):
            key.public_key().verify(b"sig", b"data", b"x" * 256)

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_invalid_length_from_public_bytes(self, variant, backend):
        with pytest.raises(ValueError):
            variant.public_key_class.from_public_bytes(b"a" * 10)

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_invalid_length_from_seed_bytes(self, variant, backend):
        with pytest.raises(ValueError):
            variant.private_key_class.from_seed_bytes(b"a" * 10)

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_invalid_type_public_bytes(self, variant, backend):
        with pytest.raises(TypeError):
            variant.public_key_class.from_public_bytes(object())

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_invalid_type_seed_bytes(self, variant, backend):
        with pytest.raises(TypeError):
            variant.private_key_class.from_seed_bytes(object())

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_invalid_private_bytes(self, variant, backend):
        key = variant.private_key_class.generate()
        with pytest.raises(TypeError):
            key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                None,
            )
        with pytest.raises(ValueError):
            key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                DummyKeySerializationEncryption(),
            )

        with pytest.raises(ValueError):
            key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.PKCS8,
                DummyKeySerializationEncryption(),
            )

        with pytest.raises(ValueError):
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_invalid_public_bytes(self, variant, backend):
        key = variant.private_key_class.generate().public_key()
        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )

        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.PKCS1,
            )

        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.Raw,
            )

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_public_key_equality(self, variant, backend):
        key = variant.private_key_class.generate()
        pub1 = key.public_key()
        pub2 = key.public_key()
        pub3 = variant.private_key_class.generate().public_key()
        assert pub1 == pub2
        assert pub1 != pub3
        assert pub1 != object()

        with pytest.raises(TypeError):
            pub1 < pub2

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_public_key_copy(self, variant, backend):
        key = variant.private_key_class.generate()
        pub1 = key.public_key()
        pub2 = copy.copy(pub1)
        assert pub1 == pub2

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_public_key_deepcopy(self, variant, backend):
        key = variant.private_key_class.generate()
        pub1 = key.public_key()
        pub2 = copy.deepcopy(pub1)
        assert pub1 == pub2

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_private_key_copy(self, variant, backend):
        key1 = variant.private_key_class.generate()
        key2 = copy.copy(key1)
        assert key1.private_bytes_raw() == key2.private_bytes_raw()

    @pytest.mark.parametrize("variant", ML_DSA_VARIANTS)
    def test_private_key_deepcopy(self, variant, backend):
        key1 = variant.private_key_class.generate()
        key2 = copy.deepcopy(key1)
        assert key1.private_bytes_raw() == key2.private_bytes_raw()


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa_supported(),
    skip_message="Requires a backend with ML-DSA support",
)
def test_mldsa65_private_key_no_seed(backend):
    pkcs8_der = load_vectors_from_file(
        os.path.join("asymmetric", "MLDSA", "mldsa65_noseed_priv.der"),
        lambda derfile: derfile.read(),
        mode="rb",
    )
    with pytest.raises(ValueError):
        serialization.load_der_private_key(
            pkcs8_der, password=None, backend=backend
        )
