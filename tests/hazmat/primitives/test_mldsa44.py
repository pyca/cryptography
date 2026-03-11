# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import copy

import pytest

from cryptography.exceptions import InvalidSignature, _Reasons
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mldsa44 import (
    MlDsa44PrivateKey,
    MlDsa44PublicKey,
)

from ...doubles import DummyKeySerializationEncryption
from ...utils import raises_unsupported_algorithm


@pytest.mark.supported(
    only_if=lambda backend: not backend.mldsa44_supported(),
    skip_message="Requires OpenSSL without ML-DSA-44 support",
)
def test_mldsa44_unsupported(backend):
    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MlDsa44PublicKey.from_public_bytes(b"0" * 1312)

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MlDsa44PrivateKey.from_seed_bytes(b"0" * 2560)

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MlDsa44PrivateKey.generate()


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa44_supported(),
    skip_message="Requires OpenSSL with ML-DSA-44 support",
)
class TestMlDsa44Signing:
    def test_sign_verify(self, backend):
        key = MlDsa44PrivateKey.generate()
        message = b"test data"
        signature = key.sign(message)
        # ML-DSA-44 signatures are 2420 bytes according
        # to FIPS 204 section 4 table 2
        assert len(signature) == 2420
        public_key = key.public_key()
        public_key.verify(signature, message)

    def test_invalid_signature(self, backend):
        key = MlDsa44PrivateKey.generate()
        signature = key.sign(b"test data")
        with pytest.raises(InvalidSignature):
            key.public_key().verify(signature, b"wrong data")

        with pytest.raises(InvalidSignature):
            key.public_key().verify(b"0" * len(signature), b"test data")

    def test_sign_verify_buffer(self, backend):
        key = MlDsa44PrivateKey.generate()
        data = bytearray(b"test data")
        signature = key.sign(data)
        key.public_key().verify(bytearray(signature), data)

    def test_sign_verify_with_context(self, backend):
        key = MlDsa44PrivateKey.generate()
        message = b"test data"
        context = b"test context"
        signature = key.sign_with_context(message, context)
        # ML-DSA-44 signatures are 2420 bytes according
        # to FIPS 204 section 4 table 2
        assert len(signature) == 2420
        public_key = key.public_key()
        public_key.verify_with_context(signature, message, context)

    def test_sign_verify_with_empty_context(self, backend):
        key = MlDsa44PrivateKey.generate()
        message = b"test data"
        context = b""
        signature = key.sign_with_context(message, context)
        public_key = key.public_key()
        public_key.verify_with_context(signature, message, context)

    def test_sign_verify_with_context_buffer(self, backend):
        key = MlDsa44PrivateKey.generate()
        data = bytearray(b"test data")
        context = bytearray(b"test context")
        signature = key.sign_with_context(data, context)
        key.public_key().verify_with_context(
            bytearray(signature), data, context
        )

    def test_invalid_signature_with_context(self, backend):
        key = MlDsa44PrivateKey.generate()
        signature = key.sign_with_context(b"test data", b"context")
        # Wrong message
        with pytest.raises(InvalidSignature):
            key.public_key().verify_with_context(
                signature, b"wrong data", b"context"
            )
        # Wrong context
        with pytest.raises(InvalidSignature):
            key.public_key().verify_with_context(
                signature, b"test data", b"wrong context"
            )
        # Invalid signature bytes
        with pytest.raises(InvalidSignature):
            key.public_key().verify_with_context(
                b"0" * len(signature), b"test data", b"context"
            )

    def test_context_not_interchangeable(self, backend):
        key = MlDsa44PrivateKey.generate()
        message = b"test data"
        context = b"test context"

        # Sign with context
        signature_with_context = key.sign_with_context(message, context)

        # Sign without context
        signature_without_context = key.sign(message)

        public_key = key.public_key()

        # Signature with context should not verify without context
        with pytest.raises(InvalidSignature):
            public_key.verify(signature_with_context, message)

        # Signature without context should not verify with context
        with pytest.raises(InvalidSignature):
            public_key.verify_with_context(
                signature_without_context, message, context
            )

    def test_generate(self, backend):
        key = MlDsa44PrivateKey.generate()
        assert key
        assert key.public_key()

    def test_pub_priv_bytes_raw(self, backend):
        key = MlDsa44PrivateKey.generate()
        seed = key.seed_bytes()
        public_raw = key.public_key().public_bytes_raw()

        # ML-DSA-44 key sizes
        assert len(seed) == 32
        assert len(public_raw) == 1312

        # Verify we can recreate the key from the seed
        MlDsa44PrivateKey.from_seed_bytes(seed)

        # Verify we can load the public key back
        loaded_public = MlDsa44PublicKey.from_public_bytes(public_raw)

        # Verify the loaded keys work
        message = b"test"
        sig = key.sign(message)
        loaded_public.verify(sig, message)

    def test_load_public_bytes(self, backend):
        public_key = MlDsa44PrivateKey.generate().public_key()
        public_bytes = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        public_key2 = MlDsa44PublicKey.from_public_bytes(public_bytes)
        assert public_bytes == public_key2.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def test_invalid_type_public_bytes(self, backend):
        with pytest.raises(TypeError):
            MlDsa44PublicKey.from_public_bytes(
                object()  # type: ignore[arg-type]
            )

    def test_invalid_type_private_bytes(self, backend):
        with pytest.raises(TypeError):
            MlDsa44PrivateKey.from_seed_bytes(
                object()  # type: ignore[arg-type]
            )

    def test_invalid_length_from_public_bytes(self, backend):
        with pytest.raises(ValueError):
            MlDsa44PublicKey.from_public_bytes(b"a" * 1311)
        with pytest.raises(ValueError):
            MlDsa44PublicKey.from_public_bytes(b"a" * 1313)

    def test_invalid_length_from_private_bytes(self, backend):
        with pytest.raises(ValueError):
            MlDsa44PrivateKey.from_seed_bytes(b"a" * 2559)
        with pytest.raises(ValueError):
            MlDsa44PrivateKey.from_seed_bytes(b"a" * 2561)

    def test_invalid_private_bytes(self, backend):
        key = MlDsa44PrivateKey.generate()
        with pytest.raises(TypeError):
            key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                None,  # type: ignore[arg-type]
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

        with pytest.raises(ValueError):
            key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.OpenSSH,
                serialization.NoEncryption(),
            )

    def test_invalid_public_bytes(self, backend):
        key = MlDsa44PrivateKey.generate().public_key()
        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )

        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.PKCS1
            )

        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.Raw
            )

        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.OpenSSH
            )

    @pytest.mark.parametrize(
        ("encoding", "fmt", "encryption", "passwd", "load_func"),
        [
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
        ],
    )
    def test_round_trip_private_serialization(
        self, encoding, fmt, encryption, passwd, load_func, backend
    ):
        key = MlDsa44PrivateKey.generate()
        serialized = key.private_bytes(encoding, fmt, encryption)
        loaded_key = load_func(serialized, passwd, backend)
        assert isinstance(loaded_key, MlDsa44PrivateKey)


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa44_supported(),
    skip_message="Requires OpenSSL with ML-DSA-44 support",
)
def test_public_key_equality(backend):
    key1 = MlDsa44PrivateKey.generate()
    key2_priv = MlDsa44PrivateKey.generate()

    # Same key should be equal
    pub1 = key1.public_key()
    pub1_copy = key1.public_key()
    assert pub1 == pub1_copy

    # Different keys should not be equal
    pub2 = key2_priv.public_key()
    assert pub1 != pub2
    assert pub1 != object()

    with pytest.raises(TypeError):
        pub1 < pub2  # type: ignore[operator]


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa44_supported(),
    skip_message="Requires OpenSSL with ML-DSA-44 support",
)
def test_public_key_copy(backend):
    key1 = MlDsa44PrivateKey.generate().public_key()
    key2 = copy.copy(key1)
    assert key1 == key2


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa44_supported(),
    skip_message="Requires OpenSSL with ML-DSA-44 support",
)
def test_public_key_deepcopy(backend):
    key1 = MlDsa44PrivateKey.generate().public_key()
    key2 = copy.deepcopy(key1)
    assert key1 == key2


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa44_supported(),
    skip_message="Requires OpenSSL with ML-DSA-44 support",
)
def test_private_key_copy(backend):
    key1 = MlDsa44PrivateKey.generate()
    key2 = copy.copy(key1)
    # Verify both keys work correctly (ML-DSA signatures are randomized)
    message = b"test"
    sig1 = key1.sign(message)
    sig2 = key2.sign(message)
    # Verify each signature with the corresponding public key
    key1.public_key().verify(sig1, message)
    key2.public_key().verify(sig2, message)
    # Verify cross-validation works (same key material)
    key1.public_key().verify(sig2, message)
    key2.public_key().verify(sig1, message)


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa44_supported(),
    skip_message="Requires OpenSSL with ML-DSA-44 support",
)
def test_private_key_deepcopy(backend):
    key1 = MlDsa44PrivateKey.generate()
    key2 = copy.deepcopy(key1)
    # Verify both keys work correctly (ML-DSA signatures are randomized)
    message = b"test"
    sig1 = key1.sign(message)
    sig2 = key2.sign(message)
    # Verify each signature with the corresponding public key
    key1.public_key().verify(sig1, message)
    key2.public_key().verify(sig2, message)
    # Verify cross-validation works (same key material)
    key1.public_key().verify(sig2, message)
    key2.public_key().verify(sig1, message)


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa44_supported(),
    skip_message="Requires OpenSSL with ML-DSA-44 support",
)
def test_rfc9881_seed_only_format(backend):
    """
    RFC 9881 Section 6 defines ML-DSA-44-PrivateKey as a CHOICE with three
    formats:
    1. seed [0] OCTET STRING (SIZE (32)) - recommended for storage efficiency
    2. expandedKey OCTET STRING (SIZE (2560))
    3. both SEQUENCE { seed, expandedKey }

    This test verifies that serialization uses the recommended seed-only
    format with [0] IMPLICIT tag.
    """
    key = MlDsa44PrivateKey.generate()

    # Serialize to DER
    der_bytes = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Parse PKCS#8 to extract the privateKey field
    def extract_private_key_octets(der):
        """Extract the privateKey OCTET STRING value from PKCS#8"""
        offset = 0

        # Skip SEQUENCE tag and length
        assert der[offset] == 0x30  # SEQUENCE
        offset += 1
        length_byte = der[offset]
        if length_byte & 0x80:
            num_octets = length_byte & 0x7F
            offset += 1 + num_octets
        else:
            offset += 1

        # Skip version INTEGER
        assert der[offset] == 0x02  # INTEGER
        offset += 1
        version_len = der[offset]
        offset += 1 + version_len

        # Skip algorithm SEQUENCE
        assert der[offset] == 0x30  # SEQUENCE
        offset += 1
        alg_len = der[offset]
        offset += 1 + alg_len

        # Extract privateKey OCTET STRING contents
        assert der[offset] == 0x04  # OCTET STRING
        offset += 1
        pk_len = der[offset]
        offset += 1

        return der[offset : offset + pk_len]

    mldsa_value = extract_private_key_octets(der_bytes)

    # Verify RFC 9881 seed-only format: [0] IMPLICIT OCTET STRING (SIZE (32))
    # Tag 0x80 = context-specific [0] primitive
    # Length 0x20 = 32 bytes
    assert mldsa_value[0] == 0x80, (
        "Expected context-specific [0] tag for seed-only format"
    )
    assert mldsa_value[1] == 0x20, "Expected length of 32 bytes for seed"
    assert len(mldsa_value) == 34, (
        "Expected 34 total bytes (tag + length + 32-byte seed)"
    )

    # Verify the key can be loaded back
    loaded_key = serialization.load_der_private_key(der_bytes, password=None)
    assert isinstance(loaded_key, MlDsa44PrivateKey)

    # Verify loaded key works
    message = b"test message"
    signature = key.sign(message)
    loaded_key.public_key().verify(signature, message)
