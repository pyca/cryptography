# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

"""
Tests for HPKE (Hybrid Public Key Encryption) implementation.
"""

import pytest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hpke import (
    AEAD,
    KDF,
    KEM,
    MessageLimitReachedError,
    Suite,
)


# Nenc for X25519
NENC = 32


@pytest.mark.supported(
    only_if=lambda backend: backend.x25519_supported(),
    skip_message="Requires OpenSSL with X25519 support",
)
class TestHPKEBasicFunctionality:
    """Test basic HPKE functionality."""

    def test_roundtrip(self):
        """Test basic encryption/decryption."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        # Sender side
        sender = suite.sender(pk_r, info=b"test")
        ciphertext = sender.encrypt(b"Hello, HPKE!", b"additional data")
        # First message returns enc || ciphertext
        enc = ciphertext[:NENC]
        ct = ciphertext[NENC:]

        # Recipient side
        recipient = suite.recipient(enc, sk_r, info=b"test")
        plaintext = recipient.decrypt(ct, b"additional data")

        assert plaintext == b"Hello, HPKE!"

    def test_roundtrip_no_aad(self):
        """Test encryption/decryption without AAD."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)
        ciphertext = sender.encrypt(b"Hello!")
        enc = ciphertext[:NENC]
        ct = ciphertext[NENC:]

        recipient = suite.recipient(enc, sk_r)
        plaintext = recipient.decrypt(ct)

        assert plaintext == b"Hello!"

    def test_wrong_key_fails(self):
        """Test that decryption with wrong key fails."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()
        sk_wrong = x25519.X25519PrivateKey.generate()

        sender = suite.sender(pk_r)
        ciphertext = sender.encrypt(b"Secret message")
        enc = ciphertext[:NENC]
        ct = ciphertext[NENC:]

        recipient = suite.recipient(enc, sk_wrong)
        with pytest.raises(InvalidTag):
            recipient.decrypt(ct)

    def test_wrong_aad_fails(self):
        """Test that decryption with wrong AAD fails."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)
        ciphertext = sender.encrypt(b"Secret message", b"correct aad")
        enc = ciphertext[:NENC]
        ct = ciphertext[NENC:]

        recipient = suite.recipient(enc, sk_r)
        with pytest.raises(InvalidTag):
            recipient.decrypt(ct, b"wrong aad")

    def test_multiple_messages(self):
        """Test encrypting/decrypting multiple messages with same context."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)

        # First message includes enc
        first_ct = sender.encrypt(b"Message 1")
        enc = first_ct[:NENC]
        ct1 = first_ct[NENC:]

        # Subsequent messages don't include enc
        ct2 = sender.encrypt(b"Message 2")
        ct3 = sender.encrypt(b"Message 3")

        recipient = suite.recipient(enc, sk_r)
        assert recipient.decrypt(ct1) == b"Message 1"
        assert recipient.decrypt(ct2) == b"Message 2"
        assert recipient.decrypt(ct3) == b"Message 3"

    def test_info_mismatch_fails(self):
        """Test that mismatched info strings cause decryption failure."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r, info=b"sender info")
        ciphertext = sender.encrypt(b"Secret")
        enc = ciphertext[:NENC]
        ct = ciphertext[NENC:]

        recipient = suite.recipient(enc, sk_r, info=b"different info")
        with pytest.raises(InvalidTag):
            recipient.decrypt(ct)

    def test_first_encrypt_returns_enc_concatenated(self):
        """Test that first encrypt() returns enc || ciphertext."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)

        # First message should be enc (32 bytes) + ciphertext
        first_ct = sender.encrypt(b"First")
        # plaintext (5) + tag (16) + enc (32) = 53
        assert len(first_ct) == 5 + 16 + NENC

        # Second message should be just ciphertext
        second_ct = sender.encrypt(b"Second")
        # plaintext (6) + tag (16) = 22
        assert len(second_ct) == 6 + 16

    def test_empty_plaintext(self):
        """Test encryption/decryption of empty plaintext."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)
        ciphertext = sender.encrypt(b"")
        enc = ciphertext[:NENC]
        ct = ciphertext[NENC:]

        recipient = suite.recipient(enc, sk_r)
        plaintext = recipient.decrypt(ct)

        assert plaintext == b""

    def test_large_plaintext(self):
        """Test encryption/decryption of large plaintext."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        large_message = b"A" * 100000

        sender = suite.sender(pk_r)
        ciphertext = sender.encrypt(large_message)
        enc = ciphertext[:NENC]
        ct = ciphertext[NENC:]

        recipient = suite.recipient(enc, sk_r)
        plaintext = recipient.decrypt(ct)

        assert plaintext == large_message


@pytest.mark.supported(
    only_if=lambda backend: backend.x25519_supported(),
    skip_message="Requires OpenSSL with X25519 support",
)
class TestHPKEErrorCases:
    """Test error handling in HPKE."""

    def test_message_limit_sender(self):
        """Test that message limit is enforced for sender."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)
        # Manually set seq to max to trigger limit
        sender._seq = sender._max_seq

        with pytest.raises(MessageLimitReachedError):
            sender.encrypt(b"test")

    def test_message_limit_recipient(self):
        """Test that message limit is enforced for recipient."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)
        ciphertext = sender.encrypt(b"test")
        enc = ciphertext[:NENC]
        ct = ciphertext[NENC:]

        recipient = suite.recipient(enc, sk_r)
        # Manually set seq to max to trigger limit
        recipient._seq = recipient._max_seq

        with pytest.raises(MessageLimitReachedError):
            recipient.decrypt(ct)

    def test_corrupted_ciphertext(self):
        """Test that corrupted ciphertext fails decryption."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)
        ciphertext = sender.encrypt(b"test")
        enc = ciphertext[:NENC]
        ct = ciphertext[NENC:]

        # Corrupt the ciphertext
        corrupted = bytes([ct[0] ^ 0xFF]) + ct[1:]

        recipient = suite.recipient(enc, sk_r)
        with pytest.raises(InvalidTag):
            recipient.decrypt(corrupted)

    def test_truncated_ciphertext(self):
        """Test that truncated ciphertext fails decryption."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)
        ciphertext = sender.encrypt(b"test")
        enc = ciphertext[:NENC]
        ct = ciphertext[NENC:]

        # Truncate the ciphertext
        truncated = ct[:-1]

        recipient = suite.recipient(enc, sk_r)
        with pytest.raises(InvalidTag):
            recipient.decrypt(truncated)
