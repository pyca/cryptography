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
    MessageLimitReachedError,
    create_recipient,
    create_sender,
)


@pytest.mark.supported(
    only_if=lambda backend: backend.x25519_supported(),
    skip_message="Requires OpenSSL with X25519 support",
)
class TestHPKEBasicFunctionality:
    """Test basic HPKE functionality."""

    def test_roundtrip(self):
        """Test basic encryption/decryption."""
        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        # Sender side
        sender = create_sender(pk_r, info=b"test")
        ciphertext = sender.encrypt(b"Hello, HPKE!", b"additional data")
        enc = sender.enc

        # Recipient side
        recipient = create_recipient(enc, sk_r, info=b"test")
        plaintext = recipient.decrypt(ciphertext, b"additional data")

        assert plaintext == b"Hello, HPKE!"

    def test_roundtrip_no_aad(self):
        """Test encryption/decryption without AAD."""
        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = create_sender(pk_r)
        ciphertext = sender.encrypt(b"Hello!")

        recipient = create_recipient(sender.enc, sk_r)
        plaintext = recipient.decrypt(ciphertext)

        assert plaintext == b"Hello!"

    def test_wrong_key_fails(self):
        """Test that decryption with wrong key fails."""
        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()
        sk_wrong = x25519.X25519PrivateKey.generate()

        sender = create_sender(pk_r)
        ciphertext = sender.encrypt(b"Secret message")

        recipient = create_recipient(sender.enc, sk_wrong)
        with pytest.raises(InvalidTag):
            recipient.decrypt(ciphertext)

    def test_wrong_aad_fails(self):
        """Test that decryption with wrong AAD fails."""
        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = create_sender(pk_r)
        ciphertext = sender.encrypt(b"Secret message", b"correct aad")

        recipient = create_recipient(sender.enc, sk_r)
        with pytest.raises(InvalidTag):
            recipient.decrypt(ciphertext, b"wrong aad")

    def test_multiple_messages(self):
        """Test encrypting/decrypting multiple messages with same context."""
        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = create_sender(pk_r)
        recipient = create_recipient(sender.enc, sk_r)

        messages = [b"Message 1", b"Message 2", b"Message 3"]
        ciphertexts = [sender.encrypt(msg) for msg in messages]

        for ct, expected in zip(ciphertexts, messages):
            assert recipient.decrypt(ct) == expected

    def test_info_mismatch_fails(self):
        """Test that mismatched info strings cause decryption failure."""
        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = create_sender(pk_r, info=b"sender info")
        ciphertext = sender.encrypt(b"Secret")

        recipient = create_recipient(sender.enc, sk_r, info=b"different info")
        with pytest.raises(InvalidTag):
            recipient.decrypt(ciphertext)

    def test_enc_property(self):
        """Test that enc is accessible via sender.enc property."""
        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = create_sender(pk_r)
        enc = sender.enc

        # enc should be 32 bytes for X25519
        assert len(enc) == 32

        # encrypt returns just ciphertext, not enc || ciphertext
        ct1 = sender.encrypt(b"First")
        ct2 = sender.encrypt(b"Second")
        # Both ciphertexts should be similar size (plaintext + tag)
        assert abs(len(ct1) - len(ct2)) == len(b"Second") - len(b"First")

    def test_empty_plaintext(self):
        """Test encryption/decryption of empty plaintext."""
        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = create_sender(pk_r)
        ciphertext = sender.encrypt(b"")

        recipient = create_recipient(sender.enc, sk_r)
        plaintext = recipient.decrypt(ciphertext)

        assert plaintext == b""

    def test_large_plaintext(self):
        """Test encryption/decryption of large plaintext."""
        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        large_message = b"A" * 100000

        sender = create_sender(pk_r)
        ciphertext = sender.encrypt(large_message)

        recipient = create_recipient(sender.enc, sk_r)
        plaintext = recipient.decrypt(ciphertext)

        assert plaintext == large_message


@pytest.mark.supported(
    only_if=lambda backend: backend.x25519_supported(),
    skip_message="Requires OpenSSL with X25519 support",
)
class TestHPKEErrorCases:
    """Test error handling in HPKE."""

    def test_message_limit_sender(self):
        """Test that message limit is enforced for sender."""
        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = create_sender(pk_r)
        # Manually set seq to max to trigger limit
        sender._seq = sender._max_seq

        with pytest.raises(MessageLimitReachedError):
            sender.encrypt(b"test")

    def test_message_limit_recipient(self):
        """Test that message limit is enforced for recipient."""
        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = create_sender(pk_r)
        ciphertext = sender.encrypt(b"test")

        recipient = create_recipient(sender.enc, sk_r)
        # Manually set seq to max to trigger limit
        recipient._seq = recipient._max_seq

        with pytest.raises(MessageLimitReachedError):
            recipient.decrypt(ciphertext)

    def test_corrupted_ciphertext(self):
        """Test that corrupted ciphertext fails decryption."""
        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = create_sender(pk_r)
        ciphertext = sender.encrypt(b"test")

        # Corrupt the ciphertext
        corrupted = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]

        recipient = create_recipient(sender.enc, sk_r)
        with pytest.raises(InvalidTag):
            recipient.decrypt(corrupted)

    def test_truncated_ciphertext(self):
        """Test that truncated ciphertext fails decryption."""
        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = create_sender(pk_r)
        ciphertext = sender.encrypt(b"test")

        # Truncate the ciphertext
        truncated = ciphertext[:-1]

        recipient = create_recipient(sender.enc, sk_r)
        with pytest.raises(InvalidTag):
            recipient.decrypt(truncated)
