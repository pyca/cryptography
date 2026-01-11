# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.utils import int_to_bytes

_HPKE_VERSION = b"HPKE-v1"

# DHKEM(X25519, HKDF-SHA256) parameters
_KEM_DHKEM_X25519_HKDF_SHA256_ID = 0x0020
_KEM_DHKEM_X25519_HKDF_SHA256_NSECRET = 32
_KEM_DHKEM_X25519_HKDF_SHA256_NENC = 32
_KEM_DHKEM_X25519_HKDF_SHA256_NPK = 32
_KEM_DHKEM_X25519_HKDF_SHA256_NSK = 32

# HKDF-SHA256 parameters
_KDF_HKDF_SHA256_ID = 0x0001
_KDF_HKDF_SHA256_NH = 32

# AES-128-GCM parameters
_AEAD_AES_128_GCM_ID = 0x0001
_AEAD_AES_128_GCM_NK = 16
_AEAD_AES_128_GCM_NN = 12
_AEAD_AES_128_GCM_NT = 16


def _xor(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


# Pre-computed suite IDs
_KEM_SUITE_ID = b"KEM" + int_to_bytes(_KEM_DHKEM_X25519_HKDF_SHA256_ID, 2)
_HPKE_SUITE_ID = (
    b"HPKE"
    + int_to_bytes(_KEM_DHKEM_X25519_HKDF_SHA256_ID, 2)
    + int_to_bytes(_KDF_HKDF_SHA256_ID, 2)
    + int_to_bytes(_AEAD_AES_128_GCM_ID, 2)
)


def _kem_labeled_extract(salt: bytes, label: bytes, ikm: bytes) -> bytes:
    """LabeledExtract for KEM as defined in RFC 9180."""
    labeled_ikm = _HPKE_VERSION + _KEM_SUITE_ID + label + ikm
    return hmac.digest(salt if salt else b"\x00" * 32, labeled_ikm, "sha256")


def _kem_labeled_expand(
    prk: bytes, label: bytes, info: bytes, length: int
) -> bytes:
    """LabeledExpand for KEM as defined in RFC 9180."""
    labeled_info = (
        int_to_bytes(length, 2) + _HPKE_VERSION + _KEM_SUITE_ID + label + info
    )
    hkdf_expand = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=labeled_info,
    )
    return hkdf_expand.derive(prk)


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    """ExtractAndExpand as defined in RFC 9180."""
    eae_prk = _kem_labeled_extract(b"", b"eae_prk", dh)
    shared_secret = _kem_labeled_expand(
        eae_prk,
        b"shared_secret",
        kem_context,
        _KEM_DHKEM_X25519_HKDF_SHA256_NSECRET,
    )
    return shared_secret


def _encap(pk_r: x25519.X25519PublicKey) -> tuple[bytes, bytes]:
    """
    Encapsulate: generate shared secret and encapsulated key.

    Returns:
        Tuple of (shared_secret, enc).
    """
    sk_e = x25519.X25519PrivateKey.generate()
    pk_e = sk_e.public_key()
    dh = sk_e.exchange(pk_r)
    enc = pk_e.public_bytes_raw()
    pk_rm = pk_r.public_bytes_raw()
    kem_context = enc + pk_rm
    shared_secret = _extract_and_expand(dh, kem_context)
    return shared_secret, enc


def _decap(enc: bytes, sk_r: x25519.X25519PrivateKey) -> bytes:
    """
    Decapsulate: recover shared secret from encapsulated key.

    Returns:
        The shared secret.
    """
    pk_e = x25519.X25519PublicKey.from_public_bytes(enc)
    dh = sk_r.exchange(pk_e)
    pk_rm = sk_r.public_key().public_bytes_raw()
    kem_context = enc + pk_rm
    shared_secret = _extract_and_expand(dh, kem_context)
    return shared_secret


def _hpke_labeled_extract(salt: bytes, label: bytes, ikm: bytes) -> bytes:
    """LabeledExtract for HPKE context as defined in RFC 9180."""
    labeled_ikm = _HPKE_VERSION + _HPKE_SUITE_ID + label + ikm
    return hmac.digest(salt if salt else b"\x00" * 32, labeled_ikm, "sha256")


def _hpke_labeled_expand(
    prk: bytes, label: bytes, info: bytes, length: int
) -> bytes:
    """LabeledExpand for HPKE context as defined in RFC 9180."""
    labeled_info = (
        int_to_bytes(length, 2) + _HPKE_VERSION + _HPKE_SUITE_ID + label + info
    )
    hkdf_expand = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=labeled_info,
    )
    return hkdf_expand.derive(prk)


def _key_schedule(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    """
    Run the HPKE key schedule for Base mode.

    Returns:
        Tuple of (key, base_nonce).
    """
    mode = 0x00  # Base mode

    psk_id_hash = _hpke_labeled_extract(b"", b"psk_id_hash", b"")
    info_hash = _hpke_labeled_extract(b"", b"info_hash", info)
    key_schedule_context = bytes([mode]) + psk_id_hash + info_hash

    secret = _hpke_labeled_extract(shared_secret, b"secret", b"")

    key = _hpke_labeled_expand(
        secret, b"key", key_schedule_context, _AEAD_AES_128_GCM_NK
    )
    base_nonce = _hpke_labeled_expand(
        secret, b"base_nonce", key_schedule_context, _AEAD_AES_128_GCM_NN
    )

    return key, base_nonce


class HPKEError(Exception):
    """Base exception for HPKE errors."""

    pass


class MessageLimitReachedError(HPKEError):
    """Raised when the message limit for a context is reached."""

    pass


class SenderContext:
    """
    HPKE sender context for encryption.

    Use this to encrypt multiple messages to the same recipient.
    """

    def __init__(
        self,
        enc: bytes,
        key: bytes,
        base_nonce: bytes,
    ) -> None:
        self._enc = enc
        self._key = key
        self._base_nonce = base_nonce
        self._seq = 0
        self._max_seq = (1 << (8 * len(base_nonce))) - 1
        self._aead = AESGCM(key)

    @property
    def enc(self) -> bytes:
        """The encapsulated key to send to the recipient."""
        return self._enc

    def _compute_nonce(self) -> bytes:
        """Compute the nonce for the current sequence number."""
        seq_bytes = int_to_bytes(self._seq, len(self._base_nonce))
        return _xor(self._base_nonce, seq_bytes)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """
        Encrypt a message.

        Args:
            plaintext: The plaintext to encrypt.
            aad: Additional authenticated data (optional).

        Returns:
            The ciphertext. Access enc via the `enc` property.

        Raises:
            MessageLimitReachedError: If the message limit is reached.
        """
        if self._seq >= self._max_seq:
            raise MessageLimitReachedError(
                "Message limit reached for this HPKE context"
            )
        nonce = self._compute_nonce()
        ct = self._aead.encrypt(nonce, plaintext, aad)
        self._seq += 1
        return ct


class RecipientContext:
    """
    HPKE recipient context for decryption.

    Use this to decrypt multiple messages from the same sender.
    """

    def __init__(
        self,
        key: bytes,
        base_nonce: bytes,
    ) -> None:
        self._key = key
        self._base_nonce = base_nonce
        self._seq = 0
        self._max_seq = (1 << (8 * len(base_nonce))) - 1
        self._aead = AESGCM(key)

    def _compute_nonce(self) -> bytes:
        """Compute the nonce for the current sequence number."""
        seq_bytes = int_to_bytes(self._seq, len(self._base_nonce))
        return _xor(self._base_nonce, seq_bytes)

    def decrypt(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypt a message.

        Args:
            ciphertext: The ciphertext to decrypt.
            aad: Additional authenticated data (optional).

        Returns:
            The plaintext.

        Raises:
            MessageLimitReachedError: If the message limit is reached.
            InvalidTag: If decryption fails (authentication failure).
        """
        if self._seq >= self._max_seq:
            raise MessageLimitReachedError(
                "Message limit reached for this HPKE context"
            )
        nonce = self._compute_nonce()
        try:
            pt = self._aead.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise InvalidTag() from e
        self._seq += 1
        return pt


def create_sender(
    public_key: x25519.X25519PublicKey, info: bytes = b""
) -> SenderContext:
    """
    Create a sender context for encrypting messages.

    This uses DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.

    Args:
        public_key: The recipient's X25519 public key.
        info: Application-specific info string (optional).

    Returns:
        A SenderContext for encrypting messages.

    Example::

        from cryptography.hazmat.primitives.hpke import (
            create_sender, create_recipient
        )
        from cryptography.hazmat.primitives.asymmetric import x25519

        # Generate recipient keys
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Sender side
        sender = create_sender(public_key, info=b"app info")
        ciphertext = sender.encrypt(b"secret message")
        enc = sender.enc  # send enc + ciphertext to recipient

        # Recipient side
        recipient = create_recipient(enc, private_key, info=b"app info")
        plaintext = recipient.decrypt(ciphertext)
    """
    shared_secret, enc = _encap(public_key)
    key, base_nonce = _key_schedule(shared_secret, info)
    return SenderContext(enc=enc, key=key, base_nonce=base_nonce)


def create_recipient(
    enc: bytes, private_key: x25519.X25519PrivateKey, info: bytes = b""
) -> RecipientContext:
    """
    Create a recipient context for decrypting messages.

    This uses DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.

    Args:
        enc: The encapsulated key from the sender.
        private_key: The recipient's X25519 private key.
        info: Application-specific info string (optional).

    Returns:
        A RecipientContext for decrypting messages.
    """
    shared_secret = _decap(enc, private_key)
    key, base_nonce = _key_schedule(shared_secret, info)
    return RecipientContext(key=key, base_nonce=base_nonce)


__all__ = [
    "HPKEError",
    "MessageLimitReachedError",
    "RecipientContext",
    "SenderContext",
    "create_recipient",
    "create_sender",
]
