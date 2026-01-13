# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import dataclasses
import enum

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.utils import int_to_bytes

_HPKE_VERSION = b"HPKE-v1"


class KEM(enum.Enum):
    """Key Encapsulation Mechanisms for HPKE."""

    X25519 = 0x0020


class KDF(enum.Enum):
    """Key Derivation Functions for HPKE."""

    HKDF_SHA256 = 0x0001


class AEAD(enum.Enum):
    """Authenticated Encryption with Associated Data algorithms for HPKE."""

    AES_128_GCM = 0x0001


@dataclasses.dataclass(frozen=True)
class _KEMParams:
    id: int
    nsecret: int
    nenc: int
    npk: int
    nsk: int
    hash: hashes.HashAlgorithm


@dataclasses.dataclass(frozen=True)
class _KDFParams:
    id: int
    nh: int
    hash: hashes.HashAlgorithm


@dataclasses.dataclass(frozen=True)
class _AEADParams:
    id: int
    nk: int
    nn: int
    nt: int


def _xor(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def _get_kem_params(kem: KEM) -> _KEMParams:
    """Get parameters for a KEM."""
    assert kem == KEM.X25519
    return _KEMParams(
        id=0x0020,
        nsecret=32,
        nenc=32,
        npk=32,
        nsk=32,
        hash=hashes.SHA256(),
    )


def _get_kdf_params(kdf: KDF) -> _KDFParams:
    """Get parameters for a KDF."""
    assert kdf == KDF.HKDF_SHA256
    return _KDFParams(
        id=0x0001,
        nh=32,
        hash=hashes.SHA256(),
    )


def _get_aead_params(aead: AEAD) -> _AEADParams:
    """Get parameters for an AEAD."""
    assert aead == AEAD.AES_128_GCM
    return _AEADParams(
        id=0x0001,
        nk=16,
        nn=12,
        nt=16,
    )


class MessageLimitReachedError(Exception):
    """Raised when the message limit for a context is reached."""

    pass


class SenderContext:
    """
    HPKE sender context for encryption.

    Use this to encrypt multiple messages to the same recipient.
    Access the encapsulated key via the `enc` property.
    """

    def __init__(
        self,
        enc: bytes,
        key: bytes,
        base_nonce: bytes,
        aead: AEAD,
    ) -> None:
        self._enc = enc
        self._key = key
        self._base_nonce = base_nonce
        self._seq = 0
        self._max_seq = (1 << (8 * len(base_nonce))) - 1
        self._aead_type = aead
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
            The ciphertext.

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
        aead: AEAD,
    ) -> None:
        self._key = key
        self._base_nonce = base_nonce
        self._seq = 0
        self._max_seq = (1 << (8 * len(base_nonce))) - 1
        self._aead_type = aead
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
        pt = self._aead.decrypt(nonce, ciphertext, aad)
        self._seq += 1
        return pt


class Suite:
    """
    HPKE cipher suite combining a KEM, KDF, and AEAD.

    Example::

        from cryptography.hazmat.primitives.hpke import Suite, KEM, KDF, AEAD
        from cryptography.hazmat.primitives.asymmetric import x25519

        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        # Generate recipient keys
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Sender side
        sender = suite.sender(public_key, info=b"app info")
        enc = sender.enc  # encapsulated key to send to recipient
        ciphertext = sender.encrypt(b"secret message")

        # Recipient side
        recipient = suite.recipient(enc, private_key, info=b"app info")
        plaintext = recipient.decrypt(ciphertext)
    """

    def __init__(self, kem: KEM, kdf: KDF, aead: AEAD) -> None:
        """
        Create an HPKE cipher suite.

        Args:
            kem: The Key Encapsulation Mechanism to use.
            kdf: The Key Derivation Function to use.
            aead: The AEAD algorithm to use.
        """
        self._kem = kem
        self._kdf = kdf
        self._aead = aead

        self._kem_params = _get_kem_params(kem)
        self._kdf_params = _get_kdf_params(kdf)
        self._aead_params = _get_aead_params(aead)

        # Build suite IDs
        self._kem_suite_id = b"KEM" + int_to_bytes(self._kem_params.id, 2)
        self._hpke_suite_id = (
            b"HPKE"
            + int_to_bytes(self._kem_params.id, 2)
            + int_to_bytes(self._kdf_params.id, 2)
            + int_to_bytes(self._aead_params.id, 2)
        )

    def _kem_labeled_extract(
        self, salt: bytes, label: bytes, ikm: bytes
    ) -> bytes:
        """LabeledExtract for KEM as defined in RFC 9180."""
        labeled_ikm = _HPKE_VERSION + self._kem_suite_id + label + ikm
        return HKDF.extract(
            self._kdf_params.hash,
            salt if salt else None,
            labeled_ikm,
        )

    def _kem_labeled_expand(
        self, prk: bytes, label: bytes, info: bytes, length: int
    ) -> bytes:
        """LabeledExpand for KEM as defined in RFC 9180."""
        labeled_info = (
            int_to_bytes(length, 2)
            + _HPKE_VERSION
            + self._kem_suite_id
            + label
            + info
        )
        hkdf_expand = HKDFExpand(
            algorithm=self._kdf_params.hash,
            length=length,
            info=labeled_info,
        )
        return hkdf_expand.derive(prk)

    def _extract_and_expand(self, dh: bytes, kem_context: bytes) -> bytes:
        """ExtractAndExpand as defined in RFC 9180."""
        eae_prk = self._kem_labeled_extract(b"", b"eae_prk", dh)
        shared_secret = self._kem_labeled_expand(
            eae_prk,
            b"shared_secret",
            kem_context,
            self._kem_params.nsecret,
        )
        return shared_secret

    def _encap(self, pk_r: x25519.X25519PublicKey) -> tuple[bytes, bytes]:
        """Encapsulate: generate shared secret and encapsulated key."""
        sk_e = x25519.X25519PrivateKey.generate()
        pk_e = sk_e.public_key()
        dh = sk_e.exchange(pk_r)
        enc = pk_e.public_bytes_raw()
        pk_rm = pk_r.public_bytes_raw()
        kem_context = enc + pk_rm
        shared_secret = self._extract_and_expand(dh, kem_context)
        return shared_secret, enc

    def _decap(self, enc: bytes, sk_r: x25519.X25519PrivateKey) -> bytes:
        """Decapsulate: recover shared secret from encapsulated key."""
        pk_e = x25519.X25519PublicKey.from_public_bytes(enc)
        dh = sk_r.exchange(pk_e)
        pk_rm = sk_r.public_key().public_bytes_raw()
        kem_context = enc + pk_rm
        shared_secret = self._extract_and_expand(dh, kem_context)
        return shared_secret

    def _hpke_labeled_extract(
        self, salt: bytes, label: bytes, ikm: bytes
    ) -> bytes:
        """LabeledExtract for HPKE context as defined in RFC 9180."""
        labeled_ikm = _HPKE_VERSION + self._hpke_suite_id + label + ikm
        return HKDF.extract(
            self._kdf_params.hash,
            salt if salt else None,
            labeled_ikm,
        )

    def _hpke_labeled_expand(
        self, prk: bytes, label: bytes, info: bytes, length: int
    ) -> bytes:
        """LabeledExpand for HPKE context as defined in RFC 9180."""
        labeled_info = (
            int_to_bytes(length, 2)
            + _HPKE_VERSION
            + self._hpke_suite_id
            + label
            + info
        )
        hkdf_expand = HKDFExpand(
            algorithm=self._kdf_params.hash,
            length=length,
            info=labeled_info,
        )
        return hkdf_expand.derive(prk)

    def _key_schedule(
        self, shared_secret: bytes, info: bytes
    ) -> tuple[bytes, bytes]:
        """Run the HPKE key schedule for Base mode."""
        mode = 0x00  # Base mode

        psk_id_hash = self._hpke_labeled_extract(b"", b"psk_id_hash", b"")
        info_hash = self._hpke_labeled_extract(b"", b"info_hash", info)
        key_schedule_context = bytes([mode]) + psk_id_hash + info_hash

        secret = self._hpke_labeled_extract(shared_secret, b"secret", b"")

        key = self._hpke_labeled_expand(
            secret, b"key", key_schedule_context, self._aead_params.nk
        )
        base_nonce = self._hpke_labeled_expand(
            secret,
            b"base_nonce",
            key_schedule_context,
            self._aead_params.nn,
        )

        return key, base_nonce

    def sender(
        self,
        public_key: x25519.X25519PublicKey,
        info: bytes = b"",
    ) -> SenderContext:
        """
        Create a sender context for encrypting messages.

        Args:
            public_key: The recipient's public key.
            info: Application-specific info string (optional).

        Returns:
            A SenderContext for encrypting messages.
        """
        shared_secret, enc = self._encap(public_key)
        key, base_nonce = self._key_schedule(shared_secret, info)
        return SenderContext(
            enc=enc, key=key, base_nonce=base_nonce, aead=self._aead
        )

    def recipient(
        self,
        enc: bytes,
        private_key: x25519.X25519PrivateKey,
        info: bytes = b"",
    ) -> RecipientContext:
        """
        Create a recipient context for decrypting messages.

        Args:
            enc: The encapsulated key from the sender.
            private_key: The recipient's private key.
            info: Application-specific info string (optional).

        Returns:
            A RecipientContext for decrypting messages.
        """
        shared_secret = self._decap(enc, private_key)
        key, base_nonce = self._key_schedule(shared_secret, info)
        return RecipientContext(
            key=key,
            base_nonce=base_nonce,
            aead=self._aead,
        )


__all__ = [
    "AEAD",
    "KDF",
    "KEM",
    "MessageLimitReachedError",
    "RecipientContext",
    "SenderContext",
    "Suite",
]
