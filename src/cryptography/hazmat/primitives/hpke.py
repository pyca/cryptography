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
_HPKE_MODE_BASE = 0x00


class KEM(enum.Enum):
    X25519 = "X25519"


class KDF(enum.Enum):
    HKDF_SHA256 = "HKDF_SHA256"


class AEAD(enum.Enum):
    AES_128_GCM = "AES_128_GCM"


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


def _get_kem_params(kem: KEM) -> _KEMParams:
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
    assert kdf == KDF.HKDF_SHA256
    return _KDFParams(
        id=0x0001,
        nh=32,
        hash=hashes.SHA256(),
    )


def _get_aead_params(aead: AEAD) -> _AEADParams:
    assert aead == AEAD.AES_128_GCM
    return _AEADParams(
        id=0x0001,
        nk=16,
        nn=12,
        nt=16,
    )


class Suite:
    def __init__(self, kem: KEM, kdf: KDF, aead: AEAD) -> None:
        if not isinstance(kem, KEM):
            raise TypeError("kem must be an instance of KEM")
        if not isinstance(kdf, KDF):
            raise TypeError("kdf must be an instance of KDF")
        if not isinstance(aead, AEAD):
            raise TypeError("aead must be an instance of AEAD")

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
        labeled_ikm = _HPKE_VERSION + self._kem_suite_id + label + ikm
        return HKDF.extract(
            self._kdf_params.hash,
            salt if salt else None,
            labeled_ikm,
        )

    def _kem_labeled_expand(
        self, prk: bytes, label: bytes, info: bytes, length: int
    ) -> bytes:
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
        eae_prk = self._kem_labeled_extract(b"", b"eae_prk", dh)
        shared_secret = self._kem_labeled_expand(
            eae_prk,
            b"shared_secret",
            kem_context,
            self._kem_params.nsecret,
        )
        return shared_secret

    def _encap(self, pk_r: x25519.X25519PublicKey) -> tuple[bytes, bytes]:
        sk_e = x25519.X25519PrivateKey.generate()
        pk_e = sk_e.public_key()
        dh = sk_e.exchange(pk_r)
        enc = pk_e.public_bytes_raw()
        pk_rm = pk_r.public_bytes_raw()
        kem_context = enc + pk_rm
        shared_secret = self._extract_and_expand(dh, kem_context)
        return shared_secret, enc

    def _decap(self, enc: bytes, sk_r: x25519.X25519PrivateKey) -> bytes:
        pk_e = x25519.X25519PublicKey.from_public_bytes(enc)
        dh = sk_r.exchange(pk_e)
        pk_rm = sk_r.public_key().public_bytes_raw()
        kem_context = enc + pk_rm
        shared_secret = self._extract_and_expand(dh, kem_context)
        return shared_secret

    def _hpke_labeled_extract(
        self, salt: bytes, label: bytes, ikm: bytes
    ) -> bytes:
        labeled_ikm = _HPKE_VERSION + self._hpke_suite_id + label + ikm
        return HKDF.extract(
            self._kdf_params.hash,
            salt if salt else None,
            labeled_ikm,
        )

    def _hpke_labeled_expand(
        self, prk: bytes, label: bytes, info: bytes, length: int
    ) -> bytes:
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
        mode = _HPKE_MODE_BASE

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

    def _encrypt(
        self,
        plaintext: bytes,
        public_key: x25519.X25519PublicKey,
        info: bytes,
        aad: bytes,
    ) -> bytes:
        """Internal encrypt method with AAD support for test vectors."""
        shared_secret, enc = self._encap(public_key)
        key, base_nonce = self._key_schedule(shared_secret, info)
        aead_impl = AESGCM(key)
        ct = aead_impl.encrypt(base_nonce, plaintext, aad)
        return enc + ct

    def _decrypt(
        self,
        ciphertext: bytes,
        private_key: x25519.X25519PrivateKey,
        info: bytes,
        aad: bytes,
    ) -> bytes:
        """Internal decrypt method with AAD support for test vectors."""
        nenc = self._kem_params.nenc
        enc = ciphertext[:nenc]
        ct = ciphertext[nenc:]
        shared_secret = self._decap(enc, private_key)
        key, base_nonce = self._key_schedule(shared_secret, info)
        aead_impl = AESGCM(key)
        return aead_impl.decrypt(base_nonce, ct, aad)

    def encrypt(
        self,
        plaintext: bytes,
        public_key: x25519.X25519PublicKey,
        info: bytes = b"",
    ) -> bytes:
        return self._encrypt(plaintext, public_key, info, aad=b"")

    def decrypt(
        self,
        ciphertext: bytes,
        private_key: x25519.X25519PrivateKey,
        info: bytes = b"",
    ) -> bytes:
        return self._decrypt(ciphertext, private_key, info, aad=b"")


__all__ = [
    "AEAD",
    "KDF",
    "KEM",
    "Suite",
]
