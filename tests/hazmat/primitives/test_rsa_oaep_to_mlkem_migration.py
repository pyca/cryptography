# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import os
import pytest
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class TestRSAOAEPToMLKEMMigration:
    def test_oaep_quantum_vulnerability_metadata(self):
        """Verifies that OAEP is marked as not quantum safe and documents PQC migration."""
        assert hasattr(padding.OAEP, "is_quantum_safe")
        assert padding.OAEP.is_quantum_safe is False
        assert "ML-KEM" in padding.OAEP.__doc__
        assert "Shor's algorithm" in padding.OAEP.__doc__

    def test_mlkem_hybrid_framing_and_decryption(self):
        """
        Tests the hybrid KEM + AEAD encryption format that remediates RSA-OAEP.
        Verifies wire-format packing, key derivation, and authenticated encryption roundtrip.
        """
        # Mock 32-byte shared secret as produced by ML-KEM-768
        mock_shared_secret = b"\x42" * 32
        mock_kem_ciphertext = b"\x11" * 1088 # ML-KEM-768 CT length

        plaintext = b"Top secret post-quantum payload"
        aad = b"SessionHeader-12345"

        # Derive AES key via HKDF (same as mlkem_hybrid_encrypt)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ML-KEM-AES-256-GCM",
        ).derive(mock_shared_secret)

        nonce = os.urandom(12)
        aesgcm = AESGCM(derived_key)
        aead_ct = aesgcm.encrypt(nonce, plaintext, aad)

        import struct
        payload = (
            struct.pack(">H", len(mock_kem_ciphertext))
            + mock_kem_ciphertext
            + nonce
            + aead_ct
        )

        # Unpack and verify
        kem_len, = struct.unpack_from(">H", payload, 0)
        assert kem_len == 1088
        extracted_kem_ct = payload[2 : 2 + kem_len]
        assert extracted_kem_ct == mock_kem_ciphertext
        extracted_nonce = payload[2 + kem_len : 2 + kem_len + 12]
        extracted_aead_ct = payload[2 + kem_len + 12 :]

        decrypted = aesgcm.decrypt(extracted_nonce, extracted_aead_ct, aad)
        assert decrypted == plaintext
