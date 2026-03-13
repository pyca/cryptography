# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import os

from cryptography import x509
from cryptography.hazmat import asn1


@asn1.sequence
class AlgorithmIdentifier:
    algorithm: x509.ObjectIdentifier


@asn1.sequence
class OneAsymmetricKey:
    version: int
    algorithm: AlgorithmIdentifier
    private_key: bytes


# ML-DSA-PrivateKey ::= CHOICE {
#     seed        [0] IMPLICIT OCTET STRING (SIZE (32)),
#     expandedKey     OCTET STRING,
#     both            SEQUENCE { seed, expandedKey }
# }
MLDSA_SEED_BYTES = 32


def generate_mldsa44_unsupported_variant(output_dir: str) -> None:
    seed = b"\x2a" * MLDSA_SEED_BYTES
    # [0] IMPLICIT OCTET STRING: tag 0x80, length 0x20
    seed_only_privkey = b"\x80\x20" + seed

    # ML-DSA-44 OID: 2.16.840.1.101.3.4.3.17
    obj = OneAsymmetricKey(
        version=0,
        algorithm=AlgorithmIdentifier(
            algorithm=x509.ObjectIdentifier("2.16.840.1.101.3.4.3.17"),
        ),
        private_key=seed_only_privkey,
    )
    with open(os.path.join(output_dir, "mldsa44_priv.der"), "wb") as f:
        f.write(asn1.encode_der(obj))


def generate_mldsa65_noseed(output_dir: str) -> None:
    # ML-DSA-65 OID: 2.16.840.1.101.3.4.3.18
    # Generate an ML-DSA-65 PKCS#8 key whose inner privateKey is an
    # empty SEQUENCE (0x30 0x00) — i.e. the "both" SEQUENCE form with
    # no seed present. This exercises the InvalidKey error path in the
    # Rust parser when seed is None.
    obj = OneAsymmetricKey(
        version=0,
        algorithm=AlgorithmIdentifier(
            algorithm=x509.ObjectIdentifier("2.16.840.1.101.3.4.3.18"),
        ),
        private_key=b"\x30\x00",
    )
    with open(os.path.join(output_dir, "mldsa65_noseed_priv.der"), "wb") as f:
        f.write(asn1.encode_der(obj))


def main():
    output_dir = os.path.join(
        "vectors", "cryptography_vectors", "asymmetric", "MLDSA"
    )
    generate_mldsa44_unsupported_variant(output_dir)
    generate_mldsa65_noseed(output_dir)


if __name__ == "__main__":
    main()
