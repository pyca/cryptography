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


def main():
    output_dir = os.path.join(
        "vectors", "cryptography_vectors", "asymmetric", "MLDSA"
    )

    priv_path = os.path.join(output_dir, "mldsa44_priv.der")

    # ML-DSA-44 OID: 2.16.840.1.101.3.4.3.17
    # Construct a PKCS#8 OneAsymmetricKey with a fixed 32-byte seed.
    #
    # The privateKey content uses the seed-only CHOICE variant:
    #   ML-DSA-PrivateKey ::= CHOICE {
    #     seed        [0] IMPLICIT OCTET STRING (SIZE (32)),
    #     expandedKey     OCTET STRING,
    #     both            SEQUENCE { seed, expandedKey }
    #   }
    seed = b"\x2a" * 32
    # [0] IMPLICIT OCTET STRING: tag 0x80, length 0x20
    seed_only_privkey = b"\x80\x20" + seed

    obj = OneAsymmetricKey(
        version=0,
        algorithm=AlgorithmIdentifier(
            algorithm=x509.ObjectIdentifier("2.16.840.1.101.3.4.3.17"),
        ),
        private_key=seed_only_privkey,
    )

    pkcs8_der = asn1.encode_der(obj)

    with open(priv_path, "wb") as f:
        f.write(pkcs8_der)


if __name__ == "__main__":
    main()
