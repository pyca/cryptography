# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii

import pytest

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.backends.interfaces import EllipticCurveBackend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


_DIGESTS = {
    "SHA-1": hashes.SHA1(),
    "SHA-224": hashes.SHA224(),
    "SHA-256": hashes.SHA256(),
    "SHA-384": hashes.SHA384(),
    "SHA-512": hashes.SHA512(),
}


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
@pytest.mark.wycheproof_tests(
    "ecdsa_test.json",
    "ecdsa_brainpoolP224r1_sha224_test.json",
    "ecdsa_brainpoolP256r1_sha256_test.json",
    "ecdsa_brainpoolP320r1_sha384_test.json",
    "ecdsa_brainpoolP384r1_sha384_test.json",
    "ecdsa_brainpoolP512r1_sha512_test.json",
    "ecdsa_secp224r1_sha224_test.json",
    "ecdsa_secp224r1_sha256_test.json",
    "ecdsa_secp224r1_sha512_test.json",
    "ecdsa_secp256k1_sha256_test.json",
    "ecdsa_secp256k1_sha512_test.json",
    "ecdsa_secp256r1_sha256_test.json",
    "ecdsa_secp256r1_sha512_test.json",
    "ecdsa_secp384r1_sha384_test.json",
    "ecdsa_secp384r1_sha512_test.json",
    "ecdsa_secp521r1_sha512_test.json",
)
def test_ecdsa_signature(backend, wycheproof):
    try:
        key = serialization.load_der_public_key(
            binascii.unhexlify(wycheproof.testgroup["keyDer"]), backend
        )
    except (UnsupportedAlgorithm, ValueError):
        # In OpenSSL 1.0.1, some keys fail to load with ValueError, instead of
        # Unsupported Algorithm. We can remove handling for that exception
        # when we drop support.
        pytest.skip(
            "unable to load key (curve {})".format(
                wycheproof.testgroup["key"]["curve"]
            )
        )
    digest = _DIGESTS[wycheproof.testgroup["sha"]]

    if (
        wycheproof.valid or
        (wycheproof.acceptable and not wycheproof.has_flag("MissingZero"))
    ):
        key.verify(
            binascii.unhexlify(wycheproof.testcase["sig"]),
            binascii.unhexlify(wycheproof.testcase["msg"]),
            ec.ECDSA(digest),
        )
    else:
        with pytest.raises(InvalidSignature):
            key.verify(
                binascii.unhexlify(wycheproof.testcase["sig"]),
                binascii.unhexlify(wycheproof.testcase["msg"]),
                ec.ECDSA(digest),
            )
