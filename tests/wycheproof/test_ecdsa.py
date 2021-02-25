# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import binascii

import pytest

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.backends.interfaces import EllipticCurveBackend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .utils import wycheproof_tests


_DIGESTS = {
    "SHA-1": hashes.SHA1(),
    "SHA-224": hashes.SHA224(),
    "SHA-256": hashes.SHA256(),
    "SHA-384": hashes.SHA384(),
    "SHA-512": hashes.SHA512(),
    "SHA3-224": hashes.SHA3_224(),
    "SHA3-256": hashes.SHA3_256(),
    "SHA3-384": hashes.SHA3_384(),
    "SHA3-512": hashes.SHA3_512(),
}


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
@wycheproof_tests(
    "ecdsa_test.json",
    "ecdsa_brainpoolP224r1_sha224_test.json",
    "ecdsa_brainpoolP256r1_sha256_test.json",
    "ecdsa_brainpoolP320r1_sha384_test.json",
    "ecdsa_brainpoolP384r1_sha384_test.json",
    "ecdsa_brainpoolP512r1_sha512_test.json",
    "ecdsa_secp224r1_sha224_test.json",
    "ecdsa_secp224r1_sha256_test.json",
    "ecdsa_secp224r1_sha512_test.json",
    "ecdsa_secp224r1_sha3_224_test.json",
    "ecdsa_secp224r1_sha3_256_test.json",
    "ecdsa_secp224r1_sha3_512_test.json",
    "ecdsa_secp256k1_sha256_test.json",
    "ecdsa_secp256k1_sha512_test.json",
    "ecdsa_secp256k1_sha3_256_test.json",
    "ecdsa_secp256k1_sha3_512_test.json",
    "ecdsa_secp256r1_sha256_test.json",
    "ecdsa_secp256r1_sha512_test.json",
    "ecdsa_secp256r1_sha3_256_test.json",
    "ecdsa_secp256r1_sha3_512_test.json",
    "ecdsa_secp384r1_sha384_test.json",
    "ecdsa_secp384r1_sha512_test.json",
    "ecdsa_secp384r1_sha3_384_test.json",
    "ecdsa_secp384r1_sha3_512_test.json",
    "ecdsa_secp521r1_sha512_test.json",
    "ecdsa_secp521r1_sha3_512_test.json",
)
def test_ecdsa_signature(backend, wycheproof):
    try:
        key = serialization.load_der_public_key(
            binascii.unhexlify(wycheproof.testgroup["keyDer"]), backend
        )
        assert isinstance(key, ec.EllipticCurvePublicKey)
    except (UnsupportedAlgorithm, ValueError):
        # In some OpenSSL 1.0.2s, some keys fail to load with ValueError,
        # instead of  Unsupported Algorithm. We can remove handling for that
        # exception when we drop support.
        pytest.skip(
            "unable to load key (curve {})".format(
                wycheproof.testgroup["key"]["curve"]
            )
        )
    digest = _DIGESTS[wycheproof.testgroup["sha"]]

    if not backend.hash_supported(digest):
        pytest.skip("Hash {} not supported".format(digest))

    if wycheproof.valid or (
        wycheproof.acceptable and not wycheproof.has_flag("MissingZero")
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
