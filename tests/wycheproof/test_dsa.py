# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii

import pytest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.interfaces import DSABackend
from cryptography.hazmat.primitives import hashes, serialization


_DIGESTS = {
    "SHA-1": hashes.SHA1(),
    "SHA-224": hashes.SHA224(),
    "SHA-256": hashes.SHA256(),
}


@pytest.mark.requires_backend_interface(interface=DSABackend)
@pytest.mark.wycheproof_tests(
    "dsa_test.json",
)
def test_dsa_signature(backend, wycheproof):
    key = serialization.load_der_public_key(
        binascii.unhexlify(wycheproof.testgroup["keyDer"]), backend
    )
    digest = _DIGESTS[wycheproof.testgroup["sha"]]

    if (
        wycheproof.valid or (
            wycheproof.acceptable and not wycheproof.has_flag("NoLeadingZero")
        )
    ):
        key.verify(
            binascii.unhexlify(wycheproof.testcase["sig"]),
            binascii.unhexlify(wycheproof.testcase["msg"]),
            digest,
        )
    else:
        with pytest.raises(InvalidSignature):
            key.verify(
                binascii.unhexlify(wycheproof.testcase["sig"]),
                binascii.unhexlify(wycheproof.testcase["msg"]),
                digest,
            )
