# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def test_hkdf(benchmark):
    def bench():
        hkdf = HKDF(
            hashes.SHA512(),
            16000,
            salt=b"salt",
            info=b"info",
        )
        hkdf.derive(b"0" * 64)

    benchmark(bench)
