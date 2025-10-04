# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def test_pbkdf2hmac(benchmark):
    def bench():
        kdf = PBKDF2HMAC(
            hashes.SHA256(),
            32,
            salt=b"0" * 16,
            iterations=100_000,
        )
        kdf.derive(b"password")

    benchmark(bench)
