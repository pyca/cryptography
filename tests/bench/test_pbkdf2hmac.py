# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def test_pbkdf2hmac(benchmark):
    def bench():
        pbkdf2 = PBKDF2HMAC(hashes.SHA256(), 64, b"salt", 512)
        pbkdf2.derive(b"0" * 64)

    benchmark(bench)
