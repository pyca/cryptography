# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

class AESSIV:
    def __init__(self, key: bytes) -> None: ...
    @staticmethod
    def generate_key(key_size: int) -> bytes: ...
    def encrypt(
        self,
        data: bytes,
        associated_data: list[bytes] | None,
    ) -> bytes: ...
    def decrypt(
        self,
        data: bytes,
        associated_data: list[bytes] | None,
    ) -> bytes: ...
