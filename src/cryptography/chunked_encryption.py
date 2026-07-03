# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

from cryptography.hazmat.bindings._rust import (
    chunked_encryption as _chunked_encryption,
)

Decrypter = _chunked_encryption.Decrypter
Encrypter = _chunked_encryption.Encrypter

__all__ = [
    "Decrypter",
    "Encrypter",
]
