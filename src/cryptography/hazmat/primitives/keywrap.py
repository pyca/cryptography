# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

from cryptography.hazmat.bindings._rust import openssl as rust_openssl

__all__ = [
    "InvalidUnwrap",
    "aes_key_unwrap",
    "aes_key_unwrap_with_padding",
    "aes_key_wrap",
    "aes_key_wrap_with_padding",
]


class InvalidUnwrap(Exception):
    pass


aes_key_wrap = rust_openssl.keywrap.aes_key_wrap
aes_key_unwrap = rust_openssl.keywrap.aes_key_unwrap
aes_key_wrap_with_padding = rust_openssl.keywrap.aes_key_wrap_with_padding
aes_key_unwrap_with_padding = rust_openssl.keywrap.aes_key_unwrap_with_padding
