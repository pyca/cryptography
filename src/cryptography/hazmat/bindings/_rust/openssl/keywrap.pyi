# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import typing

def aes_key_wrap(
    wrapping_key: bytes,
    key_to_wrap: bytes,
    backend: typing.Any = None,
) -> bytes: ...
def aes_key_unwrap(
    wrapping_key: bytes,
    wrapped_key: bytes,
    backend: typing.Any = None,
) -> bytes: ...
def aes_key_wrap_with_padding(
    wrapping_key: bytes,
    key_to_wrap: bytes,
    backend: typing.Any = None,
) -> bytes: ...
def aes_key_unwrap_with_padding(
    wrapping_key: bytes,
    wrapped_key: bytes,
    backend: typing.Any = None,
) -> bytes: ...
