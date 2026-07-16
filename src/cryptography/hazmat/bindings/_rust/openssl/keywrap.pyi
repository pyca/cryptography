# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import typing

from cryptography.utils import Buffer

def aes_key_wrap(
    wrapping_key: Buffer,
    key_to_wrap: Buffer,
    backend: typing.Any = None,
) -> bytes: ...
def aes_key_unwrap(
    wrapping_key: Buffer,
    wrapped_key: Buffer,
    backend: typing.Any = None,
) -> bytes: ...
def aes_key_wrap_with_padding(
    wrapping_key: Buffer,
    key_to_wrap: Buffer,
    backend: typing.Any = None,
) -> bytes: ...
def aes_key_unwrap_with_padding(
    wrapping_key: Buffer,
    wrapped_key: Buffer,
    backend: typing.Any = None,
) -> bytes: ...
