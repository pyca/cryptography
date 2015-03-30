# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function


def aes_key_wrap(wrapping_key, key_to_wrap, backend):
    if len(wrapping_key) not in [16, 24, 32]:
        raise ValueError("The wrapping key must be a valid AES key length")

    if len(key_to_wrap) < 16:
        raise ValueError("The key to wrap must be at least 16 bytes")

    if len(key_to_wrap) % 8 != 0:
        raise ValueError("The key to wrap must be a multiple of 8 bytes")

    # TODO: backend test for key wrap support?
    # TODO: multibackend support
    return backend.aes_key_wrap(wrapping_key, key_to_wrap)


def aes_key_unwrap(wrapping_key, wrapped_key, backend):
    if len(wrapped_key) < 24:
        raise ValueError("Must be at least 24 bytes")

    if len(wrapped_key) % 8 != 0:
        raise ValueError("The wrapped key must be a multiple of 8 bytes")

    if len(wrapping_key) not in [16, 24, 32]:
        raise ValueError("The wrapping key must be a valid AES key length")

    return backend.aes_key_unwrap(wrapping_key, wrapped_key)


class InvalidUnwrap(Exception):
    pass
