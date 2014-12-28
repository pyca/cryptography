# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import six

from cryptography import utils
from cryptography.exceptions import AlreadyFinalized
from cryptography.hazmat.bindings.utils import LazyLibrary, build_ffi
from cryptography.hazmat.primitives import interfaces


TYPES = """
uint8_t Cryptography_check_pkcs7_padding(const uint8_t *, uint8_t);
"""

FUNCTIONS = """
/* Returns the value of the input with the most-significant-bit copied to all
   of the bits. */
static uint8_t Cryptography_DUPLICATE_MSB_TO_ALL(uint8_t a) {
    return (1 - (a >> (sizeof(uint8_t) * 8 - 1))) - 1;
}

/* This returns 0xFF if a < b else 0x00, but does so in a constant time
   fashion */
static uint8_t Cryptography_constant_time_lt(uint8_t a, uint8_t b) {
    a -= b;
    return Cryptography_DUPLICATE_MSB_TO_ALL(a);
}

uint8_t Cryptography_check_pkcs7_padding(const uint8_t *data,
                                         uint8_t block_len) {
    uint8_t i;
    uint8_t pad_size = data[block_len - 1];
    uint8_t mismatch = 0;
    for (i = 0; i < block_len; i++) {
        unsigned int mask = Cryptography_constant_time_lt(i, pad_size);
        uint8_t b = data[block_len - 1 - i];
        mismatch |= (mask & (pad_size ^ b));
    }

    /* Check to make sure the pad_size was within the valid range. */
    mismatch |= ~Cryptography_constant_time_lt(0, pad_size);
    mismatch |= Cryptography_constant_time_lt(block_len, pad_size);

    /* Make sure any bits set are copied to the lowest bit */
    mismatch |= mismatch >> 4;
    mismatch |= mismatch >> 2;
    mismatch |= mismatch >> 1;
    /* Now check the low bit to see if it's set */
    return (mismatch & 1) == 0;
}
"""


_ffi = build_ffi(cdef_source=TYPES, verify_source=FUNCTIONS)
_lib = LazyLibrary(_ffi)


class PKCS7(object):
    def __init__(self, block_size):
        if not (0 <= block_size < 256):
            raise ValueError("block_size must be in range(0, 256).")

        if block_size % 8 != 0:
            raise ValueError("block_size must be a multiple of 8.")

        self.block_size = block_size

    def padder(self):
        return _PKCS7PaddingContext(self.block_size)

    def unpadder(self):
        return _PKCS7UnpaddingContext(self.block_size)


@utils.register_interface(interfaces.PaddingContext)
class _PKCS7PaddingContext(object):
    def __init__(self, block_size):
        self.block_size = block_size
        # TODO: more copies than necessary, we should use zero-buffer (#193)
        self._buffer = b""

    def update(self, data):
        if self._buffer is None:
            raise AlreadyFinalized("Context was already finalized.")

        if not isinstance(data, bytes):
            raise TypeError("data must be bytes.")

        self._buffer += data

        finished_blocks = len(self._buffer) // (self.block_size // 8)

        result = self._buffer[:finished_blocks * (self.block_size // 8)]
        self._buffer = self._buffer[finished_blocks * (self.block_size // 8):]

        return result

    def finalize(self):
        if self._buffer is None:
            raise AlreadyFinalized("Context was already finalized.")

        pad_size = self.block_size // 8 - len(self._buffer)
        result = self._buffer + six.int2byte(pad_size) * pad_size
        self._buffer = None
        return result


@utils.register_interface(interfaces.PaddingContext)
class _PKCS7UnpaddingContext(object):
    def __init__(self, block_size):
        self.block_size = block_size
        # TODO: more copies than necessary, we should use zero-buffer (#193)
        self._buffer = b""

    def update(self, data):
        if self._buffer is None:
            raise AlreadyFinalized("Context was already finalized.")

        if not isinstance(data, bytes):
            raise TypeError("data must be bytes.")

        self._buffer += data

        finished_blocks = max(
            len(self._buffer) // (self.block_size // 8) - 1,
            0
        )

        result = self._buffer[:finished_blocks * (self.block_size // 8)]
        self._buffer = self._buffer[finished_blocks * (self.block_size // 8):]

        return result

    def finalize(self):
        if self._buffer is None:
            raise AlreadyFinalized("Context was already finalized.")

        if len(self._buffer) != self.block_size // 8:
            raise ValueError("Invalid padding bytes.")

        valid = _lib.Cryptography_check_pkcs7_padding(
            self._buffer, self.block_size // 8
        )

        if not valid:
            raise ValueError("Invalid padding bytes.")

        pad_size = six.indexbytes(self._buffer, -1)
        res = self._buffer[:-pad_size]
        self._buffer = None
        return res
