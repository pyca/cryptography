# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc

import six

from cryptography import utils
from cryptography.exceptions import AlreadyFinalized
from cryptography.hazmat.bindings._padding import lib


@six.add_metaclass(abc.ABCMeta)
class PaddingContext(object):
    @abc.abstractmethod
    def update(self, data):
        """
        Pads the provided bytes and returns any available data as bytes.
        """

    @abc.abstractmethod
    def finalize(self):
        """
        Finalize the padding, returns bytes.
        """


class _BytePadding(object):
    def __init__(self, block_size):
        if not (0 <= block_size < 256):
            raise ValueError("block_size must be in range(0, 256).")

        if block_size % 8 != 0:
            raise ValueError("block_size must be a multiple of 8.")

        self.block_size = block_size


class _BytePaddingContext(object):
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

    def _padding(self, size):
        return NotImplemented

    def finalize(self):
        if self._buffer is None:
            raise AlreadyFinalized("Context was already finalized.")

        pad_size = self.block_size // 8 - len(self._buffer)
        result = self._buffer + self._padding(pad_size)
        self._buffer = None
        return result


class _ByteUnpaddingContext(object):
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

    def _check_padding(self):
        return NotImplemented

    def finalize(self):
        if self._buffer is None:
            raise AlreadyFinalized("Context was already finalized.")

        if len(self._buffer) != self.block_size // 8:
            raise ValueError("Invalid padding bytes.")

        valid = self._check_padding()

        if not valid:
            raise ValueError("Invalid padding bytes.")

        pad_size = six.indexbytes(self._buffer, -1)
        res = self._buffer[:-pad_size]
        self._buffer = None
        return res


class PKCS7(_BytePadding):

    def padder(self):
        return _PKCS7PaddingContext(self.block_size)

    def unpadder(self):
        return _PKCS7UnpaddingContext(self.block_size)


@utils.register_interface(PaddingContext)
class _PKCS7PaddingContext(_BytePaddingContext):

    def _padding(self, size):
        return six.int2byte(size) * size


@utils.register_interface(PaddingContext)
class _PKCS7UnpaddingContext(_ByteUnpaddingContext):

    def _check_padding(self):
        return lib.Cryptography_check_pkcs7_padding(
            self._buffer, self.block_size // 8
        )


class ANSIX923(_BytePadding):

    def padder(self):
        return _ANSIX923PaddingContext(self.block_size)

    def unpadder(self):
        return _ANSIX923UnpaddingContext(self.block_size)


@utils.register_interface(PaddingContext)
class _ANSIX923PaddingContext(_BytePaddingContext):

    def _padding(self, size):
        return six.int2byte(0) * (size - 1) + six.int2byte(size)


@utils.register_interface(PaddingContext)
class _ANSIX923UnpaddingContext(_ByteUnpaddingContext):

    def _check_padding(self):
        return lib.Cryptography_check_ansix923_padding(
            self._buffer, self.block_size // 8
        )
