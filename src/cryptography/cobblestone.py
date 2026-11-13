# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import mmap
import os
import threading
import typing

from cryptography.hazmat.bindings._rust import (
    cobblestone as _cobblestone,
)
from cryptography.utils import Buffer

Cobblestone128Decryptor = _cobblestone.Cobblestone128Decryptor
Cobblestone128Encryptor = _cobblestone.Cobblestone128Encryptor
Cobblestone128RangeDecryptor = _cobblestone.Cobblestone128RangeDecryptor
Cobblestone256Decryptor = _cobblestone.Cobblestone256Decryptor
Cobblestone256Encryptor = _cobblestone.Cobblestone256Encryptor
Cobblestone256RangeDecryptor = _cobblestone.Cobblestone256RangeDecryptor

# os.pread is POSIX-only. Where it exists a range can be read without a cursor
# at all, so one reader can serve concurrent requests.
_HAS_PREAD = hasattr(os, "pread")


class RangeReader(typing.Protocol):
    """The interface a range decryptor reads ciphertext through.

    Implement this to decrypt ranges out of a source this module does not
    provide a reader for, such as an object store. ``read_at`` is positional:
    it must not depend on, or disturb, any cursor, so that concurrent calls
    cannot interfere with each other.
    """

    def read_at(self, offset: int, length: int) -> Buffer:
        """Returns up to ``length`` bytes starting at ``offset``.

        Returning fewer than ``length`` bytes signals the end of the
        ciphertext, so a short read must not be used for any other reason.
        """


class BufferReader:
    """Reads ranges out of an in-memory buffer.

    ``data`` may be any bytes-like object, including an :class:`mmap.mmap` of
    a file, which allows reading ranges out of a large file without loading it
    into memory.
    """

    # mmap.mmap supports the buffer protocol but is not one of the concrete
    # types Buffer names, so it is spelled out here.
    def __init__(self, data: Buffer | mmap.mmap) -> None:
        self._data = memoryview(data).cast("B")

    def read_at(self, offset: int, length: int) -> Buffer:
        return self._data[offset : offset + length]


class FileReader:
    """Reads ranges out of an open binary file.

    ``fileobj`` must be open in binary mode and have a file descriptor. Where
    the platform provides ``pread`` the file's cursor is neither used nor
    modified, so a single reader can serve concurrent range requests;
    elsewhere reads are serialized around a seek.
    """

    def __init__(self, fileobj: typing.BinaryIO) -> None:
        self._fileobj = fileobj
        self._fd = fileobj.fileno()
        self._lock = threading.Lock()

    def read_at(self, offset: int, length: int) -> Buffer:
        if _HAS_PREAD:
            return os.pread(self._fd, length, offset)
        with self._lock:
            self._fileobj.seek(offset)
            return self._fileobj.read(length)


__all__ = [
    "BufferReader",
    "Cobblestone128Decryptor",
    "Cobblestone128Encryptor",
    "Cobblestone128RangeDecryptor",
    "Cobblestone256Decryptor",
    "Cobblestone256Encryptor",
    "Cobblestone256RangeDecryptor",
    "FileReader",
    "RangeReader",
]
