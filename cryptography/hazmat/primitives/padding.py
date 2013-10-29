# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import six


class PKCS7(object):
    def __init__(self, block_size):
        super(PKCS7, self).__init__()
        if not (0 <= block_size < 256):
            raise ValueError("block_size must be in range(0, 256)")

        if block_size % 8 != 0:
            raise ValueError("block_size must be a multiple of 8")

        self.block_size = block_size

    def padder(self):
        return _PaddingContext(self.block_size)

    def unpadder(self):
        return _UnpaddingContext(self.block_size)

    def pad(self, data):
        padder = self.padder()
        return padder.update(data) + padder.finalize()

    def unpad(self, data):
        unpadder = self.unpadder()
        return unpadder.update(data) + unpadder.finalize()


class _PaddingContext(object):
    def __init__(self, block_size):
        super(_PaddingContext, self).__init__()
        self.block_size = block_size
        # TODO: O(n ** 2) complexity for repeated concatentation, we should use
        # zero-buffer
        self._buffer = b""

    def update(self, data):
        if self._buffer is None:
            raise ValueError("Context was already finalized")

        self._buffer += data
        result = b""

        while len(self._buffer) >= self.block_size // 8:
            result += self._buffer[:self.block_size // 8]
            self._buffer = self._buffer[self.block_size // 8:]
        return result

    def finalize(self):
        if self._buffer is None:
            raise ValueError("Context was already finalized")

        pad_size = self.block_size // 8 - len(self._buffer)
        result = self._buffer + six.int2byte(pad_size) * pad_size
        self._buffer = None
        return result


class _UnpaddingContext(object):
    def __init__(self, block_size):
        super(_UnpaddingContext, self).__init__()
        self.block_size = block_size
        # TODO: O(n ** 2) complexity for repeated concatentation, we should use
        # zero-buffer
        self._buffer = b""

    def update(self, data):
        if self._buffer is None:
            raise ValueError("Context was already finalized")

        self._buffer += data
        result = b""
        while len(self._buffer) >= 2 * (self.block_size // 8):
            result += self._buffer[:self.block_size // 8]
            self._buffer = self._buffer[self.block_size // 8:]
        return result

    def finalize(self):
        if self._buffer is None:
            raise ValueError("Context was already finalized")

        if not self._buffer:
            raise ValueError("Invalid padding bytes")

        pad_size = six.indexbytes(self._buffer, -1)

        if pad_size > self.block_size // 8:
            raise ValueError("Invalid padding bytes")

        for b in six.iterbytes(self._buffer[-pad_size:]):
            if b != pad_size:
                raise ValueError("Invalid padding bytes")

        res = self._buffer[:-pad_size]
        self._buffer = None
        return res
