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
from __future__ import absolute_import, division, print_function

import six

from cryptography.primitives import interfaces


def bytes_normalize(inp):
    # We have a single integer, convert it to a bytes
    if isinstance(inp, six.integer_types):
        return six.int2byte(inp)
    elif isinstance(inp, six.binary_type):
        return inp


class PKCS7(object):

    def __init__(self, block_size):
        self.block_size = block_size
        self.byte_size = block_size // 8

        if self.byte_size >= 256:
            raise ValueError("Invalid block size, too large")

        if self.block_size % 8:
            raise ValueError("Invalid block size, must be multiple of 8")

    def iter_pad(self, data):
        # Iterate over the data yielding it in chunks the size of our blocks
        # until theres not enough data to fill another full block
        buf = b""
        for chunk in data:
            # Add our chunk into our buffer
            buf += bytes_normalize(chunk)

            # If we have enough data stored in the buffer then remove it from
            # the buffer and yield it
            while len(buf) >= self.byte_size:
                next_chunk, buf = buf[:self.byte_size], buf[self.byte_size:]
                yield next_chunk

        # Determine how big our padding needs to be
        pad_size = self.byte_size - len(buf)

        yield buf + (six.int2byte(pad_size) * pad_size)

    def pad(self, data):
        return b"".join(self.iter_pad(data))

    def iter_unpad(self, data):
        # Iterate over the data yielding chunks the size of our block size
        # keeping one block staged at all times so we can unpad the final block
        last = None
        buf = b""
        for chunk in data:
            # Add our chunk into our buffer
            buf += bytes_normalize(chunk)

            # If we have enough data stored in the buffer, remove it from the
            # buffer and do the staging + yield dance
            while len(buf) >= self.byte_size:
                next_chunk, buf = buf[:self.byte_size], buf[self.byte_size:]
                last, next_chunk = next_chunk, last
                if next_chunk:
                    yield next_chunk

        if not last:
            raise ValueError("Invalid padding bytes")

        # Determine how big our padding is
        pad_size = six.indexbytes(last, -1)

        if pad_size > self.byte_size:
            raise ValueError("Invalid padding bytes")

        # Ensure the padding characters are correct
        if set(six.iterbytes(last[-pad_size:])) != set([pad_size]):
            raise ValueError("Invalid padding bytes")

        yield last[:-pad_size]

    def unpad(self, data):
        return b"".join(self.iter_unpad(data))


interfaces.Padding.register(PKCS7)
