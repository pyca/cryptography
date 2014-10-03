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


def _truncate_digest(digest, order_bits):
    digest_len = len(digest)

    if 8 * digest_len > order_bits:
        digest_len = (order_bits + 7) // 8
        digest = digest[:digest_len]

    if 8 * digest_len > order_bits:
        rshift = 8 - (order_bits & 0x7)
        assert rshift > 0 and rshift < 8

        mask = 0xFF >> rshift << rshift

        # Set the bottom rshift bits to 0
        digest = digest[:-1] + six.int2byte(six.indexbytes(digest, -1) & mask)

    return digest
