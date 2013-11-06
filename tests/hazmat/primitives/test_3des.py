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

"""
Test using the NIST Test Vectors
"""

from __future__ import absolute_import, division, print_function

import binascii
import os

from cryptography.hazmat.primitives.ciphers import algorithms, modes

from .utils import generate_encrypt_test
from ...utils import load_nist_vectors_from_file


class TestTripleDES_CBC(object):
    test_KAT = generate_encrypt_test(
        lambda path: load_nist_vectors_from_file(path, "ENCRYPT"),
        os.path.join("ciphers", "3DES", "CBC"),
        [
            "TCBCinvperm.rsp",
            "TCBCpermop.rsp",
            "TCBCsubtab.rsp",
            "TCBCvarkey.rsp",
            "TCBCvartext.rsp",
        ],
        lambda keys, iv: algorithms.TripleDES(binascii.unhexlify(keys)),
        lambda keys, iv: modes.CBC(binascii.unhexlify(iv)),
    )

    test_MMT = generate_encrypt_test(
        lambda path: load_nist_vectors_from_file(path, "ENCRYPT"),
        os.path.join("ciphers", "3DES", "CBC"),
        [
            "TCBCMMT1.rsp",
            "TCBCMMT2.rsp",
            "TCBCMMT3.rsp",
        ],
        lambda key1, key2, key3, iv: (
            algorithms.TripleDES(binascii.unhexlify(key1 + key2 + key3))
        ),
        lambda key1, key2, key3, iv: modes.CBC(binascii.unhexlify(iv)),
    )


class TestTripleDES_OFB(object):
    test_KAT = generate_encrypt_test(
        lambda path: load_nist_vectors_from_file(path, "ENCRYPT"),
        os.path.join("ciphers", "3DES", "OFB"),
        [
            "TOFBpermop.rsp",
            "TOFBsubtab.rsp",
            "TOFBvarkey.rsp",
            "TOFBvartext.rsp",
            "TOFBinvperm.rsp",
        ],
        lambda keys, iv: algorithms.TripleDES(binascii.unhexlify(keys)),
        lambda keys, iv: modes.OFB(binascii.unhexlify(iv)),
    )

    test_MMT = generate_encrypt_test(
        lambda path: load_nist_vectors_from_file(path, "ENCRYPT"),
        os.path.join("ciphers", "3DES", "OFB"),
        [
            "TOFBMMT1.rsp",
            "TOFBMMT2.rsp",
            "TOFBMMT3.rsp",
        ],
        lambda key1, key2, key3, iv: (
            algorithms.TripleDES(binascii.unhexlify(key1 + key2 + key3))
        ),
        lambda key1, key2, key3, iv: modes.OFB(binascii.unhexlify(iv)),
    )


class TestTripleDES_CFB(object):
    test_KAT = generate_encrypt_test(
        lambda path: load_nist_vectors_from_file(path, "ENCRYPT"),
        os.path.join("ciphers", "3DES", "CFB"),
        [
            "TCFB64invperm.rsp",
            "TCFB64permop.rsp",
            "TCFB64subtab.rsp",
            "TCFB64varkey.rsp",
            "TCFB64vartext.rsp",
        ],
        lambda keys, iv: algorithms.TripleDES(binascii.unhexlify(keys)),
        lambda keys, iv: modes.CFB(binascii.unhexlify(iv)),
    )

    test_MMT = generate_encrypt_test(
        lambda path: load_nist_vectors_from_file(path, "ENCRYPT"),
        os.path.join("ciphers", "3DES", "CFB"),
        [
            "TCFB64MMT1.rsp",
            "TCFB64MMT2.rsp",
            "TCFB64MMT3.rsp",
        ],
        lambda key1, key2, key3, iv: (
            algorithms.TripleDES(binascii.unhexlify(key1 + key2 + key3))
        ),
        lambda key1, key2, key3, iv: modes.CFB(binascii.unhexlify(iv)),
    )
