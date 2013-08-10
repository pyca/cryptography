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

import textwrap

from .utils import load_nist_vectors, load_nist_vectors_from_file


def test_load_nist_vectors_encrypt():
    vector_data = textwrap.dedent("""
    # CAVS 11.1
    # Config info for aes_values
    # AESVS GFSbox test data for CBC
    # State : Encrypt and Decrypt
    # Key Length : 128
    # Generated on Fri Apr 22 15:11:33 2011

    [ENCRYPT]

    COUNT = 0
    KEY = 00000000000000000000000000000000
    IV = 00000000000000000000000000000000
    PLAINTEXT = f34481ec3cc627bacd5dc3fb08f273e6
    CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e

    COUNT = 1
    KEY = 00000000000000000000000000000000
    IV = 00000000000000000000000000000000
    PLAINTEXT = 9798c4640bad75c7c3227db910174e72
    CIPHERTEXT = a9a1631bf4996954ebc093957b234589

    [DECRYPT]

    COUNT = 0
    KEY = 00000000000000000000000000000000
    IV = 00000000000000000000000000000000
    CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e
    PLAINTEXT = f34481ec3cc627bacd5dc3fb08f273e6

    COUNT = 1
    KEY = 00000000000000000000000000000000
    IV = 00000000000000000000000000000000
    CIPHERTEXT = a9a1631bf4996954ebc093957b234589
    PLAINTEXT = 9798c4640bad75c7c3227db910174e72
    """).splitlines()

    assert load_nist_vectors(vector_data, "ENCRYPT",
        ["key", "iv", "plaintext", "ciphertext"],
    ) == [
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"f34481ec3cc627bacd5dc3fb08f273e6",
            b"0336763e966d92595a567cc9ce537f5e",
        ),
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"9798c4640bad75c7c3227db910174e72",
            b"a9a1631bf4996954ebc093957b234589",
        ),
    ]


def test_load_nist_vectors_decrypt():
    vector_data = textwrap.dedent("""
    # CAVS 11.1
    # Config info for aes_values
    # AESVS GFSbox test data for CBC
    # State : Encrypt and Decrypt
    # Key Length : 128
    # Generated on Fri Apr 22 15:11:33 2011

    [ENCRYPT]

    COUNT = 0
    KEY = 00000000000000000000000000000000
    IV = 00000000000000000000000000000000
    PLAINTEXT = f34481ec3cc627bacd5dc3fb08f273e6
    CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e

    COUNT = 1
    KEY = 00000000000000000000000000000000
    IV = 00000000000000000000000000000000
    PLAINTEXT = 9798c4640bad75c7c3227db910174e72
    CIPHERTEXT = a9a1631bf4996954ebc093957b234589

    [DECRYPT]

    COUNT = 0
    KEY = 00000000000000000000000000000000
    IV = 00000000000000000000000000000000
    CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e
    PLAINTEXT = f34481ec3cc627bacd5dc3fb08f273e6

    COUNT = 1
    KEY = 00000000000000000000000000000000
    IV = 00000000000000000000000000000000
    CIPHERTEXT = a9a1631bf4996954ebc093957b234589
    PLAINTEXT = 9798c4640bad75c7c3227db910174e72
    """).splitlines()

    assert load_nist_vectors(vector_data, "DECRYPT",
        ["key", "iv", "ciphertext", "plaintext"],
    ) == [
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"0336763e966d92595a567cc9ce537f5e",
            b"f34481ec3cc627bacd5dc3fb08f273e6",
        ),
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"a9a1631bf4996954ebc093957b234589",
            b"9798c4640bad75c7c3227db910174e72",
        ),
    ]


def test_load_nist_vectors_from_file_encrypt():
    assert load_nist_vectors_from_file(
        "AES/KAT/CBCGFSbox128.rsp",
        "ENCRYPT",
        ["key", "iv", "plaintext", "ciphertext"],
    ) == [
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"f34481ec3cc627bacd5dc3fb08f273e6",
            b"0336763e966d92595a567cc9ce537f5e",
        ),
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"9798c4640bad75c7c3227db910174e72",
            b"a9a1631bf4996954ebc093957b234589",
        ),
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"96ab5c2ff612d9dfaae8c31f30c42168",
            b"ff4f8391a6a40ca5b25d23bedd44a597",
        ),
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"6a118a874519e64e9963798a503f1d35",
            b"dc43be40be0e53712f7e2bf5ca707209",
        ),
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"cb9fceec81286ca3e989bd979b0cb284",
            b"92beedab1895a94faa69b632e5cc47ce",
        ),
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"b26aeb1874e47ca8358ff22378f09144",
            b"459264f4798f6a78bacb89c15ed3d601",
        ),
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"58c8e00b2631686d54eab84b91f0aca1",
            b"08a4e2efec8a8e3312ca7460b9040bbf",
        ),
    ]


def test_load_nist_vectors_from_file_decypt():
    assert load_nist_vectors_from_file(
        "AES/KAT/CBCGFSbox128.rsp",
        "DECRYPT",
        ["key", "iv", "ciphertext", "plaintext"],
    ) == [
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"0336763e966d92595a567cc9ce537f5e",
            b"f34481ec3cc627bacd5dc3fb08f273e6",
        ),
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"a9a1631bf4996954ebc093957b234589",
            b"9798c4640bad75c7c3227db910174e72",
        ),
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"ff4f8391a6a40ca5b25d23bedd44a597",
            b"96ab5c2ff612d9dfaae8c31f30c42168",
        ),
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"dc43be40be0e53712f7e2bf5ca707209",
            b"6a118a874519e64e9963798a503f1d35",
        ),
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"92beedab1895a94faa69b632e5cc47ce",
            b"cb9fceec81286ca3e989bd979b0cb284",
        ),
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"459264f4798f6a78bacb89c15ed3d601",
            b"b26aeb1874e47ca8358ff22378f09144"
        ),
        (
            b"00000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"08a4e2efec8a8e3312ca7460b9040bbf",
            b"58c8e00b2631686d54eab84b91f0aca1"
        ),
    ]
