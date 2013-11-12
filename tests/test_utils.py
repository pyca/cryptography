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

import py
import pytest

from .utils import (
    load_nist_vectors, load_vectors_from_file, load_cryptrec_vectors,
    load_openssl_vectors, load_hash_vectors,
)


def test_load_nist_vectors():
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

    assert load_nist_vectors(vector_data) == [
        {
            "key": b"00000000000000000000000000000000",
            "iv": b"00000000000000000000000000000000",
            "plaintext": b"f34481ec3cc627bacd5dc3fb08f273e6",
            "ciphertext": b"0336763e966d92595a567cc9ce537f5e",
        },
        {
            "key": b"00000000000000000000000000000000",
            "iv": b"00000000000000000000000000000000",
            "plaintext": b"9798c4640bad75c7c3227db910174e72",
            "ciphertext": b"a9a1631bf4996954ebc093957b234589",
        },
        {
            "key": b"00000000000000000000000000000000",
            "iv": b"00000000000000000000000000000000",
            "plaintext": b"f34481ec3cc627bacd5dc3fb08f273e6",
            "ciphertext": b"0336763e966d92595a567cc9ce537f5e",
        },
        {
            "key": b"00000000000000000000000000000000",
            "iv": b"00000000000000000000000000000000",
            "plaintext": b"9798c4640bad75c7c3227db910174e72",
            "ciphertext": b"a9a1631bf4996954ebc093957b234589",
        },
    ]


def test_load_cryptrec_vectors():
    vector_data = textwrap.dedent("""
    # Vectors taken from http://info.isl.ntt.co.jp/crypt/eng/camellia/
    # Download is t_camelia.txt

    # Camellia with 128-bit key

    K No.001 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

    P No.001 : 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    C No.001 : 07 92 3A 39 EB 0A 81 7D 1C 4D 87 BD B8 2D 1F 1C

    P No.002 : 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    C No.002 : 48 CD 64 19 80 96 72 D2 34 92 60 D8 9A 08 D3 D3

    K No.002 : 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

    P No.001 : 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    C No.001 : 07 92 3A 39 EB 0A 81 7D 1C 4D 87 BD B8 2D 1F 1C
    """).splitlines()

    assert load_cryptrec_vectors(vector_data) == [
        {
            "key": b"00000000000000000000000000000000",
            "plaintext": b"80000000000000000000000000000000",
            "ciphertext": b"07923A39EB0A817D1C4D87BDB82D1F1C",
        },
        {
            "key": b"00000000000000000000000000000000",
            "plaintext": b"40000000000000000000000000000000",
            "ciphertext": b"48CD6419809672D2349260D89A08D3D3",
        },
        {
            "key": b"10000000000000000000000000000000",
            "plaintext": b"80000000000000000000000000000000",
            "ciphertext": b"07923A39EB0A817D1C4D87BDB82D1F1C",
        },
    ]


def test_load_cryptrec_vectors_invalid():
    vector_data = textwrap.dedent("""
    # Vectors taken from http://info.isl.ntt.co.jp/crypt/eng/camellia/
    # Download is t_camelia.txt

    # Camellia with 128-bit key

    E No.001 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    """).splitlines()

    with pytest.raises(ValueError):
        load_cryptrec_vectors(vector_data)


def test_load_openssl_vectors():
    vector_data = textwrap.dedent(
        """
        # We don't support CFB{1,8}-CAMELLIAxxx.{En,De}crypt
        # For all CFB128 encrypts and decrypts, the transformed sequence is
        #   CAMELLIA-bits-CFB:key:IV/ciphertext':plaintext:ciphertext:encdec
        # CFB128-CAMELLIA128.Encrypt
        """
        "CAMELLIA-128-CFB:2B7E151628AED2A6ABF7158809CF4F3C:"
        "000102030405060708090A0B0C0D0E0F:6BC1BEE22E409F96E93D7E117393172A:"
        "14F7646187817EB586599146B82BD719:1\n"
        "CAMELLIA-128-CFB:2B7E151628AED2A6ABF7158809CF4F3C:"
        "14F7646187817EB586599146B82BD719:AE2D8A571E03AC9C9EB76FAC45AF8E51:"
        "A53D28BB82DF741103EA4F921A44880B:1\n\n"
        "# CFB128-CAMELLIA128.Decrypt\n"
        "CAMELLIA-128-CFB:2B7E151628AED2A6ABF7158809CF4F3C:"
        "000102030405060708090A0B0C0D0E0F:6BC1BEE22E409F96E93D7E117393172A:"
        "14F7646187817EB586599146B82BD719:0\n"
        "CAMELLIA-128-CFB:2B7E151628AED2A6ABF7158809CF4F3C:"
        "14F7646187817EB586599146B82BD719:AE2D8A571E03AC9C9EB76FAC45AF8E51:"
        "A53D28BB82DF741103EA4F921A44880B:0"
    ).splitlines()

    assert load_openssl_vectors(vector_data) == [
        {
            "key": b"2B7E151628AED2A6ABF7158809CF4F3C",
            "iv": b"000102030405060708090A0B0C0D0E0F",
            "plaintext": b"6BC1BEE22E409F96E93D7E117393172A",
            "ciphertext": b"14F7646187817EB586599146B82BD719",
        },
        {
            "key": b"2B7E151628AED2A6ABF7158809CF4F3C",
            "iv": b"14F7646187817EB586599146B82BD719",
            "plaintext": b"AE2D8A571E03AC9C9EB76FAC45AF8E51",
            "ciphertext": b"A53D28BB82DF741103EA4F921A44880B",
        },
        {
            "key": b"2B7E151628AED2A6ABF7158809CF4F3C",
            "iv": b"000102030405060708090A0B0C0D0E0F",
            "plaintext": b"6BC1BEE22E409F96E93D7E117393172A",
            "ciphertext": b"14F7646187817EB586599146B82BD719",
        },
        {
            "key": b"2B7E151628AED2A6ABF7158809CF4F3C",
            "iv": b"14F7646187817EB586599146B82BD719",
            "plaintext": b"AE2D8A571E03AC9C9EB76FAC45AF8E51",
            "ciphertext": b"A53D28BB82DF741103EA4F921A44880B",
        },
    ]


def test_load_hash_vectors():
    vector_data = textwrap.dedent("""

        # http://tools.ietf.org/html/rfc1321
        [irrelevant]

        Len = 0
        Msg = 00
        MD = d41d8cd98f00b204e9800998ecf8427e

        Len = 8
        Msg = 61
        MD = 0cc175b9c0f1b6a831c399e269772661

        Len = 24
        Msg = 616263
        MD = 900150983cd24fb0d6963f7d28e17f72

        Len = 112
        Msg = 6d65737361676520646967657374
        MD = f96b697d7cb7938d525a2f31aaf161d0
    """).splitlines()
    assert load_hash_vectors(vector_data) == [
        (b"", "d41d8cd98f00b204e9800998ecf8427e"),
        (b"61", "0cc175b9c0f1b6a831c399e269772661"),
        (b"616263", "900150983cd24fb0d6963f7d28e17f72"),
        (b"6d65737361676520646967657374", "f96b697d7cb7938d525a2f31aaf161d0"),
    ]


def test_load_hmac_vectors():
    vector_data = textwrap.dedent("""
Len = 224
# "Jefe"
Key = 4a656665
# "what do ya want for nothing?"
Msg = 7768617420646f2079612077616e7420666f72206e6f7468696e673f
MD = 750c783e6ab0b503eaa86e310a5db738
    """).splitlines()
    assert load_hash_vectors(vector_data) == [
        (b"7768617420646f2079612077616e7420666f72206e6f7468696e673f",
         "750c783e6ab0b503eaa86e310a5db738",
         b"4a656665"),
    ]


def test_load_hash_vectors_bad_data():
    vector_data = textwrap.dedent("""
        # http://tools.ietf.org/html/rfc1321

        Len = 0
        Msg = 00
        UNKNOWN=Hello World
    """).splitlines()
    with pytest.raises(ValueError):
        load_hash_vectors(vector_data)

def test_load_vectors_from_file(request):
    path = py.path.local(__file__).dirpath().join(
        "hazmat", "primitives", "vectors", "t.txt"
    )
    path.write(textwrap.dedent("""
    abc
    123
    """))
    request.addfinalizer(path.remove)
    vectors = load_vectors_from_file("t.txt", lambda f: f.readlines())
    assert vectors == ["\n", "abc\n", "123\n"]
