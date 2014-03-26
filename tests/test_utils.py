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

import os
import textwrap

import pretend

import pytest

import cryptography
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons

import cryptography_vectors

from .utils import (
    check_backend_support, check_for_iface, load_cryptrec_vectors,
    load_fips_dsa_key_pair_vectors, load_hash_vectors, load_nist_vectors,
    load_pkcs1_vectors, load_rsa_nist_vectors, load_vectors_from_file,
    raises_unsupported_algorithm, select_backends
)


class FakeInterface(object):
    pass


def test_select_one_backend():
    b1 = pretend.stub(name="b1")
    b2 = pretend.stub(name="b2")
    b3 = pretend.stub(name="b3")
    backends = [b1, b2, b3]
    name = "b2"
    selected_backends = select_backends(name, backends)
    assert len(selected_backends) == 1
    assert selected_backends[0] == b2


def test_select_no_backend():
    b1 = pretend.stub(name="b1")
    b2 = pretend.stub(name="b2")
    b3 = pretend.stub(name="b3")
    backends = [b1, b2, b3]
    name = "back!"
    with pytest.raises(ValueError):
        select_backends(name, backends)


def test_select_backends_none():
    b1 = pretend.stub(name="b1")
    b2 = pretend.stub(name="b2")
    b3 = pretend.stub(name="b3")
    backends = [b1, b2, b3]
    name = None
    selected_backends = select_backends(name, backends)
    assert len(selected_backends) == 3


def test_select_two_backends():
    b1 = pretend.stub(name="b1")
    b2 = pretend.stub(name="b2")
    b3 = pretend.stub(name="b3")
    backends = [b1, b2, b3]
    name = "b2 ,b1 "
    selected_backends = select_backends(name, backends)
    assert len(selected_backends) == 2
    assert selected_backends == [b1, b2]


def test_check_for_iface():
    item = pretend.stub(keywords=["fake_name"], funcargs={"backend": True})
    with pytest.raises(pytest.skip.Exception) as exc_info:
        check_for_iface("fake_name", FakeInterface, item)
    assert exc_info.value.args[0] == "True backend does not support fake_name"

    item = pretend.stub(
        keywords=["fake_name"],
        funcargs={"backend": FakeInterface()}
    )
    check_for_iface("fake_name", FakeInterface, item)


def test_check_backend_support_skip():
    supported = pretend.stub(
        kwargs={"only_if": lambda backend: False, "skip_message": "Nope"}
    )
    item = pretend.stub(keywords={"supported": supported},
                        funcargs={"backend": True})
    with pytest.raises(pytest.skip.Exception) as exc_info:
        check_backend_support(item)
    assert exc_info.value.args[0] == "Nope (True)"


def test_check_backend_support_no_skip():
    supported = pretend.stub(
        kwargs={"only_if": lambda backend: True, "skip_message": "Nope"}
    )
    item = pretend.stub(keywords={"supported": supported},
                        funcargs={"backend": True})
    assert check_backend_support(item) is None


def test_check_backend_support_no_backend():
    supported = pretend.stub(
        kwargs={"only_if": "notalambda", "skip_message": "Nope"}
    )
    item = pretend.stub(keywords={"supported": supported},
                        funcargs={})
    with pytest.raises(ValueError):
        check_backend_support(item)


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


def test_load_nist_vectors_with_null_chars():
    vector_data = textwrap.dedent("""
    COUNT = 0
    KEY = thing\\0withnulls

    COUNT = 1
    KEY = 00000000000000000000000000000000
    """).splitlines()

    assert load_nist_vectors(vector_data) == [
        {
            "key": b"thing\x00withnulls",
        },
        {
            "key": b"00000000000000000000000000000000",
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


def test_load_vectors_from_file():
    vectors = load_vectors_from_file(
        os.path.join("ciphers", "Blowfish", "bf-cfb.txt"),
        load_nist_vectors,
    )
    assert vectors == [
        {
            "key": b"0123456789ABCDEFF0E1D2C3B4A59687",
            "iv": b"FEDCBA9876543210",
            "plaintext": (
                b"37363534333231204E6F77206973207468652074696D6520666F722000"
            ),
            "ciphertext": (
                b"E73214A2822139CAF26ECF6D2EB9E76E3DA3DE04D1517200519D57A6C3"
            ),
        }
    ]


def test_load_nist_gcm_vectors():
    vector_data = textwrap.dedent("""
        [Keylen = 128]
        [IVlen = 96]
        [PTlen = 0]
        [AADlen = 0]
        [Taglen = 128]

        Count = 0
        Key = 11754cd72aec309bf52f7687212e8957
        IV = 3c819d9a9bed087615030b65
        PT =
        AAD =
        CT =
        Tag = 250327c674aaf477aef2675748cf6971

        Count = 1
        Key = 272f16edb81a7abbea887357a58c1917
        IV = 794ec588176c703d3d2a7a07
        PT =
        AAD =
        CT =
        Tag = b6e6f197168f5049aeda32dafbdaeb

        Count = 2
        Key = a49a5e26a2f8cb63d05546c2a62f5343
        IV = 907763b19b9b4ab6bd4f0281
        CT =
        AAD =
        Tag = a2be08210d8c470a8df6e8fbd79ec5cf
        FAIL

        Count = 3
        Key = 5c1155084cc0ede76b3bc22e9f7574ef
        IV = 9549e4ba69a61cad7856efc1
        PT = d1448fa852b84408e2dad8381f363de7
        AAD = e98e9d9c618e46fef32660976f854ee3
        CT = f78b60ca125218493bea1c50a2e12ef4
        Tag = d72da7f5c6cf0bca7242c71835809449

        [Keylen = 128]
        [IVlen = 96]
        [PTlen = 0]
        [AADlen = 0]
        [Taglen = 120]

        Count = 0
        Key = eac258e99c55e6ae8ef1da26640613d7
        IV = 4e8df20faaf2c8eebe922902
        CT =
        AAD =
        Tag = e39aeaebe86aa309a4d062d6274339
        PT =

        Count = 1
        Key = 3726cf02fcc6b8639a5497652c94350d
        IV = 55fef82cde693ce76efcc193
        CT =
        AAD =
        Tag = 3d68111a81ed22d2ef5bccac4fc27f
        FAIL

        Count = 2
        Key = f202299d5fd74f03b12d2119a6c4c038
        IV = eec51e7958c3f20a1bb71815
        CT =
        AAD =
        Tag = a81886b3fb26e51fca87b267e1e157
        FAIL

        Count = 3
        Key = fd52925f39546b4c55ffb6b20c59898c
        IV = f5cf3227444afd905a5f6dba
        CT =
        AAD =
        Tag = 1665b0f1a0b456e1664cfd3de08ccd
        PT =

        [Keylen = 128]
        [IVlen = 8]
        [PTlen = 104]
        [AADlen = 0]
        [Taglen = 128]

        Count = 0
        Key = 58fab7632bcf10d2bcee58520bf37414
        IV = 3c
        CT = 15c4db4cbb451211179d57017f
        AAD =
        Tag = eae841d4355feeb3f786bc86625f1e5b
        FAIL
    """).splitlines()
    assert load_nist_vectors(vector_data) == [
        {'aad': b'',
         'pt': b'',
         'iv': b'3c819d9a9bed087615030b65',
         'tag': b'250327c674aaf477aef2675748cf6971',
         'key': b'11754cd72aec309bf52f7687212e8957',
         'ct': b''},
        {'aad': b'',
         'pt': b'',
         'iv': b'794ec588176c703d3d2a7a07',
         'tag': b'b6e6f197168f5049aeda32dafbdaeb',
         'key': b'272f16edb81a7abbea887357a58c1917',
         'ct': b''},
        {'aad': b'',
         'iv': b'907763b19b9b4ab6bd4f0281',
         'tag': b'a2be08210d8c470a8df6e8fbd79ec5cf',
         'key': b'a49a5e26a2f8cb63d05546c2a62f5343',
         'ct': b'',
         'fail': True},
        {'aad': b'e98e9d9c618e46fef32660976f854ee3',
         'pt': b'd1448fa852b84408e2dad8381f363de7',
         'iv': b'9549e4ba69a61cad7856efc1',
         'tag': b'd72da7f5c6cf0bca7242c71835809449',
         'key': b'5c1155084cc0ede76b3bc22e9f7574ef',
         'ct': b'f78b60ca125218493bea1c50a2e12ef4'},
        {'aad': b'',
         'pt': b'',
         'iv': b'4e8df20faaf2c8eebe922902',
         'tag': b'e39aeaebe86aa309a4d062d6274339',
         'key': b'eac258e99c55e6ae8ef1da26640613d7',
         'ct': b''},
        {'aad': b'',
         'iv': b'55fef82cde693ce76efcc193',
         'tag': b'3d68111a81ed22d2ef5bccac4fc27f',
         'key': b'3726cf02fcc6b8639a5497652c94350d',
         'ct': b'',
         'fail': True},
        {'aad': b'',
         'iv': b'eec51e7958c3f20a1bb71815',
         'tag': b'a81886b3fb26e51fca87b267e1e157',
         'key': b'f202299d5fd74f03b12d2119a6c4c038',
         'ct': b'',
         'fail': True},
        {'aad': b'',
         'pt': b'',
         'iv': b'f5cf3227444afd905a5f6dba',
         'tag': b'1665b0f1a0b456e1664cfd3de08ccd',
         'key': b'fd52925f39546b4c55ffb6b20c59898c',
         'ct': b''},
        {'aad': b'',
         'iv': b'3c',
         'tag': b'eae841d4355feeb3f786bc86625f1e5b',
         'key': b'58fab7632bcf10d2bcee58520bf37414',
         'ct': b'15c4db4cbb451211179d57017f',
         'fail': True},
    ]


def test_load_pkcs1_vectors():
    vector_data = textwrap.dedent("""
    Test vectors for RSA-PSS
    ========================

    This file contains an extract of the original pss-vect.txt

    Key lengths:

    Key  8: 1031 bits
    Key  9: 1536 bits
    ===========================================================================

    <snip>

    # Example 8: A 1031-bit RSA key pair
    # -----------------------------------


    # Public key
    # ----------

    # Modulus:
    49 53 70 a1 fb 18 54 3c 16 d3 63 1e 31 63 25 5d
    f6 2b e6 ee e8 90 d5 f2 55 09 e4 f7 78 a8 ea 6f
    bb bc df 85 df f6 4e 0d 97 20 03 ab 36 81 fb ba
    6d d4 1f d5 41 82 9b 2e 58 2d e9 f2 a4 a4 e0 a2
    d0 90 0b ef 47 53 db 3c ee 0e e0 6c 7d fa e8 b1
    d5 3b 59 53 21 8f 9c ce ea 69 5b 08 66 8e de aa
    dc ed 94 63 b1 d7 90 d5 eb f2 7e 91 15 b4 6c ad
    4d 9a 2b 8e fa b0 56 1b 08 10 34 47 39 ad a0 73
    3f

    # Exponent:
    01 00 01

    # Private key
    # -----------

    # Modulus:
    49 53 70 a1 fb 18 54 3c 16 d3 63 1e 31 63 25 5d
    f6 2b e6 ee e8 90 d5 f2 55 09 e4 f7 78 a8 ea 6f
    bb bc df 85 df f6 4e 0d 97 20 03 ab 36 81 fb ba
    6d d4 1f d5 41 82 9b 2e 58 2d e9 f2 a4 a4 e0 a2
    d0 90 0b ef 47 53 db 3c ee 0e e0 6c 7d fa e8 b1
    d5 3b 59 53 21 8f 9c ce ea 69 5b 08 66 8e de aa
    dc ed 94 63 b1 d7 90 d5 eb f2 7e 91 15 b4 6c ad
    4d 9a 2b 8e fa b0 56 1b 08 10 34 47 39 ad a0 73
    3f

    # Public exponent:
    01 00 01

    # Exponent:
    6c 66 ff e9 89 80 c3 8f cd ea b5 15 98 98 83 61
    65 f4 b4 b8 17 c4 f6 a8 d4 86 ee 4e a9 13 0f e9
    b9 09 2b d1 36 d1 84 f9 5f 50 4a 60 7e ac 56 58
    46 d2 fd d6 59 7a 89 67 c7 39 6e f9 5a 6e ee bb
    45 78 a6 43 96 6d ca 4d 8e e3 de 84 2d e6 32 79
    c6 18 15 9c 1a b5 4a 89 43 7b 6a 61 20 e4 93 0a
    fb 52 a4 ba 6c ed 8a 49 47 ac 64 b3 0a 34 97 cb
    e7 01 c2 d6 26 6d 51 72 19 ad 0e c6 d3 47 db e9

    # Prime 1:
    08 da d7 f1 13 63 fa a6 23 d5 d6 d5 e8 a3 19 32
    8d 82 19 0d 71 27 d2 84 6c 43 9b 0a b7 26 19 b0
    a4 3a 95 32 0e 4e c3 4f c3 a9 ce a8 76 42 23 05
    bd 76 c5 ba 7b e9 e2 f4 10 c8 06 06 45 a1 d2 9e
    db

    # Prime 2:
    08 47 e7 32 37 6f c7 90 0f 89 8e a8 2e b2 b0 fc
    41 85 65 fd ae 62 f7 d9 ec 4c e2 21 7b 97 99 0d
    d2 72 db 15 7f 99 f6 3c 0d cb b9 fb ac db d4 c4
    da db 6d f6 77 56 35 8c a4 17 48 25 b4 8f 49 70
    6d

    # Prime exponent 1:
    05 c2 a8 3c 12 4b 36 21 a2 aa 57 ea 2c 3e fe 03
    5e ff 45 60 f3 3d de bb 7a da b8 1f ce 69 a0 c8
    c2 ed c1 65 20 dd a8 3d 59 a2 3b e8 67 96 3a c6
    5f 2c c7 10 bb cf b9 6e e1 03 de b7 71 d1 05 fd
    85

    # Prime exponent 2:
    04 ca e8 aa 0d 9f aa 16 5c 87 b6 82 ec 14 0b 8e
    d3 b5 0b 24 59 4b 7a 3b 2c 22 0b 36 69 bb 81 9f
    98 4f 55 31 0a 1a e7 82 36 51 d4 a0 2e 99 44 79
    72 59 51 39 36 34 34 e5 e3 0a 7e 7d 24 15 51 e1
    b9

    # Coefficient:
    07 d3 e4 7b f6 86 60 0b 11 ac 28 3c e8 8d bb 3f
    60 51 e8 ef d0 46 80 e4 4c 17 1e f5 31 b8 0b 2b
    7c 39 fc 76 63 20 e2 cf 15 d8 d9 98 20 e9 6f f3
    0d c6 96 91 83 9c 4b 40 d7 b0 6e 45 30 7d c9 1f
    3f

    # RSA-PSS signing of 6 random messages with random salts
    # -------------------------------------------------------
    # PSS Example 8.1

    # -----------------

    # Message to be signed:
    81 33 2f 4b e6 29 48 41 5e a1 d8 99 79 2e ea cf
    6c 6e 1d b1 da 8b e1 3b 5c ea 41 db 2f ed 46 70
    92 e1 ff 39 89 14 c7 14 25 97 75 f5 95 f8 54 7f
    73 56 92 a5 75 e6 92 3a f7 8f 22 c6 99 7d db 90
    fb 6f 72 d7 bb 0d d5 74 4a 31 de cd 3d c3 68 58
    49 83 6e d3 4a ec 59 63 04 ad 11 84 3c 4f 88 48
    9f 20 97 35 f5 fb 7f da f7 ce c8 ad dc 58 18 16
    8f 88 0a cb f4 90 d5 10 05 b7 a8 e8 4e 43 e5 42
    87 97 75 71 dd 99 ee a4 b1 61 eb 2d f1 f5 10 8f
    12 a4 14 2a 83 32 2e db 05 a7 54 87 a3 43 5c 9a
    78 ce 53 ed 93 bc 55 08 57 d7 a9 fb

    # Salt:
    1d 65 49 1d 79 c8 64 b3 73 00 9b e6 f6 f2 46 7b
    ac 4c 78 fa

    # Signature:
    02 62 ac 25 4b fa 77 f3 c1 ac a2 2c 51 79 f8 f0
    40 42 2b 3c 5b af d4 0a 8f 21 cf 0f a5 a6 67 cc
    d5 99 3d 42 db af b4 09 c5 20 e2 5f ce 2b 1e e1
    e7 16 57 7f 1e fa 17 f3 da 28 05 2f 40 f0 41 9b
    23 10 6d 78 45 aa f0 11 25 b6 98 e7 a4 df e9 2d
    39 67 bb 00 c4 d0 d3 5b a3 55 2a b9 a8 b3 ee f0
    7c 7f ec db c5 42 4a c4 db 1e 20 cb 37 d0 b2 74
    47 69 94 0e a9 07 e1 7f bb ca 67 3b 20 52 23 80
    c5

    # PSS Example 8.2

    # -----------------

    # Message to be signed:
    e2 f9 6e af 0e 05 e7 ba 32 6e cc a0 ba 7f d2 f7
    c0 23 56 f3 ce de 9d 0f aa bf 4f cc 8e 60 a9 73
    e5 59 5f d9 ea 08

    # Salt:
    43 5c 09 8a a9 90 9e b2 37 7f 12 48 b0 91 b6 89
    87 ff 18 38

    # Signature:
    27 07 b9 ad 51 15 c5 8c 94 e9 32 e8 ec 0a 28 0f
    56 33 9e 44 a1 b5 8d 4d dc ff 2f 31 2e 5f 34 dc
    fe 39 e8 9c 6a 94 dc ee 86 db bd ae 5b 79 ba 4e
    08 19 a9 e7 bf d9 d9 82 e7 ee 6c 86 ee 68 39 6e
    8b 3a 14 c9 c8 f3 4b 17 8e b7 41 f9 d3 f1 21 10
    9b f5 c8 17 2f ad a2 e7 68 f9 ea 14 33 03 2c 00
    4a 8a a0 7e b9 90 00 0a 48 dc 94 c8 ba c8 aa be
    2b 09 b1 aa 46 c0 a2 aa 0e 12 f6 3f bb a7 75 ba
    7e

    # <snip>

    # =============================================

    # Example 9: A 1536-bit RSA key pair
    # -----------------------------------


    # Public key
    # ----------

    # Modulus:
    e6 bd 69 2a c9 66 45 79 04 03 fd d0 f5 be b8 b9
    bf 92 ed 10 00 7f c3 65 04 64 19 dd 06 c0 5c 5b
    5b 2f 48 ec f9 89 e4 ce 26 91 09 97 9c bb 40 b4
    a0 ad 24 d2 24 83 d1 ee 31 5a d4 cc b1 53 42 68
    35 26 91 c5 24 f6 dd 8e 6c 29 d2 24 cf 24 69 73
    ae c8 6c 5b f6 b1 40 1a 85 0d 1b 9a d1 bb 8c bc
    ec 47 b0 6f 0f 8c 7f 45 d3 fc 8f 31 92 99 c5 43
    3d db c2 b3 05 3b 47 de d2 ec d4 a4 ca ef d6 14
    83 3d c8 bb 62 2f 31 7e d0 76 b8 05 7f e8 de 3f
    84 48 0a d5 e8 3e 4a 61 90 4a 4f 24 8f b3 97 02
    73 57 e1 d3 0e 46 31 39 81 5c 6f d4 fd 5a c5 b8
    17 2a 45 23 0e cb 63 18 a0 4f 14 55 d8 4e 5a 8b

    # Exponent:
    01 00 01

    # Private key
    # -----------

    # Modulus:
    e6 bd 69 2a c9 66 45 79 04 03 fd d0 f5 be b8 b9
    bf 92 ed 10 00 7f c3 65 04 64 19 dd 06 c0 5c 5b
    5b 2f 48 ec f9 89 e4 ce 26 91 09 97 9c bb 40 b4
    a0 ad 24 d2 24 83 d1 ee 31 5a d4 cc b1 53 42 68
    35 26 91 c5 24 f6 dd 8e 6c 29 d2 24 cf 24 69 73
    ae c8 6c 5b f6 b1 40 1a 85 0d 1b 9a d1 bb 8c bc
    ec 47 b0 6f 0f 8c 7f 45 d3 fc 8f 31 92 99 c5 43
    3d db c2 b3 05 3b 47 de d2 ec d4 a4 ca ef d6 14
    83 3d c8 bb 62 2f 31 7e d0 76 b8 05 7f e8 de 3f
    84 48 0a d5 e8 3e 4a 61 90 4a 4f 24 8f b3 97 02
    73 57 e1 d3 0e 46 31 39 81 5c 6f d4 fd 5a c5 b8
    17 2a 45 23 0e cb 63 18 a0 4f 14 55 d8 4e 5a 8b

    # Public exponent:
    01 00 01

    # Exponent:
    6a 7f d8 4f b8 5f ad 07 3b 34 40 6d b7 4f 8d 61
    a6 ab c1 21 96 a9 61 dd 79 56 5e 9d a6 e5 18 7b
    ce 2d 98 02 50 f7 35 95 75 35 92 70 d9 15 90 bb
    0e 42 7c 71 46 0b 55 d5 14 10 b1 91 bc f3 09 fe
    a1 31 a9 2c 8e 70 27 38 fa 71 9f 1e 00 41 f5 2e
    40 e9 1f 22 9f 4d 96 a1 e6 f1 72 e1 55 96 b4 51
    0a 6d ae c2 61 05 f2 be bc 53 31 6b 87 bd f2 13
    11 66 60 70 e8 df ee 69 d5 2c 71 a9 76 ca ae 79
    c7 2b 68 d2 85 80 dc 68 6d 9f 51 29 d2 25 f8 2b
    3d 61 55 13 a8 82 b3 db 91 41 6b 48 ce 08 88 82
    13 e3 7e eb 9a f8 00 d8 1c ab 32 8c e4 20 68 99
    03 c0 0c 7b 5f d3 1b 75 50 3a 6d 41 96 84 d6 29

    # Prime 1:
    f8 eb 97 e9 8d f1 26 64 ee fd b7 61 59 6a 69 dd
    cd 0e 76 da ec e6 ed 4b f5 a1 b5 0a c0 86 f7 92
    8a 4d 2f 87 26 a7 7e 51 5b 74 da 41 98 8f 22 0b
    1c c8 7a a1 fc 81 0c e9 9a 82 f2 d1 ce 82 1e dc
    ed 79 4c 69 41 f4 2c 7a 1a 0b 8c 4d 28 c7 5e c6
    0b 65 22 79 f6 15 4a 76 2a ed 16 5d 47 de e3 67

    # Prime 2:
    ed 4d 71 d0 a6 e2 4b 93 c2 e5 f6 b4 bb e0 5f 5f
    b0 af a0 42 d2 04 fe 33 78 d3 65 c2 f2 88 b6 a8
    da d7 ef e4 5d 15 3e ef 40 ca cc 7b 81 ff 93 40
    02 d1 08 99 4b 94 a5 e4 72 8c d9 c9 63 37 5a e4
    99 65 bd a5 5c bf 0e fe d8 d6 55 3b 40 27 f2 d8
    62 08 a6 e6 b4 89 c1 76 12 80 92 d6 29 e4 9d 3d

    # Prime exponent 1:
    2b b6 8b dd fb 0c 4f 56 c8 55 8b ff af 89 2d 80
    43 03 78 41 e7 fa 81 cf a6 1a 38 c5 e3 9b 90 1c
    8e e7 11 22 a5 da 22 27 bd 6c de eb 48 14 52 c1
    2a d3 d6 1d 5e 4f 77 6a 0a b5 56 59 1b ef e3 e5
    9e 5a 7f dd b8 34 5e 1f 2f 35 b9 f4 ce e5 7c 32
    41 4c 08 6a ec 99 3e 93 53 e4 80 d9 ee c6 28 9f

    # Prime exponent 2:
    4f f8 97 70 9f ad 07 97 46 49 45 78 e7 0f d8 54
    61 30 ee ab 56 27 c4 9b 08 0f 05 ee 4a d9 f3 e4
    b7 cb a9 d6 a5 df f1 13 a4 1c 34 09 33 68 33 f1
    90 81 6d 8a 6b c4 2e 9b ec 56 b7 56 7d 0f 3c 9c
    69 6d b6 19 b2 45 d9 01 dd 85 6d b7 c8 09 2e 77
    e9 a1 cc cd 56 ee 4d ba 42 c5 fd b6 1a ec 26 69

    # Coefficient:
    77 b9 d1 13 7b 50 40 4a 98 27 29 31 6e fa fc 7d
    fe 66 d3 4e 5a 18 26 00 d5 f3 0a 0a 85 12 05 1c
    56 0d 08 1d 4d 0a 18 35 ec 3d 25 a6 0f 4e 4d 6a
    a9 48 b2 bf 3d bb 5b 12 4c bb c3 48 92 55 a3 a9
    48 37 2f 69 78 49 67 45 f9 43 e1 db 4f 18 38 2c
    ea a5 05 df c6 57 57 bb 3f 85 7a 58 dc e5 21 56

    # PKCS#1 v1.5 Signature Example 2.17

    # -----------------

    # Message to be signed:
    06 ad d7 5a b6 89 de 06 77 44 e6 9a 2e bd 4b 90
    fa 93 83 00 3c d0 5f f5 36 cb f2 94 cd 21 5f 09
    23 b7 fc 90 04 f0 aa 18 52 71 a1 d0 06 1f d0 e9
    77 7a d1 ec 0c 71 59 1f 57 8b f7 b8 e5 a1

    # Signature:
    45 14 21 0e 54 1d 5b ad 7d d6 0a e5 49 b9 43 ac
    c4 4f 21 39 0d f5 b6 13 18 45 5a 17 61 0d f5 b7
    4d 84 ae d2 32 f1 7e 59 d9 1d d2 65 99 22 f8 12
    db d4 96 81 69 03 84 b9 54 e9 ad fb 9b 1a 96 8c
    0c bf f7 63 ec ee d6 27 50 c5 91 64 b5 e0 80 a8
    fe f3 d5 5b fe 2a cf ad 27 52 a6 a8 45 9f a1 fa
    b4 9a d3 78 c6 96 4b 23 ee 97 fd 10 34 61 0c 5c
    c1 4c 61 e0 eb fb 17 11 f8 ad e9 6f e6 55 7b 38

    # <snip>

    # =============================================

    # <snip>
    """).splitlines()

    vectors = tuple(load_pkcs1_vectors(vector_data))
    expected = (
        (
            {
                'modulus': int(
                    '495370a1fb18543c16d3631e3163255df62be6eee890d5f25509e4f77'
                    '8a8ea6fbbbcdf85dff64e0d972003ab3681fbba6dd41fd541829b2e58'
                    '2de9f2a4a4e0a2d0900bef4753db3cee0ee06c7dfae8b1d53b5953218'
                    'f9cceea695b08668edeaadced9463b1d790d5ebf27e9115b46cad4d9a'
                    '2b8efab0561b0810344739ada0733f', 16),
                'public_exponent': int('10001', 16),
                'private_exponent': int(
                    '6c66ffe98980c38fcdeab5159898836165f4b4b817c4f6a8d486ee4ea'
                    '9130fe9b9092bd136d184f95f504a607eac565846d2fdd6597a8967c7'
                    '396ef95a6eeebb4578a643966dca4d8ee3de842de63279c618159c1ab'
                    '54a89437b6a6120e4930afb52a4ba6ced8a4947ac64b30a3497cbe701'
                    'c2d6266d517219ad0ec6d347dbe9', 16),
                'p': int(
                    '8dad7f11363faa623d5d6d5e8a319328d82190d7127d2846c439b0ab7'
                    '2619b0a43a95320e4ec34fc3a9cea876422305bd76c5ba7be9e2f410c'
                    '8060645a1d29edb', 16),
                'q': int(
                    '847e732376fc7900f898ea82eb2b0fc418565fdae62f7d9ec4ce2217b'
                    '97990dd272db157f99f63c0dcbb9fbacdbd4c4dadb6df67756358ca41'
                    '74825b48f49706d', 16),
                'dmp1': int(
                    '05c2a83c124b3621a2aa57ea2c3efe035eff4560f33ddebb7adab81fc'
                    'e69a0c8c2edc16520dda83d59a23be867963ac65f2cc710bbcfb96ee1'
                    '03deb771d105fd85', 16),
                'dmq1': int(
                    '04cae8aa0d9faa165c87b682ec140b8ed3b50b24594b7a3b2c220b366'
                    '9bb819f984f55310a1ae7823651d4a02e99447972595139363434e5e3'
                    '0a7e7d241551e1b9', 16),
                'iqmp': int(
                    '07d3e47bf686600b11ac283ce88dbb3f6051e8efd04680e44c171ef53'
                    '1b80b2b7c39fc766320e2cf15d8d99820e96ff30dc69691839c4b40d7'
                    'b06e45307dc91f3f', 16),
                'examples': [
                    {
                        'message': b'81332f4be62948415ea1d899792eeacf6c6e1db1d'
                                   b'a8be13b5cea41db2fed467092e1ff398914c71425'
                                   b'9775f595f8547f735692a575e6923af78f22c6997'
                                   b'ddb90fb6f72d7bb0dd5744a31decd3dc368584983'
                                   b'6ed34aec596304ad11843c4f88489f209735f5fb7'
                                   b'fdaf7cec8addc5818168f880acbf490d51005b7a8'
                                   b'e84e43e54287977571dd99eea4b161eb2df1f5108'
                                   b'f12a4142a83322edb05a75487a3435c9a78ce53ed'
                                   b'93bc550857d7a9fb',
                        'salt': b'1d65491d79c864b373009be6f6f2467bac4c78fa',
                        'signature': b'0262ac254bfa77f3c1aca22c5179f8f040422b3'
                                     b'c5bafd40a8f21cf0fa5a667ccd5993d42dbafb4'
                                     b'09c520e25fce2b1ee1e716577f1efa17f3da280'
                                     b'52f40f0419b23106d7845aaf01125b698e7a4df'
                                     b'e92d3967bb00c4d0d35ba3552ab9a8b3eef07c7'
                                     b'fecdbc5424ac4db1e20cb37d0b2744769940ea9'
                                     b'07e17fbbca673b20522380c5'
                    }, {
                        'message': b'e2f96eaf0e05e7ba326ecca0ba7fd2f7c02356f3c'
                                   b'ede9d0faabf4fcc8e60a973e5595fd9ea08',
                        'salt': b'435c098aa9909eb2377f1248b091b68987ff1838',
                        'signature': b'2707b9ad5115c58c94e932e8ec0a280f56339e4'
                                     b'4a1b58d4ddcff2f312e5f34dcfe39e89c6a94dc'
                                     b'ee86dbbdae5b79ba4e0819a9e7bfd9d982e7ee6'
                                     b'c86ee68396e8b3a14c9c8f34b178eb741f9d3f1'
                                     b'21109bf5c8172fada2e768f9ea1433032c004a8'
                                     b'aa07eb990000a48dc94c8bac8aabe2b09b1aa46'
                                     b'c0a2aa0e12f63fbba775ba7e'
                    }
                ]
            },

            {
                'modulus': int(
                    '495370a1fb18543c16d3631e3163255df62be6eee890d5f25509e4f77'
                    '8a8ea6fbbbcdf85dff64e0d972003ab3681fbba6dd41fd541829b2e58'
                    '2de9f2a4a4e0a2d0900bef4753db3cee0ee06c7dfae8b1d53b5953218'
                    'f9cceea695b08668edeaadced9463b1d790d5ebf27e9115b46cad4d9a'
                    '2b8efab0561b0810344739ada0733f', 16),
                'public_exponent': int('10001', 16)
            }
        ),
        (
            {
                'modulus': int(
                    'e6bd692ac96645790403fdd0f5beb8b9bf92ed10007fc365046419dd0'
                    '6c05c5b5b2f48ecf989e4ce269109979cbb40b4a0ad24d22483d1ee31'
                    '5ad4ccb1534268352691c524f6dd8e6c29d224cf246973aec86c5bf6b'
                    '1401a850d1b9ad1bb8cbcec47b06f0f8c7f45d3fc8f319299c5433ddb'
                    'c2b3053b47ded2ecd4a4caefd614833dc8bb622f317ed076b8057fe8d'
                    'e3f84480ad5e83e4a61904a4f248fb397027357e1d30e463139815c6f'
                    'd4fd5ac5b8172a45230ecb6318a04f1455d84e5a8b', 16),
                'public_exponent': int('10001', 16),
                'private_exponent': int(
                    '6a7fd84fb85fad073b34406db74f8d61a6abc12196a961dd79565e9da'
                    '6e5187bce2d980250f7359575359270d91590bb0e427c71460b55d514'
                    '10b191bcf309fea131a92c8e702738fa719f1e0041f52e40e91f229f4'
                    'd96a1e6f172e15596b4510a6daec26105f2bebc53316b87bdf2131166'
                    '6070e8dfee69d52c71a976caae79c72b68d28580dc686d9f5129d225f'
                    '82b3d615513a882b3db91416b48ce08888213e37eeb9af800d81cab32'
                    '8ce420689903c00c7b5fd31b75503a6d419684d629', 16),
                'p': int(
                    'f8eb97e98df12664eefdb761596a69ddcd0e76daece6ed4bf5a1b50ac'
                    '086f7928a4d2f8726a77e515b74da41988f220b1cc87aa1fc810ce99a'
                    '82f2d1ce821edced794c6941f42c7a1a0b8c4d28c75ec60b652279f61'
                    '54a762aed165d47dee367', 16),
                'q': int(
                    'ed4d71d0a6e24b93c2e5f6b4bbe05f5fb0afa042d204fe3378d365c2f'
                    '288b6a8dad7efe45d153eef40cacc7b81ff934002d108994b94a5e472'
                    '8cd9c963375ae49965bda55cbf0efed8d6553b4027f2d86208a6e6b48'
                    '9c176128092d629e49d3d', 16),
                'dmp1': int(
                    '2bb68bddfb0c4f56c8558bffaf892d8043037841e7fa81cfa61a38c5e'
                    '39b901c8ee71122a5da2227bd6cdeeb481452c12ad3d61d5e4f776a0a'
                    'b556591befe3e59e5a7fddb8345e1f2f35b9f4cee57c32414c086aec9'
                    '93e9353e480d9eec6289f', 16),
                'dmq1': int(
                    '4ff897709fad079746494578e70fd8546130eeab5627c49b080f05ee4'
                    'ad9f3e4b7cba9d6a5dff113a41c3409336833f190816d8a6bc42e9bec'
                    '56b7567d0f3c9c696db619b245d901dd856db7c8092e77e9a1cccd56e'
                    'e4dba42c5fdb61aec2669', 16),
                'iqmp': int(
                    '77b9d1137b50404a982729316efafc7dfe66d34e5a182600d5f30a0a8'
                    '512051c560d081d4d0a1835ec3d25a60f4e4d6aa948b2bf3dbb5b124c'
                    'bbc3489255a3a948372f6978496745f943e1db4f18382ceaa505dfc65'
                    '757bb3f857a58dce52156', 16),
                'examples': [
                    {
                        'message': b'06add75ab689de067744e69a2ebd4b90fa9383003'
                                   b'cd05ff536cbf294cd215f0923b7fc9004f0aa1852'
                                   b'71a1d0061fd0e9777ad1ec0c71591f578bf7b8e5a'
                                   b'1',
                        'signature': b'4514210e541d5bad7dd60ae549b943acc44f213'
                                     b'90df5b61318455a17610df5b74d84aed232f17e'
                                     b'59d91dd2659922f812dbd49681690384b954e9a'
                                     b'dfb9b1a968c0cbff763eceed62750c59164b5e0'
                                     b'80a8fef3d55bfe2acfad2752a6a8459fa1fab49'
                                     b'ad378c6964b23ee97fd1034610c5cc14c61e0eb'
                                     b'fb1711f8ade96fe6557b38'
                    }
                ]
            },

            {
                'modulus': int(
                    'e6bd692ac96645790403fdd0f5beb8b9bf92ed10007fc365046419dd0'
                    '6c05c5b5b2f48ecf989e4ce269109979cbb40b4a0ad24d22483d1ee31'
                    '5ad4ccb1534268352691c524f6dd8e6c29d224cf246973aec86c5bf6b'
                    '1401a850d1b9ad1bb8cbcec47b06f0f8c7f45d3fc8f319299c5433ddb'
                    'c2b3053b47ded2ecd4a4caefd614833dc8bb622f317ed076b8057fe8d'
                    'e3f84480ad5e83e4a61904a4f248fb397027357e1d30e463139815c6f'
                    'd4fd5ac5b8172a45230ecb6318a04f1455d84e5a8b', 16),
                'public_exponent': int('10001', 16)
            }
        )
    )
    assert vectors == expected


def test_load_hotp_vectors():
    vector_data = textwrap.dedent("""
    # HOTP Test Vectors
    # RFC 4226 Appendix D

    COUNT = 0
    COUNTER = 0
    INTERMEDIATE = cc93cf18508d94934c64b65d8ba7667fb7cde4b0
    TRUNCATED = 4c93cf18
    HOTP = 755224
    SECRET = 12345678901234567890

    COUNT = 1
    COUNTER = 1
    INTERMEDIATE = 75a48a19d4cbe100644e8ac1397eea747a2d33ab
    TRUNCATED = 41397eea
    HOTP = 287082
    SECRET = 12345678901234567890


    COUNT = 2
    COUNTER = 2
    INTERMEDIATE = 0bacb7fa082fef30782211938bc1c5e70416ff44
    TRUNCATED = 82fef30
    HOTP = 359152
    SECRET = 12345678901234567890


    COUNT = 3
    COUNTER = 3
    INTERMEDIATE = 66c28227d03a2d5529262ff016a1e6ef76557ece
    TRUNCATED = 66ef7655
    HOTP = 969429
    SECRET = 12345678901234567890
    """).splitlines()

    assert load_nist_vectors(vector_data) == [
        {
            "counter": b"0",
            "intermediate": b"cc93cf18508d94934c64b65d8ba7667fb7cde4b0",
            "truncated": b"4c93cf18",
            "hotp": b"755224",
            "secret": b"12345678901234567890",
        },
        {
            "counter": b"1",
            "intermediate": b"75a48a19d4cbe100644e8ac1397eea747a2d33ab",
            "truncated": b"41397eea",
            "hotp": b"287082",
            "secret": b"12345678901234567890",
        },
        {
            "counter": b"2",
            "intermediate": b"0bacb7fa082fef30782211938bc1c5e70416ff44",
            "truncated": b"82fef30",
            "hotp": b"359152",
            "secret": b"12345678901234567890",
        },
        {
            "counter": b"3",
            "intermediate": b"66c28227d03a2d5529262ff016a1e6ef76557ece",
            "truncated": b"66ef7655",
            "hotp": b"969429",
            "secret": b"12345678901234567890",
        },
    ]


def test_load_totp_vectors():
    vector_data = textwrap.dedent("""
    # TOTP Test Vectors
    # RFC 6238 Appendix B

    COUNT = 0
    TIME = 59
    TOTP = 94287082
    MODE = SHA1
    SECRET = 12345678901234567890

    COUNT = 1
    TIME = 59
    TOTP = 46119246
    MODE = SHA256
    SECRET = 12345678901234567890

    COUNT = 2
    TIME = 59
    TOTP = 90693936
    MODE = SHA512
    SECRET = 12345678901234567890
    """).splitlines()

    assert load_nist_vectors(vector_data) == [
        {
            "time": b"59",
            "totp": b"94287082",
            "mode": b"SHA1",
            "secret": b"12345678901234567890",
        },
        {
            "time": b"59",
            "totp": b"46119246",
            "mode": b"SHA256",
            "secret": b"12345678901234567890",
        },
        {
            "time": b"59",
            "totp": b"90693936",
            "mode": b"SHA512",
            "secret": b"12345678901234567890",
        },
    ]


def test_load_rsa_nist_vectors():
    vector_data = textwrap.dedent("""
    # CAVS 11.4
    # "SigGen PKCS#1 RSASSA-PSS" information
    # Mod sizes selected: 1024 1536 2048 3072 4096
    # SHA Algorithm selected:SHA1 SHA224 SHA256 SHA384 SHA512
    # Salt len: 20

    [mod = 1024]

    n = bcb47b2e0dafcba81ff2a2b5cb115ca7e757184c9d72bcdcda707a146b3b4e29989d

    e = 00000000000000000000000000000000000000000000000000000000000000000010001
    SHAAlg = SHA1
    Msg = 1248f62a4389f42f7b4bb131053d6c88a994db2075b912ccbe3ea7dc611714f14e
    S = 682cf53c1145d22a50caa9eb1a9ba70670c5915e0fdfde6457a765de2a8fe12de97

    SHAAlg = SHA384
    Msg = e511903c2f1bfba245467295ac95413ac4746c984c3750a728c388aa628b0ebf
    S = 9c748702bbcc1f9468864cd360c8c39d007b2d8aaee833606c70f7593cf0d1519

    [mod = 1024]

    n = 1234567890

    e = 0010001

    SHAAlg = SHA512
    Msg = 3456781293fab829
    S = deadbeef0000
    """).splitlines()

    vectors = load_rsa_nist_vectors(vector_data)
    assert vectors == [
        {
            "modulus": int("bcb47b2e0dafcba81ff2a2b5cb115ca7e757184c9d72bcdcda"
                           "707a146b3b4e29989d", 16),
            "public_exponent": 65537,
            "algorithm": "SHA1",
            "salt_length": 20,
            "msg": b"1248f62a4389f42f7b4bb131053d6c88a994db2075b912ccbe3ea7dc6"
                   b"11714f14e",
            "s": b"682cf53c1145d22a50caa9eb1a9ba70670c5915e0fdfde6457a765de2a8"
                 b"fe12de97",
            "fail": False
        },
        {
            "modulus": int("bcb47b2e0dafcba81ff2a2b5cb115ca7e757184c9d72bcdcda"
                           "707a146b3b4e29989d", 16),
            "public_exponent": 65537,
            "algorithm": "SHA384",
            "salt_length": 20,
            "msg": b"e511903c2f1bfba245467295ac95413ac4746c984c3750a728c388aa6"
                   b"28b0ebf",
            "s": b"9c748702bbcc1f9468864cd360c8c39d007b2d8aaee833606c70f7593cf"
                 b"0d1519",
            "fail": False
        },
        {
            "modulus": 78187493520,
            "public_exponent": 65537,
            "algorithm": "SHA512",
            "salt_length": 20,
            "msg": b"3456781293fab829",
            "s": b"deadbeef0000",
            "fail": False
        },
    ]


def test_load_rsa_nist_pkcs1v15_verification_vectors():
    vector_data = textwrap.dedent("""
    # CAVS 11.0
    # "SigVer PKCS#1 Ver 1.5" information
    # Mod sizes selected: 1024 1536 2048 3072 4096
    # SHA Algorithm selected:SHA1 SHA224 SHA256 SHA384 SHA512
    # Generated on Wed Mar 02 00:13:02 2011

    [mod = 1024]

    n = be499b5e7f06c83fa0293e31465c8eb6b58af920bae52a7b5b9bfeb7aa72db126411

    p = e7a80c5d211c06acb900939495f26d365fc2b4825b75e356f89003eaa5931e6be5c3
    q = d248aa248000f720258742da67b711940c8f76e1ecd52b67a6ffe1e49354d66ff84f

    SHAAlg = SHA1
    e = 00000000000000000000000000000000000000000000000000000000000000000011
    d = 0d0f17362bdad181db4e1fe03e8de1a3208989914e14bf269558826bfa20faf4b68d
    Msg = 6b9cfac0ba1c7890b13e381ce752195cc1375237db2afcf6a9dcd1f95ec733a80c
    S = 562d87b5781c01d166fef3972669a0495c145b898a17df4743fbefb0a1582bd6ba9d
    SaltVal = 11223344555432167890
    Result = F (3 - Signature changed )

    SHAAlg = SHA1
    e = 0000000000003
    d = bfa20faf4b68d
    Msg = 2a67c70ff14f9b34ddb42e6f89d5971057a0da980fc9ae70c81a84da0c0ac42737
    S = 2b91c6ae2b3c46ff18d5b7abe239634cb752d0acb53eea0ccd8ea8483036a50e8faf
    SaltVal = 11223344555432167890
    Result = P
    """).splitlines()

    vectors = load_rsa_nist_vectors(vector_data)
    assert vectors == [
        {
            "modulus": int("be499b5e7f06c83fa0293e31465c8eb6b58af920bae52a7b5b"
                           "9bfeb7aa72db126411", 16),
            "p": int("e7a80c5d211c06acb900939495f26d365fc2b4825b75e356f89003ea"
                     "a5931e6be5c3", 16),
            "q": int("d248aa248000f720258742da67b711940c8f76e1ecd52b67a6ffe1e4"
                     "9354d66ff84f", 16),
            "public_exponent": 17,
            "algorithm": "SHA1",
            "private_exponent": int("0d0f17362bdad181db4e1fe03e8de1a3208989914"
                                    "e14bf269558826bfa20faf4b68d", 16),
            "msg": b"6b9cfac0ba1c7890b13e381ce752195cc1375237db2afcf6a9dcd1f95"
                   b"ec733a80c",
            "s": b"562d87b5781c01d166fef3972669a0495c145b898a17df4743fbefb0a15"
                 b"82bd6ba9d",
            "saltval": b"11223344555432167890",
            "fail": True
        },
        {
            "modulus": int("be499b5e7f06c83fa0293e31465c8eb6b58af920bae52a7b5b"
                           "9bfeb7aa72db126411", 16),
            "p": int("e7a80c5d211c06acb900939495f26d365fc2b4825b75e356f89003ea"
                     "a5931e6be5c3", 16),
            "q": int("d248aa248000f720258742da67b711940c8f76e1ecd52b67a6ffe1e4"
                     "9354d66ff84f", 16),
            "public_exponent": 3,
            "algorithm": "SHA1",
            "private_exponent": int("bfa20faf4b68d", 16),
            "msg": b"2a67c70ff14f9b34ddb42e6f89d5971057a0da980fc9ae70c81a84da0"
                   b"c0ac42737",
            "s": b"2b91c6ae2b3c46ff18d5b7abe239634cb752d0acb53eea0ccd8ea848303"
                 b"6a50e8faf",
            "saltval": b"11223344555432167890",
            "fail": False
        },
    ]


def test_load_rsa_nist_pss_verification_vectors():
    vector_data = textwrap.dedent("""
    # CAVS 11.0
    # "SigVer PKCS#1 RSASSA-PSS" information
    # Mod sizes selected: 1024 1536 2048 3072 4096
    # SHA Algorithm selected:SHA1 SHA224 SHA256 SHA384 SHA512
    # Salt len: 10
    # Generated on Wed Mar 02 00:25:22 2011

    [mod = 1024]

    n = be499b5e7f06c83fa0293e31465c8eb6b5

    p = e7a80c5d211c06acb900939495f26d365f
    q = d248aa248000f720258742da67b711940c

    SHAAlg = SHA1
    e = 00000000000000011
    d = c8e26a88239672cf49b3422a07c4d834ba
    Msg = 6b9cfac0ba1c7890b13e381ce752195c
    S = 562d87b5781c01d166fef3972669a0495c
    SaltVal = 11223344555432167890
    Result = F (3 - Signature changed )

    SHAAlg = SHA384
    e = 000003
    d = 0d0f17362bdad181db4e1fe03e8de1a320
    Msg = 2a67c70ff14f9b34ddb42e6f89d59710
    S = 2b91c6ae2b3c46ff18d5b7abe239634cb7
    SaltVal = 11223344555432167890
    Result = P
    """).splitlines()

    vectors = load_rsa_nist_vectors(vector_data)
    assert vectors == [
        {
            "modulus": int("be499b5e7f06c83fa0293e31465c8eb6b5", 16),
            "p": int("e7a80c5d211c06acb900939495f26d365f", 16),
            "q": int("d248aa248000f720258742da67b711940c", 16),
            "public_exponent": 17,
            "algorithm": "SHA1",
            "private_exponent": int("c8e26a88239672cf49b3422a07c4d834ba", 16),
            "msg": b"6b9cfac0ba1c7890b13e381ce752195c",
            "s": b"562d87b5781c01d166fef3972669a0495c",
            "saltval": b"11223344555432167890",
            "salt_length": 10,
            "fail": True
        },
        {
            "modulus": int("be499b5e7f06c83fa0293e31465c8eb6b5", 16),
            "p": int("e7a80c5d211c06acb900939495f26d365f", 16),
            "q": int("d248aa248000f720258742da67b711940c", 16),
            "public_exponent": 3,
            "algorithm": "SHA384",
            "private_exponent": int("0d0f17362bdad181db4e1fe03e8de1a320", 16),
            "msg": b"2a67c70ff14f9b34ddb42e6f89d59710",
            "s": b"2b91c6ae2b3c46ff18d5b7abe239634cb7",
            "saltval": b"11223344555432167890",
            "salt_length": 10,
            "fail": False
        },
    ]


def test_load_fips_dsa_key_pair_vectors():
    vector_data = textwrap.dedent("""
    #  CAVS 11.1
    #  "KeyPair" information
    #  Mod sizes selected: L=1024, N=160:: L=2048, N=224 :: L=2048, N=256 :: L
=3072, N=256
    # Generated on Wed May 04 08:50:52 2011


    [mod = L=1024, N=160]

    P = d38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d4b725ef341eabb47cf8a7a\
8a41e792a156b7ce97206c4f9c5ce6fc5ae7912102b6b502e59050b5b21ce263dddb2044b65223\
6f4d42ab4b5d6aa73189cef1ace778d7845a5c1c1c7147123188f8dc551054ee162b634d60f097\
f719076640e20980a0093113a8bd73
    Q = 96c5390a8b612c0e422bb2b0ea194a3ec935a281
    G = 06b7861abbd35cc89e79c52f68d20875389b127361ca66822138ce4991d2b862259d6b\
4548a6495b195aa0e0b6137ca37eb23b94074d3c3d300042bdf15762812b6333ef7b07ceba7860\
7610fcc9ee68491dbc1e34cd12615474e52b18bc934fb00c61d39e7da8902291c4434a4e2224c3\
f4fd9f93cd6f4f17fc076341a7e7d9

    X = 8185fee9cc7c0e91fd85503274f1cd5a3fd15a49
    Y = 6f26d98d41de7d871b6381851c9d91fa03942092ab6097e76422070edb71db44ff5682\
80fdb1709f8fc3feab39f1f824adaeb2a298088156ac31af1aa04bf54f475bdcfdcf2f8a2dd973\
e922d83e76f016558617603129b21c70bf7d0e5dc9e68fe332e295b65876eb9a12fe6fca9f1a1c\
e80204646bf99b5771d249a6fea627

    X = 85322d6ea73083064376099ca2f65f56e8522d9b
    Y = 21f8690f717c9f4dcb8f4b6971de2f15b9231fcf41b7eeb997d781f240bfdddfd2090d\
22083c26cca39bf37c9caf1ec89518ea64845a50d747b49131ffff6a2fd11ea7bacbb93c7d0513\
7383a06365af82225dd3713ca5a45006316f53bd12b0e260d5f79795e5a4c9f353f12867a1d320\
2394673ada8563b71555e53f415254

    [mod = L=2048, N=224]

    P = 904ef8e31e14721910fa0969e77c99b79f190071a86026e37a887a6053960dbfb74390\
a6641319fe0af32c4e982934b0f1f4c5bc57534e8e56d77c36f0a99080c0d5bc9022fa34f58922\
81d7b1009571cb5b35699303f912b276d86b1b0722fc0b1500f0ffb2e4d90867a3bdca181a9734\
617a8a9f991aa7c14dec1cf45ceba00600f8425440ed0c3b52c82e3aa831932a98b477da220867\
eb2d5e0ca34580b33b1b65e558411ed09c369f4717bf03b551787e13d9e47c267c91c697225265\
da157945cd8b32e84fc45b80533265239aa00a2dd3d05f5cb231b7daf724b7ecdce170360a8397\
2e5be94626273d449f441be300a7345db387bebadad67d8060a7
    Q = d7d0a83e84d13032b830ed74a6a88592ec9a4cf42bf37080c6600aad
    G = 2050b18d3c9f39fac396c009310d6616f9309b67b59aef9aee813d6b4f12ee29ba8a6b\
350b11d4336d44b4641230002d870f1e6b1d8728bdd40262df0d2440999185ae077f7034c61679\
f4360fbb5d181569e7cb8acb04371c11ba55f1bbd777b74304b99b66d4405303e7120dc8bc4785\
f56e9533e65b63a0c77cce7bba0d5d6069df5edffa927c5a255a09405a008258ed93506a843366\
2154f6f67e922d7c9788f04d4ec09581063950d9cde8e373ea59a58b2a6df6ba8663345574fabb\
a9ca981696d83aeac1f34f14f1a813ba900b3f0341dea23f7d3297f919a97e1ae00ac0728c93fe\
0a88b66591baf4eb0bc6900f39ba5feb41cbbeea7eb7919aa4d3

    X = 3f19424da3b4f0cafca3fc5019fcd225dd7e496ffdf6b77e364f45be
    Y = 7681ed0ac257ab7ff17c52de4638c0614749792707a0c0d23883697e34963df15c806f\
a6206f7fafb3269018e7703bd1e6f518d13544331a017713dbbe0cee8da6c095271fbf24edb74a\
44e18b1d3b835622f68d31921c67c83e8479d1972ed0cb106c68188fe22c044254251ebf880b90\
49dc3b7958ef61e1e67d2f677d2a7d2ab6b7c42b70cc5dedc3e5de7459a2dbc70c69008553d7ff\
b6bf81c012c8bd67bdddeaab9a4a4373027912a7c7d9cd9cfc6c81dffe0cc7a6d40c3b2065aee7\
be80e3c35497d64c8045bc511edaf7314c84c56bd9f0fecf62262ea5b45b49a0cffb223713bdbd\
3ad03a25a0bb2211eba41ffcd08ab0e1ad485c29a3fc25ee8359

    X = 241396352dd26efe0e2e184da52fe2b61d9d51b91b5009674c447854
    Y = 2f07a3aa9884c65288e5fef56c7b7f4445632273290bae6fcaab87c90058b2bef81ad3\
34958657cf649ffb976d618b34ce69ef6d68c0d8bfe275cf097a301e8dd5595958e0c668c15f67\
b5c0b0d01983057ce61593635aab5e0564ed720b0336f055a86755c76be22df3b8487f16e2ba0b\
5136fd30d7e3b1d30c3bd298d3acc0a1988a11756c94e9a53184d0d3edfbb649caf03eace3083d\
e9933921e627f4b2e011d1c79e45d8ea1eb7e4e59a1cbd8382b3238474eb949749c985200fbb25\
41e2dce080aa881945d4d935076e48a0846dc5513bb4da8563b946af54f546455931e79c065ce7\
ca223a98f8fde40091d38eb2c3eb8e3b81d88374f3146b0afc42

    [mod = L=2048, N=256]

    P = ea1fb1af22881558ef93be8a5f8653c5a559434c49c8c2c12ace5e9c41434c9cf0a8e9\
498acb0f4663c08b4484eace845f6fb17dac62c98e706af0fc74e4da1c6c2b3fbf5a1d58ff82fc\
1a66f3e8b12252c40278fff9dd7f102eed2cb5b7323ebf1908c234d935414dded7f8d244e54561\
b0dca39b301de8c49da9fb23df33c6182e3f983208c560fb5119fbf78ebe3e6564ee235c6a15cb\
b9ac247baba5a423bc6582a1a9d8a2b4f0e9e3d9dbac122f750dd754325135257488b1f6ecabf2\
1bff2947fe0d3b2cb7ffe67f4e7fcdf1214f6053e72a5bb0dd20a0e9fe6db2df0a908c36e95e60\
bf49ca4368b8b892b9c79f61ef91c47567c40e1f80ac5aa66ef7
    Q = 8ec73f3761caf5fdfe6e4e82098bf10f898740dcb808204bf6b18f507192c19d
    G = e4c4eca88415b23ecf811c96e48cd24200fe916631a68a684e6ccb6b1913413d344d1d\
8d84a333839d88eee431521f6e357c16e6a93be111a98076739cd401bab3b9d565bf4fb99e9d18\
5b1e14d61c93700133f908bae03e28764d107dcd2ea7674217622074bb19efff482f5f5c1a86d5\
551b2fc68d1c6e9d8011958ef4b9c2a3a55d0d3c882e6ad7f9f0f3c61568f78d0706b10a26f23b\
4f197c322b825002284a0aca91807bba98ece912b80e10cdf180cf99a35f210c1655fbfdd74f13\
b1b5046591f8403873d12239834dd6c4eceb42bf7482e1794a1601357b629ddfa971f2ed273b14\
6ec1ca06d0adf55dd91d65c37297bda78c6d210c0bc26e558302

    X = 405772da6e90d809e77d5de796562a2dd4dfd10ef00a83a3aba6bd818a0348a1
    Y = 6b32e31ab9031dc4dd0b5039a78d07826687ab087ae6de4736f5b0434e1253092e8a0b\
231f9c87f3fc8a4cb5634eb194bf1b638b7a7889620ce6711567e36aa36cda4604cfaa601a4591\
8371d4ccf68d8b10a50a0460eb1dc0fff62ef5e6ee4d473e18ea4a66c196fb7e677a49b48241a0\
b4a97128eff30fa437050501a584f8771e7280d26d5af30784039159c11ebfea10b692fd0a5821\
5eeb18bff117e13f08db792ed4151a218e4bed8dddfb0793225bd1e9773505166f4bd8cedbb286\
ea28232972da7bae836ba97329ba6b0a36508e50a52a7675e476d4d4137eae13f22a9d2fefde70\
8ba8f34bf336c6e76331761e4b0617633fe7ec3f23672fb19d27

    X = 0e0b95e31fda3f888059c46c3002ef8f2d6be112d0209aeb9e9545da67aeea80
    Y = 778082b77ddba6f56597cc74c3a612abf2ddbd85cc81430c99ab843c1f630b9db01399\
65f563978164f9bf3a8397256be714625cd41cd7fa0067d94ea66d7e073f7125af692ad01371d4\
a17f4550590378f2b074030c20e36911598a1018772f61be3b24de4be5a388ccc09e15a92819c3\
1dec50de9fde105b49eaa097b9d13d9219eeb33b628facfd1c78a7159c8430d0647c506e7e3de7\
4763cb351eada72c00bef3c9641881e6254870c1e6599f8ca2f1bbb74f39a905e3a34e4544168e\
6e50c9e3305fd09cab6ed4aff6fda6e0d5bf375c81ac9054406d9193b003c89272f1bd83d48250\
134b65c77c2b6332d38d34d9016f0e8975536ad6c348a1faedb0

    [mod = L=3072, N=256]

    P = f335666dd1339165af8b9a5e3835adfe15c158e4c3c7bd53132e7d5828c352f593a9a7\
87760ce34b789879941f2f01f02319f6ae0b756f1a842ba54c85612ed632ee2d79ef17f06b77c6\
41b7b080aff52a03fc2462e80abc64d223723c236deeb7d201078ec01ca1fbc1763139e25099a8\
4ec389159c409792080736bd7caa816b92edf23f2c351f90074aa5ea2651b372f8b58a0a65554d\
b2561d706a63685000ac576b7e4562e262a14285a9c6370b290e4eb7757527d80b6c0fd5df831d\
36f3d1d35f12ab060548de1605fd15f7c7aafed688b146a02c945156e284f5b71282045aba9844\
d48b5df2e9e7a5887121eae7d7b01db7cdf6ff917cd8eb50c6bf1d54f90cce1a491a9c74fea88f\
7e7230b047d16b5a6027881d6f154818f06e513faf40c8814630e4e254f17a47bfe9cb519b9828\
9935bf17673ae4c8033504a20a898d0032ee402b72d5986322f3bdfb27400561f7476cd715eaab\
b7338b854e51fc2fa026a5a579b6dcea1b1c0559c13d3c1136f303f4b4d25ad5b692229957
    Q = d3eba6521240694015ef94412e08bf3cf8d635a455a398d6f210f6169041653b
    G = ce84b30ddf290a9f787a7c2f1ce92c1cbf4ef400e3cd7ce4978db2104d7394b493c183\
32c64cec906a71c3778bd93341165dee8e6cd4ca6f13afff531191194ada55ecf01ff94d6cf7c4\
768b82dd29cd131aaf202aefd40e564375285c01f3220af4d70b96f1395420d778228f1461f5d0\
b8e47357e87b1fe3286223b553e3fc9928f16ae3067ded6721bedf1d1a01bfd22b9ae85fce7782\
0d88cdf50a6bde20668ad77a707d1c60fcc5d51c9de488610d0285eb8ff721ff141f93a9fb23c1\
d1f7654c07c46e58836d1652828f71057b8aff0b0778ef2ca934ea9d0f37daddade2d823a4d8e3\
62721082e279d003b575ee59fd050d105dfd71cd63154efe431a0869178d9811f4f231dc5dcf3b\
0ec0f2b0f9896c32ec6c7ee7d60aa97109e09224907328d4e6acd10117e45774406c4c947da802\
0649c3168f690e0bd6e91ac67074d1d436b58ae374523deaf6c93c1e6920db4a080b744804bb07\
3cecfe83fa9398cf150afa286dc7eb7949750cf5001ce104e9187f7e16859afa8fd0d775ae

    X = b2764c46113983777d3e7e97589f1303806d14ad9f2f1ef033097de954b17706
    Y = 814824e435e1e6f38daa239aad6dad21033afce6a3ebd35c1359348a0f2418871968c2\
babfc2baf47742148828f8612183178f126504da73566b6bab33ba1f124c15aa461555c2451d86\
c94ee21c3e3fc24c55527e01b1f03adcdd8ec5cb08082803a7b6a829c3e99eeb332a2cf5c035b0\
ce0078d3d414d31fa47e9726be2989b8d06da2e6cd363f5a7d1515e3f4925e0b32adeae3025cc5\
a996f6fd27494ea408763de48f3bb39f6a06514b019899b312ec570851637b8865cff3a52bf5d5\
4ad5a19e6e400a2d33251055d0a440b50d53f4791391dc754ad02b9eab74c46b4903f9d76f8243\
39914db108057af7cde657d41766a99991ac8787694f4185d6f91d7627048f827b405ec67bf2fe\
56141c4c581d8c317333624e073e5879a82437cb0c7b435c0ce434e15965db1315d64895991e6b\
be7dac040c42052408bbc53423fd31098248a58f8a67da3a39895cd0cc927515d044c1e3cb6a32\
59c3d0da354cce89ea3552c59609db10ee989986527436af21d9485ddf25f90f7dff6d2bae

    X = 52e3e040efb30e1befd909a0bdbcfd140d005b1bff094af97186080262f1904d
    Y = a5ae6e8f9b7a68ab0516dad4d7b7d002126f811d5a52e3d35c6d387fcb43fd19bf7792\
362f9c98f8348aa058bb62376685f3d0c366c520d697fcd8416947151d4bbb6f32b53528a01647\
9e99d2cd48d1fc679027c15f0042f207984efe05c1796bca8eba678dfdd00b80418e3ea840557e\
73b09e003882f9a68edba3431d351d1ca07a8150b018fdbdf6c2f1ab475792a3ccaa6594472a45\
f8dc777b60bf67de3e0f65c20d11b7d59faedf83fbce52617f500d9e514947c455274c6e900464\
767fb56599b81344cf6d12c25cb2b7d038d7b166b6cf30534811c15d0e8ab880a2ac06786ae2dd\
de61329a78d526f65245380ce877e979c5b50de66c9c30d66382c8f254653d25a1eb1d3a4897d7\
623399b473ce712a2184cf2da1861706c41466806aefe41b497db82aca6c31c8f4aa68c17d1d9e\
380b57998917655783ec96e5234a131f7299398d36f1f5f84297a55ff292f1f060958c358fed34\
6db2de45127ca728a9417b2c54203e33e53b9a061d924395b09afab8daf3e8dd7eedcec3ac
    """).splitlines()

    expected = [
        {'g': int('06b7861abbd35cc89e79c52f68d20875389b127361ca66822138ce499'
                  '1d2b862259d6b4548a6495b195aa0e0b6137ca37eb23b94074d3c3d3000'
                  '42bdf15762812b6333ef7b07ceba78607610fcc9ee68491dbc1e34cd12'
                  '615474e52b18bc934fb00c61d39e7da8902291c4434a4e2224c3f'
                  '4fd9f93cd6f4f17fc076341a7e7d9', 16),
         'p': int('d38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d4b725e'
                  'f341eabb47cf8a7a8a41e792a156b7ce97206c4f9c5ce6fc5ae791210'
                  '2b6b502e59050b5b21ce263dddb2044b652236f4d42ab4b5d6aa73189c'
                  'ef1ace778d7845a5c1c1c7147123188f8dc551054ee162b634d60f097f7'
                  '19076640e20980a0093113a8bd73', 16),
         'q': int('96c5390a8b612c0e422bb2b0ea194a3ec935a281', 16),
         'x': int('8185fee9cc7c0e91fd85503274f1cd5a3fd15a49', 16),
         'y': int('6f26d98d41de7d871b6381851c9d91fa03942092ab6097e76422'
                  '070edb71db44ff568280fdb1709f8fc3feab39f1f824adaeb2a29808815'
                  '6ac31af1aa04bf54f475bdcfdcf2f8a2dd973e922d83e76f01655861760'
                  '3129b21c70bf7d0e5dc9e68fe332e295b65876eb9a12fe6fca9f1a1ce80'
                  '204646bf99b5771d249a6fea627', 16)},
        {'g': int('06b7861abbd35cc89e79c52f68d20875389b127361ca66822138ce4991d'
                  '2b862259d6b4548a6495b195aa0e0b6137ca37eb23b94074d3c3d30004'
                  '2bdf15762812b6333ef7b07ceba78607610fcc9ee68491dbc1e34cd126'
                  '15474e52b18bc934fb00c61d39e7da8902291c4434a4e2224c3f4fd9'
                  'f93cd6f4f17fc076341a7e7d9', 16),
         'p': int('d38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d4b725ef341e'
                  'abb47cf8a7a8a41e792a156b7ce97206c4f9c5ce6fc5ae7912102b6b50'
                  '2e59050b5b21ce263dddb2044b652236f4d42ab4b5d6aa73189cef1a'
                  'ce778d7845a5c1c1c7147123188f8dc551054ee162b634d6'
                  '0f097f719076640e20980a0093113a8bd73', 16),
         'q': int('96c5390a8b612c0e422bb2b0ea194a3ec935a281', 16),
         'x': int('85322d6ea73083064376099ca2f65f56e8522d9b', 16),
         'y': int('21f8690f717c9f4dcb8f4b6971de2f15b9231fcf41b7eeb997d781f240'
                  'bfdddfd2090d22083c26cca39bf37c9caf1ec89518ea64845a50d747b49'
                  '131ffff6a2fd11ea7bacbb93c7d05137383a06365af82225dd3713c'
                  'a5a45006316f53bd12b0e260d5f79795e5a4c9f353f12867a1d3'
                  '202394673ada8563b71555e53f415254', 16)},

        {'g': int('e4c4eca88415b23ecf811c96e48cd24200fe916631a68a684e6ccb6b191'
                  '3413d344d1d8d84a333839d88eee431521f6e357c16e6a93be111a9807'
                  '6739cd401bab3b9d565bf4fb99e9d185b1e14d61c93700133f908bae0'
                  '3e28764d107dcd2ea7674217622074bb19efff482f5f5c1a86d5551b2'
                  'fc68d1c6e9d8011958ef4b9c2a3a55d0d3c882e6ad7f9f0f3c61568f78'
                  'd0706b10a26f23b4f197c322b825002284a0aca91807bba98ece912'
                  'b80e10cdf180cf99a35f210c1655fbfdd74f13b1b5046591f8403873d'
                  '12239834dd6c4eceb42bf7482e1794a1601357b629ddfa971f2ed273b1'
                  '46ec1ca06d0adf55dd91d65c37297bda78c6d210c0bc26e558302', 16),
         'p': int('ea1fb1af22881558ef93be8a5f8653c5a559434c49c8c2c12ace'
                  '5e9c41434c9cf0a8e9498acb0f4663c08b4484eace845f6fb17d'
                  'ac62c98e706af0fc74e4da1c6c2b3fbf5a1d58ff82fc1a66f3e8b122'
                  '52c40278fff9dd7f102eed2cb5b7323ebf1908c234d935414dded7f8d2'
                  '44e54561b0dca39b301de8c49da9fb23df33c6182e3f983208c560fb5'
                  '119fbf78ebe3e6564ee235c6a15cbb9ac247baba5a423bc6582a1a9d8a'
                  '2b4f0e9e3d9dbac122f750dd754325135257488b1f6ecabf21bff2947'
                  'fe0d3b2cb7ffe67f4e7fcdf1214f6053e72a5bb0dd20a0e9fe6db2df0a'
                  '908c36e95e60bf49ca4368b8b892b9c79f61ef91c47567c40e1f80ac'
                  '5aa66ef7', 16),
         'q': int('8ec73f3761caf5fdfe6e4e82098bf10f898740dcb808204bf6b1'
                  '8f507192c19d', 16),
         'x': int('405772da6e90d809e77d5de796562a2dd4dfd10ef00a83a3aba6'
                  'bd818a0348a1', 16),
         'y': int('6b32e31ab9031dc4dd0b5039a78d07826687ab087ae6de4736f5'
                  'b0434e1253092e8a0b231f9c87f3fc8a4cb5634eb194bf1b638'
                  'b7a7889620ce6711567e36aa36cda4604cfaa601a45918371d'
                  '4ccf68d8b10a50a0460eb1dc0fff62ef5e6ee4d473e18ea4a6'
                  '6c196fb7e677a49b48241a0b4a97128eff30fa437050501a584'
                  'f8771e7280d26d5af30784039159c11ebfea10b692fd0a58215ee'
                  'b18bff117e13f08db792ed4151a218e4bed8dddfb0793225bd1e97'
                  '73505166f4bd8cedbb286ea28232972da7bae836ba97329ba6b0a36508'
                  'e50a52a7675e476d4d4137eae13f22a9d2fefde708ba8f34bf336c6e7'
                  '6331761e4b0617633fe7ec3f23672fb19d27', 16)},
        {'g': int('e4c4eca88415b23ecf811c96e48cd24200fe916631a68a684e6ccb6b191'
                  '3413d344d1d8d84a333839d88eee431521f6e357c16e6a93be111a9807'
                  '6739cd401bab3b9d565bf4fb99e9d185b1e14d61c93700133f908bae0'
                  '3e28764d107dcd2ea7674217622074bb19efff482f5f5c1a86d5551b2'
                  'fc68d1c6e9d8011958ef4b9c2a3a55d0d3c882e6ad7f9f0f3c61568f78'
                  'd0706b10a26f23b4f197c322b825002284a0aca91807bba98ece912'
                  'b80e10cdf180cf99a35f210c1655fbfdd74f13b1b5046591f8403873d'
                  '12239834dd6c4eceb42bf7482e1794a1601357b629ddfa971f2ed273b1'
                  '46ec1ca06d0adf55dd91d65c37297bda78c6d210c0bc26e558302', 16),
         'p': int('ea1fb1af22881558ef93be8a5f8653c5a559434c49c8c2c12ace'
                  '5e9c41434c9cf0a8e9498acb0f4663c08b4484eace845f6fb17d'
                  'ac62c98e706af0fc74e4da1c6c2b3fbf5a1d58ff82fc1a66f3e8b122'
                  '52c40278fff9dd7f102eed2cb5b7323ebf1908c234d935414dded7f8d2'
                  '44e54561b0dca39b301de8c49da9fb23df33c6182e3f983208c560fb5'
                  '119fbf78ebe3e6564ee235c6a15cbb9ac247baba5a423bc6582a1a9d8a'
                  '2b4f0e9e3d9dbac122f750dd754325135257488b1f6ecabf21bff2947'
                  'fe0d3b2cb7ffe67f4e7fcdf1214f6053e72a5bb0dd20a0e9fe6db2df0a'
                  '908c36e95e60bf49ca4368b8b892b9c79f61ef91c47567c40e1f80ac'
                  '5aa66ef7', 16),
         'q': int('8ec73f3761caf5fdfe6e4e82098bf10f898740dcb808204bf6b1'
                  '8f507192c19d', 16),
         'x': int('0e0b95e31fda3f888059c46c3002ef8f2d6be112d0209aeb9e95'
                  '45da67aeea80', 16),
         'y': int('778082b77ddba6f56597cc74c3a612abf2ddbd85cc81430c99ab'
                  '843c1f630b9db0139965f563978164f9bf3a8397256be714625'
                  'cd41cd7fa0067d94ea66d7e073f7125af692ad01371d4a17f45'
                  '50590378f2b074030c20e36911598a1018772f61be3b24de4be'
                  '5a388ccc09e15a92819c31dec50de9fde105b49eaa097b9d13d'
                  '9219eeb33b628facfd1c78a7159c8430d0647c506e7e3de74763c'
                  'b351eada72c00bef3c9641881e6254870c1e6599f8ca2f1bbb74f'
                  '39a905e3a34e4544168e6e50c9e3305fd09cab6ed4aff6fda6e0d'
                  '5bf375c81ac9054406d9193b003c89272f1bd83d48250134b65c77'
                  'c2b6332d38d34d9016f0e8975536ad6c348a1faedb0', 16)},

        {'g': int('ce84b30ddf290a9f787a7c2f1ce92c1cbf4ef400e3cd7ce4978d'
                  'b2104d7394b493c18332c64cec906a71c3778bd93341165dee8'
                  'e6cd4ca6f13afff531191194ada55ecf01ff94d6cf7c4768b82'
                  'dd29cd131aaf202aefd40e564375285c01f3220af4d70b96f1'
                  '395420d778228f1461f5d0b8e47357e87b1fe3286223b553e3'
                  'fc9928f16ae3067ded6721bedf1d1a01bfd22b9ae85fce77820d88cdf'
                  '50a6bde20668ad77a707d1c60fcc5d51c9de488610d0285eb8ff721f'
                  'f141f93a9fb23c1d1f7654c07c46e58836d1652828f71057b8aff0b077'
                  '8ef2ca934ea9d0f37daddade2d823a4d8e362721082e279d003b575ee'
                  '59fd050d105dfd71cd63154efe431a0869178d9811f4f231dc5dcf3b'
                  '0ec0f2b0f9896c32ec6c7ee7d60aa97109e09224907328d4e6acd1011'
                  '7e45774406c4c947da8020649c3168f690e0bd6e91ac67074d1d436b'
                  '58ae374523deaf6c93c1e6920db4a080b744804bb073cecfe83fa939'
                  '8cf150afa286dc7eb7949750cf5001ce104e9187f7e16859afa8fd0d'
                  '775ae', 16),
         'p': int('f335666dd1339165af8b9a5e3835adfe15c158e4c3c7bd53132e7d5828'
                  'c352f593a9a787760ce34b789879941f2f01f02319f6ae0b756f1a842'
                  'ba54c85612ed632ee2d79ef17f06b77c641b7b080aff52a03fc2462e8'
                  '0abc64d223723c236deeb7d201078ec01ca1fbc1763139e25099a84ec'
                  '389159c409792080736bd7caa816b92edf23f2c351f90074aa5ea2651'
                  'b372f8b58a0a65554db2561d706a63685000ac576b7e4562e262a1428'
                  '5a9c6370b290e4eb7757527d80b6c0fd5df831d36f3d1d35f12ab0605'
                  '48de1605fd15f7c7aafed688b146a02c945156e284f5b71282045aba9'
                  '844d48b5df2e9e7a5887121eae7d7b01db7cdf6ff917cd8eb50c6bf1d'
                  '54f90cce1a491a9c74fea88f7e7230b047d16b5a6027881d6f154818f'
                  '06e513faf40c8814630e4e254f17a47bfe9cb519b98289935bf17673a'
                  'e4c8033504a20a898d0032ee402b72d5986322f3bdfb27400561f7476'
                  'cd715eaabb7338b854e51fc2fa026a5a579b6dcea1b1c0559c13d3c11'
                  '36f303f4b4d25ad5b692229957', 16),
         'q': int('d3eba6521240694015ef94412e08bf3cf8d635a455a398d6f210'
                  'f6169041653b', 16),
         'x': int('b2764c46113983777d3e7e97589f1303806d14ad9f2f1ef03309'
                  '7de954b17706', 16),
         'y': int('814824e435e1e6f38daa239aad6dad21033afce6a3ebd35c1359348a0f2'
                  '418871968c2babfc2baf47742148828f8612183178f126504da73566b6'
                  'bab33ba1f124c15aa461555c2451d86c94ee21c3e3fc24c55527e'
                  '01b1f03adcdd8ec5cb08082803a7b6a829c3e99eeb332a2cf5c035b0c'
                  'e0078d3d414d31fa47e9726be2989b8d06da2e6cd363f5a7d1515e3f4'
                  '925e0b32adeae3025cc5a996f6fd27494ea408763de48f3bb39f6a06'
                  '514b019899b312ec570851637b8865cff3a52bf5d54ad5a19e6e400'
                  'a2d33251055d0a440b50d53f4791391dc754ad02b9eab74c46b4903'
                  'f9d76f824339914db108057af7cde657d41766a99991ac8787694f'
                  '4185d6f91d7627048f827b405ec67bf2fe56141c4c581d8c317333'
                  '624e073e5879a82437cb0c7b435c0ce434e15965db1315d648959'
                  '91e6bbe7dac040c42052408bbc53423fd31098248a58f8a67da3a'
                  '39895cd0cc927515d044c1e3cb6a3259c3d0da354cce89ea3552c'
                  '59609db10ee989986527436af21d9485ddf25f90f7dff6d2bae', 16)},
        {'g': int('ce84b30ddf290a9f787a7c2f1ce92c1cbf4ef400e3cd7ce4978d'
                  'b2104d7394b493c18332c64cec906a71c3778bd93341165dee8'
                  'e6cd4ca6f13afff531191194ada55ecf01ff94d6cf7c4768b82'
                  'dd29cd131aaf202aefd40e564375285c01f3220af4d70b96f1'
                  '395420d778228f1461f5d0b8e47357e87b1fe3286223b553e3'
                  'fc9928f16ae3067ded6721bedf1d1a01bfd22b9ae85fce77820d88cdf'
                  '50a6bde20668ad77a707d1c60fcc5d51c9de488610d0285eb8ff721f'
                  'f141f93a9fb23c1d1f7654c07c46e58836d1652828f71057b8aff0b077'
                  '8ef2ca934ea9d0f37daddade2d823a4d8e362721082e279d003b575ee'
                  '59fd050d105dfd71cd63154efe431a0869178d9811f4f231dc5dcf3b'
                  '0ec0f2b0f9896c32ec6c7ee7d60aa97109e09224907328d4e6acd1011'
                  '7e45774406c4c947da8020649c3168f690e0bd6e91ac67074d1d436b'
                  '58ae374523deaf6c93c1e6920db4a080b744804bb073cecfe83fa939'
                  '8cf150afa286dc7eb7949750cf5001ce104e9187f7e16859afa8fd0d'
                  '775ae', 16),
         'p': int('f335666dd1339165af8b9a5e3835adfe15c158e4c3c7bd53132e7d5828'
                  'c352f593a9a787760ce34b789879941f2f01f02319f6ae0b756f1a842'
                  'ba54c85612ed632ee2d79ef17f06b77c641b7b080aff52a03fc2462e8'
                  '0abc64d223723c236deeb7d201078ec01ca1fbc1763139e25099a84ec'
                  '389159c409792080736bd7caa816b92edf23f2c351f90074aa5ea2651'
                  'b372f8b58a0a65554db2561d706a63685000ac576b7e4562e262a1428'
                  '5a9c6370b290e4eb7757527d80b6c0fd5df831d36f3d1d35f12ab0605'
                  '48de1605fd15f7c7aafed688b146a02c945156e284f5b71282045aba9'
                  '844d48b5df2e9e7a5887121eae7d7b01db7cdf6ff917cd8eb50c6bf1d'
                  '54f90cce1a491a9c74fea88f7e7230b047d16b5a6027881d6f154818f'
                  '06e513faf40c8814630e4e254f17a47bfe9cb519b98289935bf17673a'
                  'e4c8033504a20a898d0032ee402b72d5986322f3bdfb27400561f7476'
                  'cd715eaabb7338b854e51fc2fa026a5a579b6dcea1b1c0559c13d3c11'
                  '36f303f4b4d25ad5b692229957', 16),
         'q': int('d3eba6521240694015ef94412e08bf3cf8d635a455a398d6f210'
                  'f6169041653b', 16),
         'x': int('52e3e040efb30e1befd909a0bdbcfd140d005b1bff094af97186'
                  '080262f1904d', 16),
         'y': int('a5ae6e8f9b7a68ab0516dad4d7b7d002126f811d5a52e3d35c6d'
                  '387fcb43fd19bf7792362f9c98f8348aa058bb62376685f3d0c3'
                  '66c520d697fcd8416947151d4bbb6f32b53528a016479e99d2cd'
                  '48d1fc679027c15f0042f207984efe05c1796bca8eba678dfdd0'
                  '0b80418e3ea840557e73b09e003882f9a68edba3431d351d1ca0'
                  '7a8150b018fdbdf6c2f1ab475792a3ccaa6594472a45f8dc777b'
                  '60bf67de3e0f65c20d11b7d59faedf83fbce52617f500d9e5149'
                  '47c455274c6e900464767fb56599b81344cf6d12c25cb2b7d038'
                  'd7b166b6cf30534811c15d0e8ab880a2ac06786ae2ddde61329a'
                  '78d526f65245380ce877e979c5b50de66c9c30d66382c8f25465'
                  '3d25a1eb1d3a4897d7623399b473ce712a2184cf2da1861706c4'
                  '1466806aefe41b497db82aca6c31c8f4aa68c17d1d9e380b5799'
                  '8917655783ec96e5234a131f7299398d36f1f5f84297a55ff292'
                  'f1f060958c358fed346db2de45127ca728a9417b2c54203e33e5'
                  '3b9a061d924395b09afab8daf3e8dd7eedcec3ac', 16)}
    ]

    assert expected == load_fips_dsa_key_pair_vectors(vector_data)


def test_vector_version():
    assert cryptography.__version__ == cryptography_vectors.__version__


def test_raises_unsupported_algorithm_wrong_type():
    # Check that it asserts if the wrong type of exception is raised.

    class TestException(Exception):
        pass

    with pytest.raises(TestException):
        with raises_unsupported_algorithm(None):
            raise TestException


def test_raises_unsupported_algorithm_wrong_reason():
    # Check that it asserts if the wrong reason code is raised.
    with pytest.raises(AssertionError):
        with raises_unsupported_algorithm(None):
            raise UnsupportedAlgorithm("An error.",
                                       _Reasons.BACKEND_MISSING_INTERFACE)


def test_raises_unsupported_algorithm():
    # Check that it doesnt assert if the right things are raised.
    with raises_unsupported_algorithm(
        _Reasons.BACKEND_MISSING_INTERFACE
    ) as exc:
        raise UnsupportedAlgorithm("An error.",
                                   _Reasons.BACKEND_MISSING_INTERFACE)
    assert exc
