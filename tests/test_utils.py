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

from .utils import (
    load_nist_vectors, load_vectors_from_file, load_cryptrec_vectors,
    load_hash_vectors, check_for_iface, check_backend_support,
    select_backends, load_pkcs1_vectors, load_rsa_nist_vectors,
    load_fips_dsa_key_pair_vectors
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
            "algorithm": b"SHA1",
            "salt_length": 20,
            "msg": b"1248f62a4389f42f7b4bb131053d6c88a994db2075b912ccbe3ea7dc6"
                   b"11714f14e",
            "s": b"682cf53c1145d22a50caa9eb1a9ba70670c5915e0fdfde6457a765de2a8"
                 b"fe12de97"
        },
        {
            "modulus": int("bcb47b2e0dafcba81ff2a2b5cb115ca7e757184c9d72bcdcda"
                           "707a146b3b4e29989d", 16),
            "public_exponent": 65537,
            "algorithm": b"SHA384",
            "salt_length": 20,
            "msg": b"e511903c2f1bfba245467295ac95413ac4746c984c3750a728c388aa6"
                   b"28b0ebf",
            "s": b"9c748702bbcc1f9468864cd360c8c39d007b2d8aaee833606c70f7593cf"
                 b"0d1519"
        },
        {
            "modulus": 78187493520,
            "public_exponent": 65537,
            "algorithm": b"SHA512",
            "salt_length": 20,
            "msg": b"3456781293fab829",
            "s": b"deadbeef0000"
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

    X = 8007aace9226517add3b31fb72fe57cf0b71de87
    Y = 0869599e9c233f98719353f50431b8cf9219443b245ccca95fcf81d757288b27b4ee08\
037f0a8ee5d997eecf7ddf1cae641fa0b24bb0e0fb97765166d92a79b1519cb9549431947ff58e\
de390c8fe2c44ff1fe9f8b15839d93cfd727dd0c2698ccf04f85f491d59a4e7fbf873122228af5\
c27095eea09d7d13b0d585c79c4849

    X = 2f08cf0627c8ffbde07420c324e594170da5879e
    Y = 1f9098ddb4ec6f7a14841ae87792450292f210fb5a7a908117731b3c5f3d1694331a85\
a129b0b6b5363e61544c351799ef1fd9fdae6f7707b1ef55933192b03cc41a773d1e2c119fe592\
05ce8f8c47f27ef0620c6892c61bb04907e00e6b82c81e1b77bb4e3f87562327555a226217aaaa\
4e1d29bac7cc8cbebceee3895d8917

    X = 423616c18872f9a3ae1db1f70302ae8decff0be9
    Y = b62df8a3635c8f5acdc92d710d920a643eb93010d003e6e61eee57d6a80ca5512bc1a0\
b689dd256a2ff1dcac4adb099ef66317de9c6b5188627c1f0aec54049d0bf1c8214c492d09ce82\
43af9508c49493ea8d6f85d141850ebdabf6cbfeced92c1cc0b844227eedfc03e8650f89c2b6d1\
1462d8cc5b78254574bbe558f2e724

    X = 4c4489ee5a17f30eec191644ae28105aafb82307
    Y = 37fe0fdb5adec7bd56cdd68b1fc5669c292ae0c0c7c339aab844b7b83bc0118056274a\
1f2b2bd4d4c8973458e86bddff94a6adb9b28d9a1f3ff0bc82972e3c8e452756ab7f921750f773\
d75c58346096ce2b804c57f2dee415471013d9a31d347960c42e5748d0feda02bdf0b22902103d\
e1591d9b5dcdfb18575d8c164031d1

    X = 4ea539bf524cacbbf850ea20e18659db13c14cc1
    Y = 7d4b1d55c3cba4f1d7073afda9faed928d7653eac594ef2c84a7c83a77817e186a4706\
b4dae53f67fe7fc97e5915babda7398aec5a8afa302de1af67e709d6cc5cab6d19af8350273468\
75758cedb5552494a85e8b2292f69cd2d665fc3375180f30110f5f9f03472ce431a64db795bce0\
7b0d42bb0d22dc94182dd43c2dabe3

    X = 272b5be463d69c564fb82e54b8824fd5622fd819
    Y = d133f99a7d8c5168f58a1f8be91e40d98446336533517289d40f0f6c974bbc3abd32de\
81b92ab4c0d164b44271a884992d93104cca9e85acdec20717492e7cddd24f99146e59c16877cf\
4a2f4fca669528b0e4a42b2154c09b4a15ac74d1aed9ca141b7fd6b8eeb5f315a88dfade013539\
f3ca61628411e89f0e6553ed18c03e

    X = 49df2e11a4cab60b3d8f53a02bc8d982a52035e6
    Y = 555b359dd7998b8020f04f84f7e4ee3e7d7d2352d95b6d5bc51b96a2132bc1ac779652\
ccfbfb5b102edb3861aa98d4feba59f65bd0501755c5d0d894b031841365f2f4e9749b5850542d\
be82a3b5d614d93f34692087507d2972acdab700892bb847cb4e881998342b7230aef923a07b07\
563efbc053a300c0ea284d7f381da2

    X = 06f5fe27b77fbdb24beb34f4fe13203e46ad8460
    Y = 881344b829c31389b4882c2fde977d73adb72e5001f41b57c7726b9ac99ef413d0fb5d\
f9ed587994c45580efa11d4445cea85b149e74f746308ee223c82263b14f4a2ec5ae971083dca7\
25c5fb0ae233b67a4be60be8aca3f40c5bfaf9d9c4dc40d49dec1c4e539c88cddfce40106cb6f8\
8fd094037fae75de54317ad4842cc1

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

    X = 6597601e43fd515925142b0a74933737e59c3cd2aa80a794e10a389e
    Y = 04d040606f0f62d332a4fff2800200ae6c18baf01d3f6d1e9474fffb267e0388532420\
21e3e2747345da8bb87c723cc1c9c446152b47b76044de0521a253d9f50b38f310bd3f5503d92e\
f78ba34c09988982ab8b8eabde78210cbaa68d18cf06b8fee156ffef4f85ce06af4e0515c77eba\
d16b7651273551d82732196cd7b180f747b2f9fa33ff198981ad095145207a726cac95117b2d02\
800e4d0bba1618dd2615393ecdd35c4ac45ac522ea3a6178691a51c3d83c352dfc762c22967560\
5851ecfc14af915f220632f74b2f3f285c8ec3ef5df1df2e330f24a4e45e121455813ed7671c63\
c7efa5eb67a4387386e2d62b4c0006643526333185b341bdaf74

    X = 0864c128bd440c2ae2c75818c3dd8638864c8986805229a8888b1fdd
    Y = 092501d654b604f0b8a1d979c43412ca43328b5bd5894b1f9c473b17892b02d01ef8ac\
61fd4c677e132417e57a0425042097037041a0cc76969bf3fc793cb58148bbbd2e46cd53a617cf\
57d514310d78c1aac2d45f70cf99185edee78416ef9f7e871c0454a78904a43eab19a62042038d\
a01d3e20cc564900ee917d2ba0aaf1797fcad1dff72d5b0dfd7a6a4818b352152c97d93a819237\
d8176b178aaa043be6809a92a7a529fc76e76df9083db8322b2140f84e507975bd7c11bc9d8f84\
d09e4756b60bdbd1d00d7761e45ce20c790fcc89ce9c611173750ccafc65e71c6be7bf04f8dcfc\
1023aa6595df397906b968045abcf8d04ac7a8892ac660ed864b

    X = 7b77e817e3cefa4534e7c64c6100acee0141af243a9da541727245ba
    Y = 302449ac7f32830c5ba247ed84c7164d9e868cbd93bd00bbd51afa84717f9c10f0984d\
c5a528ac2fe8d8db4852ddbd553dffb6edf424ae7fcf9c04480a1fbd4209d4cecc29f3f2ebfb8f\
5afb64b8f3cb022a3e73065483e3ea40d323fa843ffb9f2ef1be94e1f027bc680491d510177ee1\
7a217c67e60a0a4d731d03398d4c9c2b212ed5e71291369f19b1445f677d32f4c441a84f908ec9\
1d0a1c53337349eb5a74f94e127b57fd4baed51f3db00a7c4bb30b76ef088613422be64cc9e289\
8337e6cd58d06a17eaa99b7c3324badec0b559dbaf435a32f82ef9c5f2c4766870cc1b9275d3e9\
6e6315c55cf4d13ded14d8172df84eba120da038f12b1bf92dc4

    X = 12b57756670073de8bc9f25a5a9ac10cecb5a34945ece8c3cfeefbe5
    Y = 7001d0f2b7c07e7589c0c28311419177388a79fb74f7b761c79b9c33d7f516f51b56ba\
9c227cab80c5dc3a334b0ffb952ddee23a733dd4100a207cf03ff0b96a180118df0f8fdeee5621\
10d837a535476dfac4de2b9a22dada75ad30e8a0b2c40f78db89f78b7558066dc46fb51adc8e0c\
d5a43824a1bc80f46e1fcaf788e79631bfc0c93481c6f76b159043b846aee4ac94978baefe6398\
ecb1ea5873c64d972087d80b6f5a285c9f349341393bff6fc53ddaacf8222e21b2ad5a8d0a030c\
71da771110d35db80500fccb2a778f76886b2c3187a41cf349b908cef0ce4e909cf3925535bde4\
3b4162307207e2e4de23bc10381a769c4616eb0591de1fbe64f8

    X = a9f140ea5c160405bd7b0024036556de7452eaa4e44553c99d36ace9
    Y = 51cf000e715c5710110448e73647e00d8760da9cc3eed625c08e8a049ef61f8c79e88e\
0d28e3705c4031d95dcd05324007683cc65c981ea08c8698e84d291e20357899a44ae65ab98f7f\
7e7047d43883266a56a69a445449c4c179156ed4a2f5495363bba0b6c88ec609fef584d77e3359\
186c45ed89b6353839a06c9a258e3ab01d7d88a671c796787c40e539f32013de4b2cbefabc8bb2\
0a0f3c18657d11dbfb67787b818a9f75b1761bc0dd5f49d8e5f92b338f5cea0567f1dc7840df41\
ecfd1d49b2e1bb0f25ca8b90129076f57f1d137bcfca9be6dc4816b4413793c1e4deb97e545462\
88ec5ebbfbad08e8ad30e1327437d709d54febcd4d403e0b5852

    X = b865321afa5061d48c51fd3b5e2c0b3ab6bedcbe780ebc51ccceb3e0
    Y = 8b1e3f87a4a5e4b2fc6f5ea6301f48d7f82cb9608e866952177638050172dc5c7a7248\
4e526bd6593265bea0b37ac4b471f9ebe8d23b9457f680bfe3a13babfe0051a5ff38bde37cc1f0\
48c3a5169237d41e2952e64e363576b70910c29c56571dfd4c4ff4651eb43ed060e082155bc90d\
0baa2b67c6cd27d6badaecf921a276c3a98a2297b789f0e1f574eada6cae30706dfe96aef9fb43\
07509c47364ed81e2e1ac16b2c2f8e040ca00bcd3ad04a33ae562cbc3779a9cbb6fe6c51669d11\
23cfd4d5687d5c9e46c1e0e9205e638ae18f737804dfacc578c3a4aad529ceeb4695c10ed24c09\
c88a2e723fc8bcc4a8cbd9c626245cfd1c6e2caef7abee1be824

    X = 7aa8736a0b96f558c8998d65cc29dbf62f3172679b03f40ea60102d5
    Y = 6f675b01fac4ac2caac80cad0eda8ccc038c06ae8aa95ae5832f4e90ff744e73422a9d\
5d53c109b056e2205d026bc8220098de413d46c3815aeafd83c1c2a111c4bde690be1c24bb95b5\
fec1917f5d2a86533bdb8d3beebde645fe0a849479ccc92145507b0e283c81056ca3cc97685fea\
8040f1881975ca17d166494d08207bc9efd92c62f2bdc2cbd1be8bdc7cf479885e225466d09e73\
666c8d57c5e1ce3025f8912560adf769e54eb2167ccb69afbf958e178e8c0bbba55415b0f90d04\
0789ed42be470b7171556d63799618f7eaf1a5bacfb8e8f5be4bda95a57822d96cdb3b454db927\
4aac690879b66bda0672fc7fa6031ed40ac5b5a8ae5d0e4dd630

    X = 7979f52dc7a4958f5075982e1c0c359dd398cec0a75ced7897834c4b
    Y = 0264508b83422b402936c841b21b14d328202c0138180b823d22291914b00d2c2f8e3b\
033da92e4b1f76b35332362117118404a66b5c87dec38957c2a15aa5d109d763be6a02f4389a26\
c300e70b626fc68fbd04e1b2de8b8090d1a5a8e0a08dd110965569852121dcf44f92275f033cde\
840896257645d9390ff95c0afa7a5b1085e3c02a481d5b3b304bd07007654c4daabb1993480cf8\
2755a30bf9e66cf9d06f4ad75b7c2385682cc0719867ccd3e732a36ccd3275ddda126bc08e5093\
349dde5ef729a6f972648b8fc974107be92f57511dc903651d90a5f1939748769dba01f0b7afa1\
3c18e6c38a255fbba0d7d1d0eb2fdd4d1f9e2b10a9b0f7cf095c

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

    X = 835fd2d1b7b03d90c5ebc073ee69b386c9c07ca06bce80bc574634af8d534f7a
    Y = cbc3feccf1ef62d31df626a4b2e234afdf1795443e46a471ec8b902b0ae9af36344120\
ed3ca6009751b03e8963a6151e7b2fe572837c3e23815d472ce75cfbaaaaf36e89a939983bd494\
f0421b0f35079e5a243672d708ca3492539733b2a847f638167f7d64c8dd7e3cc8b2f0e7a7fb4b\
5d1eb4671378caab107c56cb19e4656c5dbb829a712aea8922d1086ffea567dadcf8b42a7d850c\
b3fab1ae7bbd095a6b55c89e1477cbd3780d99474ec70151f0043240a62f730e498310e64b892a\
07c6716b9cbead0e826e8c545aa0d358d1588fd65d83059f237b9bd732a5a83507c9ce89dc9a98\
cbf9517a76cfc4c588d9d98c0520ba0a0b936e9f35821c31bb23

    X = 30f59255791b2f1d8a28e612f9f838201abb68d2a1256830041e0e139088f585
    Y = 0ed9564e1d901e13dfb367c71859af2ec4cc2ed1e0007e9d6262ae1c84562f81ddbfa8\
0ba8dad6d7dc70d38579929ac69d0fbe04143750f91741ccd690ddc3c743cae9589bd32147a677\
722ba1289a567ea724e20c5ec1e1621582932eada130b8a579d2ff3590bc70fe09721b0067965e\
f2b16fbc7d4739dc780592e5868c8ccd298082ada393654e26e7748177fb55e84509427dd14dc3\
f92e1c6a3e83eb705bf1537d08a0129f01e2c92234264efce0ec2164103999472631de238ddca8\
4d25a6436caf75563085ba5843e2271bb9b12ee1cfa2dce94d681cda686d281c7ec10b6c4e44af\
f0bf54452416d76267e09eb2a73264433ee9dc72fdf4417c6f7d

    X = 4d921f8c9e8ceeb7e5244b843a9a238af96818d760bd872ea3e7d3a37d7e97b5
    Y = 8b3907eccaaa1ff67705789dbf7e914af940353cda7d0da1d2564a030a5afd7a70d408\
14b32b0092fe1a92ebf91f2a2c10e9fab9521d855fd8c18199018d5810c7ae7633829f85c739f2\
43d51c3567449e8f500dd5aec8ff8e1bb3587bdcea9635e4e4b0215ab00d9ea6edd3c48579f257\
f63a95b85271925334bf73900c4e0e4f644379afc9f765354051a57bf37c939d2055d78919ab1b\
1e9348d585bc73836cfea8310209940cded440fa131e873243029339f57d3a2c4f57ebee294a42\
a06f339dd9e635308755575801b418c5f83e23974b5b4c2f703a628b3fd83b398b5f271616492d\
f14efb7436ed630b4e39d40ab504935bbdbf9b82f25bbd09014e

    X = 1b46dd4a0b6c3693a1f1e685dd529d6f99dec061d631c7c797ed9908f14b39aa
    Y = 27e21468657d4f6216e806b716ab87fd324a22d0df4d5e1c26bfc12676fc5db5cd1345\
d3e078428e5fcc7e03c6a6fb6c4e181bb561cdbdfe565f38ec384be183fc5a0930eb3a92cda25f\
2867b05a7bd7d4d1a7739be9a75569eac9e98e4115ba415db505ef93c0e2b1e58789acd474e414\
3dfe584ce1f1df6da01f5d3f9a27bba10cdf78737e7aa818daf753eae647477ef20283f5f62b0d\
9b53f073281131ef3c692407724c5f61abbabcb24ab056236a7062004b2739c803f663d9999934\
66b5fca3452d954b0edbbf7fefda6d40df8df7ed21f83885e44ebc511a70cb03d525bbe21dce5f\
fb28516441aea2f804301a6c2527265a3df0c411d48cd370fff4

    X = 47eea9c0e8b43329262f3a0b617cd04db1cf159af2aba0ea06c2ee5b8a6c2d69
    Y = 65dad9740de9422632c4401df77b68a37fbe3db48aceadab7d9002770b38dc8297886c\
dde82fab71650944a692cf714f82841f4f5668ecbeb677744e398a558c5f72d087d26ee29b6324\
c8def060ed5c5fe4f10b215f4b04dde218fe023ae8fcb99be89ad9a1bb737ae73ae7180944de3f\
d6abc0d66b6832213a5db47469e6127394bc1fd5142e46438fa48f9774038a3ea312bf539c700f\
7a486964abdde996cc0b7d84fec7ef4da121db184d2410d44e9ad9b1b95c3d71edf4a4ba1f29e9\
b8733097fa0c7e8a43141fd0a560f1675323c6ca4504ddb1ed1c2e5887c68f4eecf426f64ce222\
2bb7a83e771dc27464fef02da9c7c78b2cc36a8aa34b2ab5555a

    X = 7e15dc5a1fbfa404a40be5f94334d22d50c29550008d29daf16ec682fa29e10a
    Y = be5e833678b92b78dcbf83b9137329bd9a4fcf3094baf2bb3fd4518e663911cff2d799\
5ad5903e0b3d6a71e0cf01426ae03332331867857ef8935a78f75a269268e108b1b03e5346eddd\
f4af610ba2aaeb55e5132dccf989aaf5ea069574147c9925297847410ce9fbba9cc65e73e011f2\
49f449dffc304a170f2e2a218197e91128ead770f03e7e8966887c870e6c405129e08f5c49b1cd\
ef48be2c62007c629c35330e2a27f73acf334295dd7832cbe495b61204694b1eab831a05f40b7a\
84c3cc726aa6fa408d2d91cb3e02dd7487d4fe1e50b0f7b4d6e468bb086e695fded8f9e8231bb9\
a40b0ff33b61f7143e7df513e7219c2b9102c8ac4321b4036ffb

    X = 8c77eb7870a4108f70251698f0a272a45a87346c8ef14d01e6e5effd914e65eb
    Y = 7e3451f243886f90c62cff555ef70fb1b28e3040336d03e2924f8c093e9afddadc8a2e\
769eb98b5187feb9e029bba4fe3c1fcd0e891abca0792ab9cea27250be580f68baa5e92d05e405\
f8ceeec89b66020a4b08c5b0b4ffe123cf75da89f06a54e90c1f1a747f51e5208d7d718d8bf3f6\
173442914bcfcd8f68568d7933471f438fe33efffb867b75a8bae0000795643d4170d49f56579f\
4d5082d50bd0b21837fa4066821c3b4bf9e88a7e3064d76623e07174a3459cef41afa192b3fd4d\
bc84b04e48facb96a66dd39864f8c90838890bdaac64211b0cc800a2a4523540fce1c90d48d44f\
2160ba2cac83988b09faf27e371298d2feeb677e71ce37e35389

    X = 12d4b73532b0a480f88fb82eb3cf89729539ba3b5bfb463c792dc223d1a526dd
    Y = 1371ad94dc2db02476ac925aa0cbdd7e247f86a08a6f2492cd4b3f7b05aa881b2e83d0\
c5d82246c17cae230a41dd04f05a8c3fed1e09cf8e0d8dc98a9887ff772e2f60434ebea076344f\
4fbffcbbbd8dee4bc10e7626f26a92c3bf0ac08117bd539b477077d45e11fbe47818f3ce03d6da\
f34c77595e72d1c8376d9772f51ce956f0e30e98f51155e9effb974f3d46fb48c76a004b0117db\
c19d78044f248821f88fa87d55ba124842d159b5ac4ce916487ecf9d03321241a2bf1896747f15\
5f281434435741b1f26a79d35270167ba3b505a6cec672339823c8fc6dc797d458d639e5ed015a\
c710ebd31b86d736e9b2ab340e7f38f58788483484b81eb0b1ec
    """).splitlines()

    expected_vectors = [
        {'g': '06b7861abbd35cc89e79c52f68d20875389b127361ca66\
822138ce4991d2b862259d6b4548a6495b195aa0e0b6137ca37eb23b94074d3c3\
d300042bdf15762812b6333ef7b07ceba78607610fcc9ee68491dbc1e34cd1261\
5474e52b18bc934fb00c61d39e7da8902291c4434a4e2224c3f4fd9f93cd6f4f1\
7fc076341a7e7d9',
         'p': 'd38311e2cd388c3ed698e82fdf88eb92b5a9a483dc8800\
5d4b725ef341eabb47cf8a7a8a41e792a156b7ce97206c4f9c5ce6fc5ae791210\
2b6b502e59050b5b21ce263dddb2044b652236f4d42ab4b5d6aa73189cef1ace7\
78d7845a5c1c1c7147123188f8dc551054ee162b634d60f097f719076640e2098\
0a0093113a8bd73',
         'q': '96c5390a8b612c0e422bb2b0ea194a3ec935a281',
         'x': '8185fee9cc7c0e91fd85503274f1cd5a3fd15a49',
         'y': '6f26d98d41de7d871b6381851c9d91fa03942092ab6097\
e76422070edb71db44ff568280fdb1709f8fc3feab39f1f824adaeb2a29808815\
6ac31af1aa04bf54f475bdcfdcf2f8a2dd973e922d83e76f016558617603129b2\
1c70bf7d0e5dc9e68fe332e295b65876eb9a12fe6fca9f1a1ce80204646bf99b5\
771d249a6fea627'},
        {'g': '06b7861abbd35cc89e79c52f68d20875389b127361ca66822138\
    ce4991d2b862259d6b4548a6495b195aa0e0b6137ca37eb23b94074d3c3d30004\
    2bdf15762812b6333ef7b07ceba78607610fcc9ee68491dbc1e34cd12615474e5\
    2b18bc934fb00c61d39e7da8902291c4434a4e2224c3f4fd9f93cd6f4f17fc076\
    341a7e7d9',
         'p': 'd38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d4b72\
    5ef341eabb47cf8a7a8a41e792a156b7ce97206c4f9c5ce6fc5ae7912102b6b50\
    2e59050b5b21ce263dddb2044b652236f4d42ab4b5d6aa73189cef1ace778d784\
    5a5c1c1c7147123188f8dc551054ee162b634d60f097f719076640e20980a0093\
    113a8bd73',
         'q': '96c5390a8b612c0e422bb2b0ea194a3ec935a281',
         'x': '85322d6ea73083064376099ca2f65f56e8522d9b',
         'y': '21f8690f717c9f4dcb8f4b6971de2f15b9231fcf41b7eeb997d7\
    81f240bfdddfd2090d22083c26cca39bf37c9caf1ec89518ea64845a50d747b49\
    131ffff6a2fd11ea7bacbb93c7d05137383a06365af82225dd3713ca5a4500631\
    6f53bd12b0e260d5f79795e5a4c9f353f12867a1d3202394673ada8563b71555e\
    53f415254'},
        {'g': '06b7861abbd35cc89e79c52f68d20875389b127361ca66822138\
   ce4991d2b862259d6b4548a6495b195aa0e0b6137ca37eb23b94074d3c3d30004\
   2bdf15762812b6333ef7b07ceba78607610fcc9ee68491dbc1e34cd12615474e5\
   2b18bc934fb00c61d39e7da8902291c4434a4e2224c3f4fd9f93cd6f4f17fc076\
   341a7e7d9',
         'p': 'd38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d4b72\
   5ef341eabb47cf8a7a8a41e792a156b7ce97206c4f9c5ce6fc5ae7912102b6b50\
   2e59050b5b21ce263dddb2044b652236f4d42ab4b5d6aa73189cef1ace778d784\
   5a5c1c1c7147123188f8dc551054ee162b634d60f097f719076640e20980a0093\
   113a8bd73',
         'q': '96c5390a8b612c0e422bb2b0ea194a3ec935a281',
         'x': '8007aace9226517add3b31fb72fe57cf0b71de87',
         'y': '0869599e9c233f98719353f50431b8cf9219443b245ccca95fcf\
   81d757288b27b4ee08037f0a8ee5d997eecf7ddf1cae641fa0b24bb0e0fb97765\
   166d92a79b1519cb9549431947ff58ede390c8fe2c44ff1fe9f8b15839d93cfd7\
   27dd0c2698ccf04f85f491d59a4e7fbf873122228af5c27095eea09d7d13b0d58\
   5c79c4849'},
        {'g': '06b7861abbd35cc89e79c52f68d20875389b127361ca66822138\
   ce4991d2b862259d6b4548a6495b195aa0e0b6137ca37eb23b94074d3c3d30004\
   2bdf15762812b6333ef7b07ceba78607610fcc9ee68491dbc1e34cd12615474e5\
   2b18bc934fb00c61d39e7da8902291c4434a4e2224c3f4fd9f93cd6f4f17fc076\
   341a7e7d9',
         'p': 'd38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d4b72\
   5ef341eabb47cf8a7a8a41e792a156b7ce97206c4f9c5ce6fc5ae7912102b6b50\
   2e59050b5b21ce263dddb2044b652236f4d42ab4b5d6aa73189cef1ace778d784\
   5a5c1c1c7147123188f8dc551054ee162b634d60f097f719076640e20980a0093\
   113a8bd73',
         'q': '96c5390a8b612c0e422bb2b0ea194a3ec935a281',
         'x': '2f08cf0627c8ffbde07420c324e594170da5879e',
         'y': '1f9098ddb4ec6f7a14841ae87792450292f210fb5a7a90811773\
   1b3c5f3d1694331a85a129b0b6b5363e61544c351799ef1fd9fdae6f7707b1ef5\
   5933192b03cc41a773d1e2c119fe59205ce8f8c47f27ef0620c6892c61bb04907\
   e00e6b82c81e1b77bb4e3f87562327555a226217aaaa4e1d29bac7cc8cbebceee\
   3895d8917'},
        {'g': '06b7861abbd35cc89e79c52f68d20875389b127361ca66822138\
   ce4991d2b862259d6b4548a6495b195aa0e0b6137ca37eb23b94074d3c3d30004\
   2bdf15762812b6333ef7b07ceba78607610fcc9ee68491dbc1e34cd12615474e5\
   2b18bc934fb00c61d39e7da8902291c4434a4e2224c3f4fd9f93cd6f4f17fc076\
   341a7e7d9',
         'p': 'd38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d4b72\
   5ef341eabb47cf8a7a8a41e792a156b7ce97206c4f9c5ce6fc5ae7912102b6b50\
   2e59050b5b21ce263dddb2044b652236f4d42ab4b5d6aa73189cef1ace778d784\
   5a5c1c1c7147123188f8dc551054ee162b634d60f097f719076640e20980a0093\
   113a8bd73',
         'q': '96c5390a8b612c0e422bb2b0ea194a3ec935a281',
         'x': '423616c18872f9a3ae1db1f70302ae8decff0be9',
         'y': 'b62df8a3635c8f5acdc92d710d920a643eb93010d003e6e61eee\
   57d6a80ca5512bc1a0b689dd256a2ff1dcac4adb099ef66317de9c6b5188627c1\
   f0aec54049d0bf1c8214c492d09ce8243af9508c49493ea8d6f85d141850ebdab\
   f6cbfeced92c1cc0b844227eedfc03e8650f89c2b6d11462d8cc5b78254574bbe\
   558f2e724'},
        {'g': '06b7861abbd35cc89e79c52f68d20875389b127361ca66822138\
   ce4991d2b862259d6b4548a6495b195aa0e0b6137ca37eb23b94074d3c3d30004\
   2bdf15762812b6333ef7b07ceba78607610fcc9ee68491dbc1e34cd12615474e5\
   2b18bc934fb00c61d39e7da8902291c4434a4e2224c3f4fd9f93cd6f4f17fc076\
   341a7e7d9',
         'p': 'd38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d4b72\
   5ef341eabb47cf8a7a8a41e792a156b7ce97206c4f9c5ce6fc5ae7912102b6b50\
   2e59050b5b21ce263dddb2044b652236f4d42ab4b5d6aa73189cef1ace778d784\
   5a5c1c1c7147123188f8dc551054ee162b634d60f097f719076640e20980a0093\
   113a8bd73',
         'q': '96c5390a8b612c0e422bb2b0ea194a3ec935a281',
         'x': '4c4489ee5a17f30eec191644ae28105aafb82307',
         'y': '37fe0fdb5adec7bd56cdd68b1fc5669c292ae0c0c7c339aab844\
   b7b83bc0118056274a1f2b2bd4d4c8973458e86bddff94a6adb9b28d9a1f3ff0b\
   c82972e3c8e452756ab7f921750f773d75c58346096ce2b804c57f2dee4154710\
   13d9a31d347960c42e5748d0feda02bdf0b22902103de1591d9b5dcdfb18575d8\
   c164031d1'},
        {'g': '06b7861abbd35cc89e79c52f68d20875389b127361ca66822138\
   ce4991d2b862259d6b4548a6495b195aa0e0b6137ca37eb23b94074d3c3d30004\
   2bdf15762812b6333ef7b07ceba78607610fcc9ee68491dbc1e34cd12615474e5\
   2b18bc934fb00c61d39e7da8902291c4434a4e2224c3f4fd9f93cd6f4f17fc076\
   341a7e7d9',
         'p': 'd38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d4b72\
   5ef341eabb47cf8a7a8a41e792a156b7ce97206c4f9c5ce6fc5ae7912102b6b50\
   2e59050b5b21ce263dddb2044b652236f4d42ab4b5d6aa73189cef1ace778d784\
   5a5c1c1c7147123188f8dc551054ee162b634d60f097f719076640e20980a0093\
   113a8bd73',
         'q': '96c5390a8b612c0e422bb2b0ea194a3ec935a281',
         'x': '4ea539bf524cacbbf850ea20e18659db13c14cc1',
         'y': '7d4b1d55c3cba4f1d7073afda9faed928d7653eac594ef2c84a7\
   c83a77817e186a4706b4dae53f67fe7fc97e5915babda7398aec5a8afa302de1a\
   f67e709d6cc5cab6d19af835027346875758cedb5552494a85e8b2292f69cd2d6\
   65fc3375180f30110f5f9f03472ce431a64db795bce07b0d42bb0d22dc94182dd\
   43c2dabe3'},
        {'g': '06b7861abbd35cc89e79c52f68d20875389b127361ca66822138\
   ce4991d2b862259d6b4548a6495b195aa0e0b6137ca37eb23b94074d3c3d30004\
   2bdf15762812b6333ef7b07ceba78607610fcc9ee68491dbc1e34cd12615474e5\
   2b18bc934fb00c61d39e7da8902291c4434a4e2224c3f4fd9f93cd6f4f17fc076\
   341a7e7d9',
         'p': 'd38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d4b72\
   5ef341eabb47cf8a7a8a41e792a156b7ce97206c4f9c5ce6fc5ae7912102b6b50\
   2e59050b5b21ce263dddb2044b652236f4d42ab4b5d6aa73189cef1ace778d784\
   5a5c1c1c7147123188f8dc551054ee162b634d60f097f719076640e20980a0093\
   113a8bd73',
         'q': '96c5390a8b612c0e422bb2b0ea194a3ec935a281',
         'x': '272b5be463d69c564fb82e54b8824fd5622fd819',
         'y': 'd133f99a7d8c5168f58a1f8be91e40d98446336533517289d40f\
   0f6c974bbc3abd32de81b92ab4c0d164b44271a884992d93104cca9e85acdec20\
   717492e7cddd24f99146e59c16877cf4a2f4fca669528b0e4a42b2154c09b4a15\
   ac74d1aed9ca141b7fd6b8eeb5f315a88dfade013539f3ca61628411e89f0e655\
   3ed18c03e'},
        {'g': '06b7861abbd35cc89e79c52f68d20875389b127361ca66822138\
   ce4991d2b862259d6b4548a6495b195aa0e0b6137ca37eb23b94074d3c3d30004\
   2bdf15762812b6333ef7b07ceba78607610fcc9ee68491dbc1e34cd12615474e5\
   2b18bc934fb00c61d39e7da8902291c4434a4e2224c3f4fd9f93cd6f4f17fc076\
   341a7e7d9',
         'p': 'd38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d4b72\
   5ef341eabb47cf8a7a8a41e792a156b7ce97206c4f9c5ce6fc5ae7912102b6b50\
   2e59050b5b21ce263dddb2044b652236f4d42ab4b5d6aa73189cef1ace778d784\
   5a5c1c1c7147123188f8dc551054ee162b634d60f097f719076640e20980a0093\
   113a8bd73',
         'q': '96c5390a8b612c0e422bb2b0ea194a3ec935a281',
         'x': '49df2e11a4cab60b3d8f53a02bc8d982a52035e6',
         'y': '555b359dd7998b8020f04f84f7e4ee3e7d7d2352d95b6d5bc51b\
   96a2132bc1ac779652ccfbfb5b102edb3861aa98d4feba59f65bd0501755c5d0d\
   894b031841365f2f4e9749b5850542dbe82a3b5d614d93f34692087507d2972ac\
   dab700892bb847cb4e881998342b7230aef923a07b07563efbc053a300c0ea284\
   d7f381da2'},
        {'g': '06b7861abbd35cc89e79c52f68d20875389b127361ca66822138\
   ce4991d2b862259d6b4548a6495b195aa0e0b6137ca37eb23b94074d3c3d30004\
   2bdf15762812b6333ef7b07ceba78607610fcc9ee68491dbc1e34cd12615474e5\
   2b18bc934fb00c61d39e7da8902291c4434a4e2224c3f4fd9f93cd6f4f17fc076\
   341a7e7d9',
         'p': 'd38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d4b72\
   5ef341eabb47cf8a7a8a41e792a156b7ce97206c4f9c5ce6fc5ae7912102b6b50\
   2e59050b5b21ce263dddb2044b652236f4d42ab4b5d6aa73189cef1ace778d784\
   5a5c1c1c7147123188f8dc551054ee162b634d60f097f719076640e20980a0093\
   113a8bd73',
         'q': '96c5390a8b612c0e422bb2b0ea194a3ec935a281',
         'x': '06f5fe27b77fbdb24beb34f4fe13203e46ad8460',
         'y': '881344b829c31389b4882c2fde977d73adb72e5001f41b57c772\
   6b9ac99ef413d0fb5df9ed587994c45580efa11d4445cea85b149e74f746308ee\
   223c82263b14f4a2ec5ae971083dca725c5fb0ae233b67a4be60be8aca3f40c5b\
   faf9d9c4dc40d49dec1c4e539c88cddfce40106cb6f88fd094037fae75de54317\
   ad4842cc1'},
        {'g': 'e4c4eca88415b23ecf811c96e48cd24200fe916631a68a684e6c\
   cb6b1913413d344d1d8d84a333839d88eee431521f6e357c16e6a93be111a9807\
   6739cd401bab3b9d565bf4fb99e9d185b1e14d61c93700133f908bae03e28764d\
   107dcd2ea7674217622074bb19efff482f5f5c1a86d5551b2fc68d1c6e9d80119\
   58ef4b9c2a3a55d0d3c882e6ad7f9f0f3c61568f78d0706b10a26f23b4f197c32\
   2b825002284a0aca91807bba98ece912b80e10cdf180cf99a35f210c1655fbfdd\
   74f13b1b5046591f8403873d12239834dd6c4eceb42bf7482e1794a1601357b62\
   9ddfa971f2ed273b146ec1ca06d0adf55dd91d65c37297bda78c6d210c0bc26e5\
   58302',
         'p': 'ea1fb1af22881558ef93be8a5f8653c5a559434c49c8c2c12ace\
   5e9c41434c9cf0a8e9498acb0f4663c08b4484eace845f6fb17dac62c98e706af\
   0fc74e4da1c6c2b3fbf5a1d58ff82fc1a66f3e8b12252c40278fff9dd7f102eed\
   2cb5b7323ebf1908c234d935414dded7f8d244e54561b0dca39b301de8c49da9f\
   b23df33c6182e3f983208c560fb5119fbf78ebe3e6564ee235c6a15cbb9ac247b\
   aba5a423bc6582a1a9d8a2b4f0e9e3d9dbac122f750dd754325135257488b1f6e\
   cabf21bff2947fe0d3b2cb7ffe67f4e7fcdf1214f6053e72a5bb0dd20a0e9fe6d\
   b2df0a908c36e95e60bf49ca4368b8b892b9c79f61ef91c47567c40e1f80ac5aa\
   66ef7',
         'q': '8ec73f3761caf5fdfe6e4e82098bf10f898740dcb808204bf6b1\
   8f507192c19d',
         'x': '405772da6e90d809e77d5de796562a2dd4dfd10ef00a83a3aba6\
   bd818a0348a1',
         'y': '6b32e31ab9031dc4dd0b5039a78d07826687ab087ae6de4736f5\
   b0434e1253092e8a0b231f9c87f3fc8a4cb5634eb194bf1b638b7a7889620ce67\
   11567e36aa36cda4604cfaa601a45918371d4ccf68d8b10a50a0460eb1dc0fff6\
   2ef5e6ee4d473e18ea4a66c196fb7e677a49b48241a0b4a97128eff30fa437050\
   501a584f8771e7280d26d5af30784039159c11ebfea10b692fd0a58215eeb18bf\
   f117e13f08db792ed4151a218e4bed8dddfb0793225bd1e9773505166f4bd8ced\
   bb286ea28232972da7bae836ba97329ba6b0a36508e50a52a7675e476d4d4137e\
   ae13f22a9d2fefde708ba8f34bf336c6e76331761e4b0617633fe7ec3f23672fb\
   19d27'},
        {'g': 'e4c4eca88415b23ecf811c96e48cd24200fe916631a68a684e6c\
   cb6b1913413d344d1d8d84a333839d88eee431521f6e357c16e6a93be111a9807\
   6739cd401bab3b9d565bf4fb99e9d185b1e14d61c93700133f908bae03e28764d\
   107dcd2ea7674217622074bb19efff482f5f5c1a86d5551b2fc68d1c6e9d80119\
   58ef4b9c2a3a55d0d3c882e6ad7f9f0f3c61568f78d0706b10a26f23b4f197c32\
   2b825002284a0aca91807bba98ece912b80e10cdf180cf99a35f210c1655fbfdd\
   74f13b1b5046591f8403873d12239834dd6c4eceb42bf7482e1794a1601357b62\
   9ddfa971f2ed273b146ec1ca06d0adf55dd91d65c37297bda78c6d210c0bc26e5\
   58302',
         'p': 'ea1fb1af22881558ef93be8a5f8653c5a559434c49c8c2c12ace\
   5e9c41434c9cf0a8e9498acb0f4663c08b4484eace845f6fb17dac62c98e706af\
   0fc74e4da1c6c2b3fbf5a1d58ff82fc1a66f3e8b12252c40278fff9dd7f102eed\
   2cb5b7323ebf1908c234d935414dded7f8d244e54561b0dca39b301de8c49da9f\
   b23df33c6182e3f983208c560fb5119fbf78ebe3e6564ee235c6a15cbb9ac247b\
   aba5a423bc6582a1a9d8a2b4f0e9e3d9dbac122f750dd754325135257488b1f6e\
   cabf21bff2947fe0d3b2cb7ffe67f4e7fcdf1214f6053e72a5bb0dd20a0e9fe6d\
   b2df0a908c36e95e60bf49ca4368b8b892b9c79f61ef91c47567c40e1f80ac5aa\
   66ef7',
         'q': '8ec73f3761caf5fdfe6e4e82098bf10f898740dcb808204bf6b1\
   8f507192c19d',
         'x': '0e0b95e31fda3f888059c46c3002ef8f2d6be112d0209aeb9e95\
   45da67aeea80',
         'y': '778082b77ddba6f56597cc74c3a612abf2ddbd85cc81430c99ab\
   843c1f630b9db0139965f563978164f9bf3a8397256be714625cd41cd7fa0067d\
   94ea66d7e073f7125af692ad01371d4a17f4550590378f2b074030c20e3691159\
   8a1018772f61be3b24de4be5a388ccc09e15a92819c31dec50de9fde105b49eaa\
   097b9d13d9219eeb33b628facfd1c78a7159c8430d0647c506e7e3de74763cb35\
   1eada72c00bef3c9641881e6254870c1e6599f8ca2f1bbb74f39a905e3a34e454\
   4168e6e50c9e3305fd09cab6ed4aff6fda6e0d5bf375c81ac9054406d9193b003\
   c89272f1bd83d48250134b65c77c2b6332d38d34d9016f0e8975536ad6c348a1f\
   aedb0'},
        {'g': 'e4c4eca88415b23ecf811c96e48cd24200fe916631a68a684e6c\
   cb6b1913413d344d1d8d84a333839d88eee431521f6e357c16e6a93be111a9807\
   6739cd401bab3b9d565bf4fb99e9d185b1e14d61c93700133f908bae03e28764d\
   107dcd2ea7674217622074bb19efff482f5f5c1a86d5551b2fc68d1c6e9d80119\
   58ef4b9c2a3a55d0d3c882e6ad7f9f0f3c61568f78d0706b10a26f23b4f197c32\
   2b825002284a0aca91807bba98ece912b80e10cdf180cf99a35f210c1655fbfdd\
   74f13b1b5046591f8403873d12239834dd6c4eceb42bf7482e1794a1601357b62\
   9ddfa971f2ed273b146ec1ca06d0adf55dd91d65c37297bda78c6d210c0bc26e5\
   58302',
         'p': 'ea1fb1af22881558ef93be8a5f8653c5a559434c49c8c2c12ace\
   5e9c41434c9cf0a8e9498acb0f4663c08b4484eace845f6fb17dac62c98e706af\
   0fc74e4da1c6c2b3fbf5a1d58ff82fc1a66f3e8b12252c40278fff9dd7f102eed\
   2cb5b7323ebf1908c234d935414dded7f8d244e54561b0dca39b301de8c49da9f\
   b23df33c6182e3f983208c560fb5119fbf78ebe3e6564ee235c6a15cbb9ac247b\
   aba5a423bc6582a1a9d8a2b4f0e9e3d9dbac122f750dd754325135257488b1f6e\
   cabf21bff2947fe0d3b2cb7ffe67f4e7fcdf1214f6053e72a5bb0dd20a0e9fe6d\
   b2df0a908c36e95e60bf49ca4368b8b892b9c79f61ef91c47567c40e1f80ac5aa\
   66ef7',
         'q': '8ec73f3761caf5fdfe6e4e82098bf10f898740dcb808204bf6b1\
   8f507192c19d',
         'x': '835fd2d1b7b03d90c5ebc073ee69b386c9c07ca06bce80bc5746\
   34af8d534f7a',
         'y': 'cbc3feccf1ef62d31df626a4b2e234afdf1795443e46a471ec8b\
   902b0ae9af36344120ed3ca6009751b03e8963a6151e7b2fe572837c3e23815d4\
   72ce75cfbaaaaf36e89a939983bd494f0421b0f35079e5a243672d708ca349253\
   9733b2a847f638167f7d64c8dd7e3cc8b2f0e7a7fb4b5d1eb4671378caab107c5\
   6cb19e4656c5dbb829a712aea8922d1086ffea567dadcf8b42a7d850cb3fab1ae\
   7bbd095a6b55c89e1477cbd3780d99474ec70151f0043240a62f730e498310e64\
   b892a07c6716b9cbead0e826e8c545aa0d358d1588fd65d83059f237b9bd732a5\
   a83507c9ce89dc9a98cbf9517a76cfc4c588d9d98c0520ba0a0b936e9f35821c3\
   1bb23'},
        {'g': 'e4c4eca88415b23ecf811c96e48cd24200fe916631a68a684e6c\
   cb6b1913413d344d1d8d84a333839d88eee431521f6e357c16e6a93be111a9807\
   6739cd401bab3b9d565bf4fb99e9d185b1e14d61c93700133f908bae03e28764d\
   107dcd2ea7674217622074bb19efff482f5f5c1a86d5551b2fc68d1c6e9d80119\
   58ef4b9c2a3a55d0d3c882e6ad7f9f0f3c61568f78d0706b10a26f23b4f197c32\
   2b825002284a0aca91807bba98ece912b80e10cdf180cf99a35f210c1655fbfdd\
   74f13b1b5046591f8403873d12239834dd6c4eceb42bf7482e1794a1601357b62\
   9ddfa971f2ed273b146ec1ca06d0adf55dd91d65c37297bda78c6d210c0bc26e5\
   58302',
         'p': 'ea1fb1af22881558ef93be8a5f8653c5a559434c49c8c2c12ace\
   5e9c41434c9cf0a8e9498acb0f4663c08b4484eace845f6fb17dac62c98e706af\
   0fc74e4da1c6c2b3fbf5a1d58ff82fc1a66f3e8b12252c40278fff9dd7f102eed\
   2cb5b7323ebf1908c234d935414dded7f8d244e54561b0dca39b301de8c49da9f\
   b23df33c6182e3f983208c560fb5119fbf78ebe3e6564ee235c6a15cbb9ac247b\
   aba5a423bc6582a1a9d8a2b4f0e9e3d9dbac122f750dd754325135257488b1f6e\
   cabf21bff2947fe0d3b2cb7ffe67f4e7fcdf1214f6053e72a5bb0dd20a0e9fe6d\
   b2df0a908c36e95e60bf49ca4368b8b892b9c79f61ef91c47567c40e1f80ac5aa\
   66ef7',
         'q': '8ec73f3761caf5fdfe6e4e82098bf10f898740dcb808204bf6b1\
   8f507192c19d',
         'x': '30f59255791b2f1d8a28e612f9f838201abb68d2a1256830041e\
   0e139088f585',
         'y': '0ed9564e1d901e13dfb367c71859af2ec4cc2ed1e0007e9d6262\
   ae1c84562f81ddbfa80ba8dad6d7dc70d38579929ac69d0fbe04143750f91741c\
   cd690ddc3c743cae9589bd32147a677722ba1289a567ea724e20c5ec1e1621582\
   932eada130b8a579d2ff3590bc70fe09721b0067965ef2b16fbc7d4739dc78059\
   2e5868c8ccd298082ada393654e26e7748177fb55e84509427dd14dc3f92e1c6a\
   3e83eb705bf1537d08a0129f01e2c92234264efce0ec2164103999472631de238\
   ddca84d25a6436caf75563085ba5843e2271bb9b12ee1cfa2dce94d681cda686d\
   281c7ec10b6c4e44aff0bf54452416d76267e09eb2a73264433ee9dc72fdf4417\
   c6f7d'},
        {'g': 'e4c4eca88415b23ecf811c96e48cd24200fe916631a68a684e6c\
   cb6b1913413d344d1d8d84a333839d88eee431521f6e357c16e6a93be111a9807\
   6739cd401bab3b9d565bf4fb99e9d185b1e14d61c93700133f908bae03e28764d\
   107dcd2ea7674217622074bb19efff482f5f5c1a86d5551b2fc68d1c6e9d80119\
   58ef4b9c2a3a55d0d3c882e6ad7f9f0f3c61568f78d0706b10a26f23b4f197c32\
   2b825002284a0aca91807bba98ece912b80e10cdf180cf99a35f210c1655fbfdd\
   74f13b1b5046591f8403873d12239834dd6c4eceb42bf7482e1794a1601357b62\
   9ddfa971f2ed273b146ec1ca06d0adf55dd91d65c37297bda78c6d210c0bc26e5\
   58302',
         'p': 'ea1fb1af22881558ef93be8a5f8653c5a559434c49c8c2c12ace\
   5e9c41434c9cf0a8e9498acb0f4663c08b4484eace845f6fb17dac62c98e706af\
   0fc74e4da1c6c2b3fbf5a1d58ff82fc1a66f3e8b12252c40278fff9dd7f102eed\
   2cb5b7323ebf1908c234d935414dded7f8d244e54561b0dca39b301de8c49da9f\
   b23df33c6182e3f983208c560fb5119fbf78ebe3e6564ee235c6a15cbb9ac247b\
   aba5a423bc6582a1a9d8a2b4f0e9e3d9dbac122f750dd754325135257488b1f6e\
   cabf21bff2947fe0d3b2cb7ffe67f4e7fcdf1214f6053e72a5bb0dd20a0e9fe6d\
   b2df0a908c36e95e60bf49ca4368b8b892b9c79f61ef91c47567c40e1f80ac5aa\
   66ef7',
         'q': '8ec73f3761caf5fdfe6e4e82098bf10f898740dcb808204bf6b1\
   8f507192c19d',
         'x': '4d921f8c9e8ceeb7e5244b843a9a238af96818d760bd872ea3e7\
   d3a37d7e97b5',
         'y': '8b3907eccaaa1ff67705789dbf7e914af940353cda7d0da1d256\
   4a030a5afd7a70d40814b32b0092fe1a92ebf91f2a2c10e9fab9521d855fd8c18\
   199018d5810c7ae7633829f85c739f243d51c3567449e8f500dd5aec8ff8e1bb3\
   587bdcea9635e4e4b0215ab00d9ea6edd3c48579f257f63a95b85271925334bf7\
   3900c4e0e4f644379afc9f765354051a57bf37c939d2055d78919ab1b1e9348d5\
   85bc73836cfea8310209940cded440fa131e873243029339f57d3a2c4f57ebee2\
   94a42a06f339dd9e635308755575801b418c5f83e23974b5b4c2f703a628b3fd8\
   3b398b5f271616492df14efb7436ed630b4e39d40ab504935bbdbf9b82f25bbd0\
   9014e'},
        {'g': 'e4c4eca88415b23ecf811c96e48cd24200fe916631a68a684e6c\
   cb6b1913413d344d1d8d84a333839d88eee431521f6e357c16e6a93be111a9807\
   6739cd401bab3b9d565bf4fb99e9d185b1e14d61c93700133f908bae03e28764d\
   107dcd2ea7674217622074bb19efff482f5f5c1a86d5551b2fc68d1c6e9d80119\
   58ef4b9c2a3a55d0d3c882e6ad7f9f0f3c61568f78d0706b10a26f23b4f197c32\
   2b825002284a0aca91807bba98ece912b80e10cdf180cf99a35f210c1655fbfdd\
   74f13b1b5046591f8403873d12239834dd6c4eceb42bf7482e1794a1601357b62\
   9ddfa971f2ed273b146ec1ca06d0adf55dd91d65c37297bda78c6d210c0bc26e5\
   58302',
         'p': 'ea1fb1af22881558ef93be8a5f8653c5a559434c49c8c2c12ace\
   5e9c41434c9cf0a8e9498acb0f4663c08b4484eace845f6fb17dac62c98e706af\
   0fc74e4da1c6c2b3fbf5a1d58ff82fc1a66f3e8b12252c40278fff9dd7f102eed\
   2cb5b7323ebf1908c234d935414dded7f8d244e54561b0dca39b301de8c49da9f\
   b23df33c6182e3f983208c560fb5119fbf78ebe3e6564ee235c6a15cbb9ac247b\
   aba5a423bc6582a1a9d8a2b4f0e9e3d9dbac122f750dd754325135257488b1f6e\
   cabf21bff2947fe0d3b2cb7ffe67f4e7fcdf1214f6053e72a5bb0dd20a0e9fe6d\
   b2df0a908c36e95e60bf49ca4368b8b892b9c79f61ef91c47567c40e1f80ac5aa\
   66ef7',
         'q': '8ec73f3761caf5fdfe6e4e82098bf10f898740dcb808204bf6b1\
   8f507192c19d',
         'x': '1b46dd4a0b6c3693a1f1e685dd529d6f99dec061d631c7c797ed\
   9908f14b39aa',
         'y': '27e21468657d4f6216e806b716ab87fd324a22d0df4d5e1c26bf\
   c12676fc5db5cd1345d3e078428e5fcc7e03c6a6fb6c4e181bb561cdbdfe565f3\
   8ec384be183fc5a0930eb3a92cda25f2867b05a7bd7d4d1a7739be9a75569eac9\
   e98e4115ba415db505ef93c0e2b1e58789acd474e4143dfe584ce1f1df6da01f5\
   d3f9a27bba10cdf78737e7aa818daf753eae647477ef20283f5f62b0d9b53f073\
   281131ef3c692407724c5f61abbabcb24ab056236a7062004b2739c803f663d99\
   9993466b5fca3452d954b0edbbf7fefda6d40df8df7ed21f83885e44ebc511a70\
   cb03d525bbe21dce5ffb28516441aea2f804301a6c2527265a3df0c411d48cd37\
   0fff4'},
        {'g': 'e4c4eca88415b23ecf811c96e48cd24200fe916631a68a684e6c\
   cb6b1913413d344d1d8d84a333839d88eee431521f6e357c16e6a93be111a9807\
   6739cd401bab3b9d565bf4fb99e9d185b1e14d61c93700133f908bae03e28764d\
   107dcd2ea7674217622074bb19efff482f5f5c1a86d5551b2fc68d1c6e9d80119\
   58ef4b9c2a3a55d0d3c882e6ad7f9f0f3c61568f78d0706b10a26f23b4f197c32\
   2b825002284a0aca91807bba98ece912b80e10cdf180cf99a35f210c1655fbfdd\
   74f13b1b5046591f8403873d12239834dd6c4eceb42bf7482e1794a1601357b62\
   9ddfa971f2ed273b146ec1ca06d0adf55dd91d65c37297bda78c6d210c0bc26e5\
   58302',
         'p': 'ea1fb1af22881558ef93be8a5f8653c5a559434c49c8c2c12ace\
   5e9c41434c9cf0a8e9498acb0f4663c08b4484eace845f6fb17dac62c98e706af\
   0fc74e4da1c6c2b3fbf5a1d58ff82fc1a66f3e8b12252c40278fff9dd7f102eed\
   2cb5b7323ebf1908c234d935414dded7f8d244e54561b0dca39b301de8c49da9f\
   b23df33c6182e3f983208c560fb5119fbf78ebe3e6564ee235c6a15cbb9ac247b\
   aba5a423bc6582a1a9d8a2b4f0e9e3d9dbac122f750dd754325135257488b1f6e\
   cabf21bff2947fe0d3b2cb7ffe67f4e7fcdf1214f6053e72a5bb0dd20a0e9fe6d\
   b2df0a908c36e95e60bf49ca4368b8b892b9c79f61ef91c47567c40e1f80ac5aa\
   66ef7',
         'q': '8ec73f3761caf5fdfe6e4e82098bf10f898740dcb808204bf6b1\
   8f507192c19d',
         'x': '47eea9c0e8b43329262f3a0b617cd04db1cf159af2aba0ea06c2\
   ee5b8a6c2d69',
         'y': '65dad9740de9422632c4401df77b68a37fbe3db48aceadab7d90\
   02770b38dc8297886cdde82fab71650944a692cf714f82841f4f5668ecbeb6777\
   44e398a558c5f72d087d26ee29b6324c8def060ed5c5fe4f10b215f4b04dde218\
   fe023ae8fcb99be89ad9a1bb737ae73ae7180944de3fd6abc0d66b6832213a5db\
   47469e6127394bc1fd5142e46438fa48f9774038a3ea312bf539c700f7a486964\
   abdde996cc0b7d84fec7ef4da121db184d2410d44e9ad9b1b95c3d71edf4a4ba1\
   f29e9b8733097fa0c7e8a43141fd0a560f1675323c6ca4504ddb1ed1c2e5887c6\
   8f4eecf426f64ce2222bb7a83e771dc27464fef02da9c7c78b2cc36a8aa34b2ab\
   5555a'},
        {'g': 'e4c4eca88415b23ecf811c96e48cd24200fe916631a68a684e6c\
   cb6b1913413d344d1d8d84a333839d88eee431521f6e357c16e6a93be111a9807\
   6739cd401bab3b9d565bf4fb99e9d185b1e14d61c93700133f908bae03e28764d\
   107dcd2ea7674217622074bb19efff482f5f5c1a86d5551b2fc68d1c6e9d80119\
   58ef4b9c2a3a55d0d3c882e6ad7f9f0f3c61568f78d0706b10a26f23b4f197c32\
   2b825002284a0aca91807bba98ece912b80e10cdf180cf99a35f210c1655fbfdd\
   74f13b1b5046591f8403873d12239834dd6c4eceb42bf7482e1794a1601357b62\
   9ddfa971f2ed273b146ec1ca06d0adf55dd91d65c37297bda78c6d210c0bc26e5\
   58302',
         'p': 'ea1fb1af22881558ef93be8a5f8653c5a559434c49c8c2c12ace\
   5e9c41434c9cf0a8e9498acb0f4663c08b4484eace845f6fb17dac62c98e706af\
   0fc74e4da1c6c2b3fbf5a1d58ff82fc1a66f3e8b12252c40278fff9dd7f102eed\
   2cb5b7323ebf1908c234d935414dded7f8d244e54561b0dca39b301de8c49da9f\
   b23df33c6182e3f983208c560fb5119fbf78ebe3e6564ee235c6a15cbb9ac247b\
   aba5a423bc6582a1a9d8a2b4f0e9e3d9dbac122f750dd754325135257488b1f6e\
   cabf21bff2947fe0d3b2cb7ffe67f4e7fcdf1214f6053e72a5bb0dd20a0e9fe6d\
   b2df0a908c36e95e60bf49ca4368b8b892b9c79f61ef91c47567c40e1f80ac5aa\
   66ef7',
         'q': '8ec73f3761caf5fdfe6e4e82098bf10f898740dcb808204bf6b1\
   8f507192c19d',
         'x': '7e15dc5a1fbfa404a40be5f94334d22d50c29550008d29daf16e\
   c682fa29e10a',
         'y': 'be5e833678b92b78dcbf83b9137329bd9a4fcf3094baf2bb3fd4\
   518e663911cff2d7995ad5903e0b3d6a71e0cf01426ae03332331867857ef8935\
   a78f75a269268e108b1b03e5346edddf4af610ba2aaeb55e5132dccf989aaf5ea\
   069574147c9925297847410ce9fbba9cc65e73e011f249f449dffc304a170f2e2\
   a218197e91128ead770f03e7e8966887c870e6c405129e08f5c49b1cdef48be2c\
   62007c629c35330e2a27f73acf334295dd7832cbe495b61204694b1eab831a05f\
   40b7a84c3cc726aa6fa408d2d91cb3e02dd7487d4fe1e50b0f7b4d6e468bb086e\
   695fded8f9e8231bb9a40b0ff33b61f7143e7df513e7219c2b9102c8ac4321b40\
   36ffb'},
        {'g': 'e4c4eca88415b23ecf811c96e48cd24200fe916631a68a684e6c\
   cb6b1913413d344d1d8d84a333839d88eee431521f6e357c16e6a93be111a9807\
   6739cd401bab3b9d565bf4fb99e9d185b1e14d61c93700133f908bae03e28764d\
   107dcd2ea7674217622074bb19efff482f5f5c1a86d5551b2fc68d1c6e9d80119\
   58ef4b9c2a3a55d0d3c882e6ad7f9f0f3c61568f78d0706b10a26f23b4f197c32\
   2b825002284a0aca91807bba98ece912b80e10cdf180cf99a35f210c1655fbfdd\
   74f13b1b5046591f8403873d12239834dd6c4eceb42bf7482e1794a1601357b62\
   9ddfa971f2ed273b146ec1ca06d0adf55dd91d65c37297bda78c6d210c0bc26e5\
   58302',
         'p': 'ea1fb1af22881558ef93be8a5f8653c5a559434c49c8c2c12ace\
   5e9c41434c9cf0a8e9498acb0f4663c08b4484eace845f6fb17dac62c98e706af\
   0fc74e4da1c6c2b3fbf5a1d58ff82fc1a66f3e8b12252c40278fff9dd7f102eed\
   2cb5b7323ebf1908c234d935414dded7f8d244e54561b0dca39b301de8c49da9f\
   b23df33c6182e3f983208c560fb5119fbf78ebe3e6564ee235c6a15cbb9ac247b\
   aba5a423bc6582a1a9d8a2b4f0e9e3d9dbac122f750dd754325135257488b1f6e\
   cabf21bff2947fe0d3b2cb7ffe67f4e7fcdf1214f6053e72a5bb0dd20a0e9fe6d\
   b2df0a908c36e95e60bf49ca4368b8b892b9c79f61ef91c47567c40e1f80ac5aa\
   66ef7',
         'q': '8ec73f3761caf5fdfe6e4e82098bf10f898740dcb808204bf6b1\
   8f507192c19d',
         'x': '8c77eb7870a4108f70251698f0a272a45a87346c8ef14d01e6e5\
   effd914e65eb',
         'y': '7e3451f243886f90c62cff555ef70fb1b28e3040336d03e2924f\
   8c093e9afddadc8a2e769eb98b5187feb9e029bba4fe3c1fcd0e891abca0792ab\
   9cea27250be580f68baa5e92d05e405f8ceeec89b66020a4b08c5b0b4ffe123cf\
   75da89f06a54e90c1f1a747f51e5208d7d718d8bf3f6173442914bcfcd8f68568\
   d7933471f438fe33efffb867b75a8bae0000795643d4170d49f56579f4d5082d5\
   0bd0b21837fa4066821c3b4bf9e88a7e3064d76623e07174a3459cef41afa192b\
   3fd4dbc84b04e48facb96a66dd39864f8c90838890bdaac64211b0cc800a2a452\
   3540fce1c90d48d44f2160ba2cac83988b09faf27e371298d2feeb677e71ce37e\
   35389'},
        {'g': 'e4c4eca88415b23ecf811c96e48cd24200fe916631a68a684e6c\
   cb6b1913413d344d1d8d84a333839d88eee431521f6e357c16e6a93be111a9807\
   6739cd401bab3b9d565bf4fb99e9d185b1e14d61c93700133f908bae03e28764d\
   107dcd2ea7674217622074bb19efff482f5f5c1a86d5551b2fc68d1c6e9d80119\
   58ef4b9c2a3a55d0d3c882e6ad7f9f0f3c61568f78d0706b10a26f23b4f197c32\
   2b825002284a0aca91807bba98ece912b80e10cdf180cf99a35f210c1655fbfdd\
   74f13b1b5046591f8403873d12239834dd6c4eceb42bf7482e1794a1601357b62\
   9ddfa971f2ed273b146ec1ca06d0adf55dd91d65c37297bda78c6d210c0bc26e5\
   58302',
         'p': 'ea1fb1af22881558ef93be8a5f8653c5a559434c49c8c2c12ace\
   5e9c41434c9cf0a8e9498acb0f4663c08b4484eace845f6fb17dac62c98e706af\
   0fc74e4da1c6c2b3fbf5a1d58ff82fc1a66f3e8b12252c40278fff9dd7f102eed\
   2cb5b7323ebf1908c234d935414dded7f8d244e54561b0dca39b301de8c49da9f\
   b23df33c6182e3f983208c560fb5119fbf78ebe3e6564ee235c6a15cbb9ac247b\
   aba5a423bc6582a1a9d8a2b4f0e9e3d9dbac122f750dd754325135257488b1f6e\
   cabf21bff2947fe0d3b2cb7ffe67f4e7fcdf1214f6053e72a5bb0dd20a0e9fe6d\
   b2df0a908c36e95e60bf49ca4368b8b892b9c79f61ef91c47567c40e1f80ac5aa\
   66ef7',
         'q': '8ec73f3761caf5fdfe6e4e82098bf10f898740dcb808204bf6b1\
   8f507192c19d',
         'x': '12d4b73532b0a480f88fb82eb3cf89729539ba3b5bfb463c792d\
   c223d1a526dd',
         'y': '1371ad94dc2db02476ac925aa0cbdd7e247f86a08a6f2492cd4b\
   3f7b05aa881b2e83d0c5d82246c17cae230a41dd04f05a8c3fed1e09cf8e0d8dc\
   98a9887ff772e2f60434ebea076344f4fbffcbbbd8dee4bc10e7626f26a92c3bf\
   0ac08117bd539b477077d45e11fbe47818f3ce03d6daf34c77595e72d1c8376d9\
   772f51ce956f0e30e98f51155e9effb974f3d46fb48c76a004b0117dbc19d7804\
   4f248821f88fa87d55ba124842d159b5ac4ce916487ecf9d03321241a2bf18967\
   47f155f281434435741b1f26a79d35270167ba3b505a6cec672339823c8fc6dc7\
   97d458d639e5ed015ac710ebd31b86d736e9b2ab340e7f38f58788483484b81eb\
   0b1ec'}
    ]

    expected = []
    for dictionary in expected_vectors:
        new_dict = {}
        for k, v in dictionary.iteritems():
            v = v.strip()
            v = v.replace(" ", "")
            v = int(v, 16)
            new_dict[k] = v
        expected.append(new_dict)

    assert expected == load_fips_dsa_key_pair_vectors(vector_data)
