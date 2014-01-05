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

import os
import textwrap

import pretend

import pytest

from .utils import (
    load_nist_vectors, load_vectors_from_file, load_cryptrec_vectors,
    load_openssl_vectors, load_hash_vectors, check_for_iface,
    check_backend_support
)


class FakeInterface(object):
    pass


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
