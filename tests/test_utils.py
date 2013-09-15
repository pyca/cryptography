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

from .utils import (load_nist_vectors, load_nist_vectors_from_file,
    load_cryptrec_vectors, load_cryptrec_vectors_from_file,
    load_openssl_vectors, load_openssl_vectors_from_file)


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


def test_load_nist_vectors_from_file_decrypt():
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
        (
            b"00000000000000000000000000000000",
            b"80000000000000000000000000000000",
            b"07923A39EB0A817D1C4D87BDB82D1F1C",
        ),
        (
            b"00000000000000000000000000000000",
            b"40000000000000000000000000000000",
            b"48CD6419809672D2349260D89A08D3D3",
        ),
        (
            b"10000000000000000000000000000000",
            b"80000000000000000000000000000000",
            b"07923A39EB0A817D1C4D87BDB82D1F1C",
        ),
    ]


def test_load_cryptrec_vectors_from_file_encrypt():
    test_set = load_cryptrec_vectors_from_file(
        "Camellia/NTT/camellia-128-ecb.txt"
    )
    assert test_set[0] == (
        (
            b"00000000000000000000000000000000",
            b"80000000000000000000000000000000",
            b"07923A39EB0A817D1C4D87BDB82D1F1C",
        )
    )
    assert len(test_set) == 1280


def test_load_openssl_vectors_encrypt():
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

    assert load_openssl_vectors(vector_data, "ENCRYPT") == [
        (
            b"2B7E151628AED2A6ABF7158809CF4F3C",
            b"000102030405060708090A0B0C0D0E0F",
            b"6BC1BEE22E409F96E93D7E117393172A",
            b"14F7646187817EB586599146B82BD719",
        ),
        (
            b"2B7E151628AED2A6ABF7158809CF4F3C",
            b"14F7646187817EB586599146B82BD719",
            b"AE2D8A571E03AC9C9EB76FAC45AF8E51",
            b"A53D28BB82DF741103EA4F921A44880B",
        ),
    ]


def test_load_openssl_vectors_decrypt():
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
        "A53D28BB82DF741103EA4F921A44880B:30C81C46A35CE411E5FBC1191A0A52EF:"
        "9C2157A664626D1DEF9EA420FDE69B96:0\n"
        "CAMELLIA-128-CFB:2B7E151628AED2A6ABF7158809CF4F3C:"
        "9C2157A664626D1DEF9EA420FDE69B96:F69F2445DF4F9B17AD2B417BE66C3710:"
        "742A25F0542340C7BAEF24CA8482BB09:0\n"
    ).splitlines()

    assert load_openssl_vectors(vector_data, "DECRYPT") == [
        (
            b"2B7E151628AED2A6ABF7158809CF4F3C",
            b"A53D28BB82DF741103EA4F921A44880B",
            b"30C81C46A35CE411E5FBC1191A0A52EF",
            b"9C2157A664626D1DEF9EA420FDE69B96",
        ),
        (
            b"2B7E151628AED2A6ABF7158809CF4F3C",
            b"9C2157A664626D1DEF9EA420FDE69B96",
            b"F69F2445DF4F9B17AD2B417BE66C3710",
            b"742A25F0542340C7BAEF24CA8482BB09",
        ),
    ]


def test_load_openssl_vectors_from_file_encrypt():
    test_list = load_openssl_vectors_from_file(
        "Camellia/camellia-ofb.txt",
        "ENCRYPT"
    )
    assert len(test_list) == 12
    assert test_list[:4] == [
        (
            b"2B7E151628AED2A6ABF7158809CF4F3C",
            b"000102030405060708090A0B0C0D0E0F",
            b"6BC1BEE22E409F96E93D7E117393172A",
            b"14F7646187817EB586599146B82BD719",
        ),
        (
            b"2B7E151628AED2A6ABF7158809CF4F3C",
            b"50FE67CC996D32B6DA0937E99BAFEC60",
            b"AE2D8A571E03AC9C9EB76FAC45AF8E51",
            b"25623DB569CA51E01482649977E28D84",
        ),
        (
            b"2B7E151628AED2A6ABF7158809CF4F3C",
            b"D9A4DADA0892239F6B8B3D7680E15674",
            b"30C81C46A35CE411E5FBC1191A0A52EF",
            b"C776634A60729DC657D12B9FCA801E98",
        ),
        (
            b"2B7E151628AED2A6ABF7158809CF4F3C",
            b"A78819583F0308E7A6BF36B1386ABF23",
            b"F69F2445DF4F9B17AD2B417BE66C3710",
            b"D776379BE0E50825E681DA1A4C980E8E",
        ),
    ]


def test_load_openssl_vectors_from_file_decrypt():
    test_list = load_openssl_vectors_from_file(
        "Camellia/camellia-ofb.txt",
        "DECRYPT"
    )
    assert len(test_list) == 12
    assert test_list[:4] == [
        (
            b"2B7E151628AED2A6ABF7158809CF4F3C",
            b"000102030405060708090A0B0C0D0E0F",
            b"6BC1BEE22E409F96E93D7E117393172A",
            b"14F7646187817EB586599146B82BD719",
        ),
        (
            b"2B7E151628AED2A6ABF7158809CF4F3C",
            b"50FE67CC996D32B6DA0937E99BAFEC60",
            b"AE2D8A571E03AC9C9EB76FAC45AF8E51",
            b"25623DB569CA51E01482649977E28D84",
        ),
        (
            b"2B7E151628AED2A6ABF7158809CF4F3C",
            b"D9A4DADA0892239F6B8B3D7680E15674",
            b"30C81C46A35CE411E5FBC1191A0A52EF",
            b"C776634A60729DC657D12B9FCA801E98",
        ),
        (
            b"2B7E151628AED2A6ABF7158809CF4F3C",
            b"A78819583F0308E7A6BF36B1386ABF23",
            b"F69F2445DF4F9B17AD2B417BE66C3710",
            b"D776379BE0E50825E681DA1A4C980E8E",
        ),
    ]


def test_load_openssl_vectors_from_file_no_enc_dec_flag():
    test_list = load_openssl_vectors_from_file(
        "Camellia/camellia-cbc.txt",
        "ENCRYPT"
    )
    assert len(test_list) == 12
    assert test_list[:4] == [
        (
            b"2B7E151628AED2A6ABF7158809CF4F3C",
            b"000102030405060708090A0B0C0D0E0F",
            b"6BC1BEE22E409F96E93D7E117393172A",
            b"1607CF494B36BBF00DAEB0B503C831AB",
        ),
        (
            b"2B7E151628AED2A6ABF7158809CF4F3C",
            b"1607CF494B36BBF00DAEB0B503C831AB",
            b"AE2D8A571E03AC9C9EB76FAC45AF8E51",
            b"A2F2CF671629EF7840C5A5DFB5074887",
        ),
        (
            b"2B7E151628AED2A6ABF7158809CF4F3C",
            b"A2F2CF671629EF7840C5A5DFB5074887",
            b"30C81C46A35CE411E5FBC1191A0A52EF",
            b"0F06165008CF8B8B5A63586362543E54",
        ),
        (
            b"2B7E151628AED2A6ABF7158809CF4F3C",
            b"36A84CDAFD5F9A85ADA0F0A993D6D577",
            b"F69F2445DF4F9B17AD2B417BE66C3710",
            b"74C64268CDB8B8FAF5B34E8AF3732980",
        ),
    ]
