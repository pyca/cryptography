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
        "AES/KAT/CBCGFSbox256.rsp",
        "ENCRYPT",
        ["key", "iv", "plaintext", "ciphertext"],
    ) == [
        (
            b"0000000000000000000000000000000000000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"014730f80ac625fe84f026c60bfd547d",
            b"5c9d844ed46f9885085e5d6a4f94c7d7",
        ),
        (
            b"0000000000000000000000000000000000000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"0b24af36193ce4665f2825d7b4749c98",
            b"a9ff75bd7cf6613d3731c77c3b6d0c04",
        ),
        (
            b"0000000000000000000000000000000000000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"761c1fe41a18acf20d241650611d90f1",
            b"623a52fcea5d443e48d9181ab32c7421",
        ),
        (
            b"0000000000000000000000000000000000000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"8a560769d605868ad80d819bdba03771",
            b"38f2c7ae10612415d27ca190d27da8b4",
        ),
        (
            b"0000000000000000000000000000000000000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"91fbef2d15a97816060bee1feaa49afe",
            b"1bc704f1bce135ceb810341b216d7abe",
        ),
    ]


def test_load_nist_vectors_from_file_decypt():
    assert load_nist_vectors_from_file(
        "AES/KAT/CBCGFSbox256.rsp",
        "DECRYPT",
        ["key", "iv", "ciphertext", "plaintext"],
    ) == [
        (
            b"0000000000000000000000000000000000000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"5c9d844ed46f9885085e5d6a4f94c7d7",
            b"014730f80ac625fe84f026c60bfd547d",
        ),
        (
            b"0000000000000000000000000000000000000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"a9ff75bd7cf6613d3731c77c3b6d0c04",
            b"0b24af36193ce4665f2825d7b4749c98",
        ),
        (
            b"0000000000000000000000000000000000000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"623a52fcea5d443e48d9181ab32c7421",
            b"761c1fe41a18acf20d241650611d90f1",
        ),
        (
            b"0000000000000000000000000000000000000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"38f2c7ae10612415d27ca190d27da8b4",
            b"8a560769d605868ad80d819bdba03771",
        ),
        (
            b"0000000000000000000000000000000000000000000000000000000000000000",
            b"00000000000000000000000000000000",
            b"1bc704f1bce135ceb810341b216d7abe",
            b"91fbef2d15a97816060bee1feaa49afe",
        ),
    ]
