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
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "f34481ec3cc627bacd5dc3fb08f273e6",
            "0336763e966d92595a567cc9ce537f5e",
        ),
        (
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "9798c4640bad75c7c3227db910174e72",
            "a9a1631bf4996954ebc093957b234589",
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
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "0336763e966d92595a567cc9ce537f5e",
            "f34481ec3cc627bacd5dc3fb08f273e6",
        ),
        (
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "a9a1631bf4996954ebc093957b234589",
            "9798c4640bad75c7c3227db910174e72",
        ),
    ]


def test_load_nist_vectors_from_file_encrypt():
    assert load_nist_vectors_from_file(
        "AES/KAT/CBCGFSbox256.rsp",
        "ENCRYPT",
        ["key", "iv", "plaintext", "ciphertext"],
    ) == [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "014730f80ac625fe84f026c60bfd547d",
            "5c9d844ed46f9885085e5d6a4f94c7d7",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "0b24af36193ce4665f2825d7b4749c98",
            "a9ff75bd7cf6613d3731c77c3b6d0c04",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "761c1fe41a18acf20d241650611d90f1",
            "623a52fcea5d443e48d9181ab32c7421",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "8a560769d605868ad80d819bdba03771",
            "38f2c7ae10612415d27ca190d27da8b4",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "91fbef2d15a97816060bee1feaa49afe",
            "1bc704f1bce135ceb810341b216d7abe",
        ),
    ]


def test_load_nist_vectors_from_file_decypt():
    assert load_nist_vectors_from_file(
        "AES/KAT/CBCGFSbox256.rsp",
        "DECRYPT",
        ["key", "iv", "ciphertext", "plaintext"],
    ) == [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "5c9d844ed46f9885085e5d6a4f94c7d7",
            "014730f80ac625fe84f026c60bfd547d",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "a9ff75bd7cf6613d3731c77c3b6d0c04",
            "0b24af36193ce4665f2825d7b4749c98",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "623a52fcea5d443e48d9181ab32c7421",
            "761c1fe41a18acf20d241650611d90f1",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "38f2c7ae10612415d27ca190d27da8b4",
            "8a560769d605868ad80d819bdba03771",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "1bc704f1bce135ceb810341b216d7abe",
            "91fbef2d15a97816060bee1feaa49afe",
        ),
    ]
