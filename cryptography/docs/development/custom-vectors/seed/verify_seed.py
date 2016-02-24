import binascii

import botan

from tests.utils import load_nist_vectors


def encrypt(mode, key, iv, plaintext):
    encryptor = botan.Cipher("SEED/{0}/NoPadding".format(mode), "encrypt",
                             binascii.unhexlify(key))

    cipher_text = encryptor.cipher(binascii.unhexlify(plaintext),
                                   binascii.unhexlify(iv))
    return binascii.hexlify(cipher_text)


def verify_vectors(mode, filename):
    with open(filename, "r") as f:
        vector_file = f.read().splitlines()

    vectors = load_nist_vectors(vector_file)
    for vector in vectors:
        ct = encrypt(
            mode,
            vector["key"],
            vector["iv"],
            vector["plaintext"]
        )
        assert ct == vector["ciphertext"]


ofb_path = "vectors/cryptography_vectors/ciphers/SEED/seed-ofb.txt"
verify_vectors("OFB", ofb_path)
cfb_path = "vectors/cryptography_vectors/ciphers/SEED/seed-cfb.txt"
verify_vectors("CFB", cfb_path)
