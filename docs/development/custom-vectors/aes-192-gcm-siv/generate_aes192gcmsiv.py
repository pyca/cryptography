# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV


def convert_key_to_192_bits(key: str) -> str:
    """
    This takes existing 128 and 256-bit keys from test vectors from OpenSSL
    and makes them 192-bit by either appending 0 or truncating the key.
    """
    new_key = binascii.unhexlify(key)
    if len(new_key) == 16:
        new_key += b"\x00" * 8
    elif len(new_key) == 32:
        new_key = new_key[0:24]
    else:
        raise RuntimeError(
            "Unexpected key length. OpenSSL AES-GCM-SIV test vectors only "
            "contain 128-bit and 256-bit keys"
        )

    return binascii.hexlify(new_key).decode("ascii")


def encrypt(key: str, iv: str, plaintext: str, aad: str) -> (str, str):
    aesgcmsiv = AESGCMSIV(binascii.unhexlify(key))
    encrypted_output = aesgcmsiv.encrypt(
        binascii.unhexlify(iv),
        binascii.unhexlify(plaintext),
        binascii.unhexlify(aad) if aad else None,
    )
    ciphertext, tag = encrypted_output[:-16], encrypted_output[-16:]

    return (
        binascii.hexlify(ciphertext).decode("ascii"),
        binascii.hexlify(tag).decode("ascii"),
    )


def build_vectors(filename):
    count = 0
    output = []
    key = None
    iv = None
    aad = None
    plaintext = None

    with open(filename) as vector_file:
        for line in vector_file:
            line = line.strip()
            if line.startswith("Key"):
                if count != 0:
                    ciphertext, tag = encrypt(key, iv, plaintext, aad)
                    output.append(f"Tag = {tag}\nCiphertext = {ciphertext}\n")
                output.append(f"\nCOUNT = {count}")
                count += 1
                aad = None
                _, key = line.split(" = ")
                key = convert_key_to_192_bits(key)
                output.append(f"Key = {key}")
            elif line.startswith("IV"):
                _, iv = line.split(" = ")
                output.append(f"IV = {iv}")
            elif line.startswith("AAD"):
                _, aad = line.split(" = ")
                output.append(f"AAD = {aad}")
            elif line.startswith("Plaintext"):
                _, plaintext = line.split(" = ")
                output.append(f"Plaintext = {plaintext}")

        ciphertext, tag = encrypt(key, iv, plaintext, aad)
        output.append(f"Tag = {tag}\nCiphertext = {ciphertext}\n")
        return "\n".join(output)


def write_file(data, filename):
    with open(filename, "w") as f:
        f.write(data)


path = "vectors/cryptography_vectors/ciphers/AES/GCM-SIV/openssl.txt"
write_file(build_vectors(path), "aes-192-gcm-siv.txt")
