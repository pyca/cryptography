# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii
import struct

from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms

_N_BLOCKS = [1, 1.5, 2, 2.5, 3]
_INITIAL_COUNTERS = [2**32 - 1, 2**64 - 1]


def _build_vectors():
    count = 0
    output = []
    key = "0" * 64
    nonce = "0" * 16
    for blocks in _N_BLOCKS:
        plaintext = binascii.unhexlify("0" * int(128 * blocks))
        for counter in _INITIAL_COUNTERS:
            full_nonce = struct.pack("<Q", counter) + binascii.unhexlify(nonce)
            cipher = ciphers.Cipher(
                algorithms.ChaCha20(binascii.unhexlify(key), full_nonce),
                None,
            )
            encryptor = cipher.encryptor()
            output.append(f"\nCOUNT = {count}")
            count += 1
            output.append(f"KEY = {key}")
            output.append(f"NONCE = {nonce}")
            output.append(f"INITIAL_BLOCK_COUNTER = {counter}")
            output.append(f"PLAINTEXT = {binascii.hexlify(plaintext)}")
            output.append(
                f"CIPHERTEXT = {binascii.hexlify(encryptor.update(plaintext))}"
            )
    return "\n".join(output)


def _write_file(data, filename):
    with open(filename, "w") as f:
        f.write(data)


if __name__ == "__main__":
    _write_file(_build_vectors(), "counter-overflow.txt")
