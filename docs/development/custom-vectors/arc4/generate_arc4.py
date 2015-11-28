# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms


_RFC6229_KEY_MATERIALS = [
    (True,
     8 * '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'),
    (False,
     8 * '1ada31d5cf688221c109163908ebe51debb46227c6cc8b37641910833222772a')
]


_RFC6229_OFFSETS = [
    0,
    16,
    240,
    256,
    496,
    512,
    752,
    768,
    1008,
    1024,
    1520,
    1536,
    2032,
    2048,
    3056,
    3072,
    4080,
    4096
]


_SIZES_TO_GENERATE = [
    160
]


def _key_for_size(size, keyinfo):
    msb, key = keyinfo
    if msb:
        return key[:size // 4]
    else:
        return key[-size // 4:]


def _build_vectors():
    count = 0
    output = []
    key = None
    plaintext = binascii.unhexlify(32 * '0')
    for size in _SIZES_TO_GENERATE:
        for keyinfo in _RFC6229_KEY_MATERIALS:
            key = _key_for_size(size, keyinfo)
            cipher = ciphers.Cipher(
                algorithms.ARC4(binascii.unhexlify(key)),
                None,
                default_backend())
            encryptor = cipher.encryptor()
            current_offset = 0
            for offset in _RFC6229_OFFSETS:
                if offset % 16 != 0:
                    raise ValueError(
                        "Offset {} is not evenly divisible by 16"
                        .format(offset))
                while current_offset < offset:
                    encryptor.update(plaintext)
                    current_offset += len(plaintext)
                output.append("\nCOUNT = {}".format(count))
                count += 1
                output.append("KEY = {}".format(key))
                output.append("OFFSET = {}".format(offset))
                output.append("PLAINTEXT = {}".format(
                    binascii.hexlify(plaintext)))
                output.append("CIPHERTEXT = {}".format(
                    binascii.hexlify(encryptor.update(plaintext))))
                current_offset += len(plaintext)
            assert not encryptor.finalize()
    return "\n".join(output)


def _write_file(data, filename):
    with open(filename, 'w') as f:
        f.write(data)


if __name__ == '__main__':
    _write_file(_build_vectors(), 'arc4.txt')
