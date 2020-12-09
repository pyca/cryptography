# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

IKM = binascii.unhexlify(b"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
L = 1200
OKM = HKDF(
    algorithm=hashes.SHA256(),
    length=L,
    salt=None,
    info=None,
    backend=default_backend(),
).derive(IKM)


def _build_vectors():
    output = [
        "COUNT = 0",
        "Hash = SHA-256",
        "IKM = " + binascii.hexlify(IKM).decode("ascii"),
        "salt = ",
        "info = ",
        "L = {}".format(L),
        "OKM = " + binascii.hexlify(OKM).decode("ascii"),
    ]
    return "\n".join(output)


def _write_file(data, filename):
    with open(filename, "w") as f:
        f.write(data)


if __name__ == "__main__":
    _write_file(_build_vectors(), "hkdf.txt")
