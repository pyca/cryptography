# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii
import itertools
import os

from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tests.utils import load_pkcs1_vectors, load_vectors_from_file


def build_vectors(mgf1alg, hashalg, filename):
    vectors = load_vectors_from_file(filename, load_pkcs1_vectors)

    output = []
    for vector in vectors:
        # RSA keys for this must be long enough to accommodate the length of
        # the underlying hash function. This means we can't use the keys from
        # the sha1 test vectors for sha512 tests because 1024-bit keys are too
        # small. Instead we parse the vectors for the test cases, then
        # generate our own 2048-bit keys for each.
        private, _ = vector
        skey = rsa.generate_private_key(65537, 2048, backend)
        pn = skey.private_numbers()
        examples = private["examples"]
        output.append(b"# =============================================")
        output.append(b"# Example")
        output.append(b"# Public key")
        output.append(b"# Modulus:")
        output.append(format(pn.public_numbers.n, "x"))
        output.append(b"# Exponent:")
        output.append(format(pn.public_numbers.e, "x"))
        output.append(b"# Private key")
        output.append(b"# Modulus:")
        output.append(format(pn.public_numbers.n, "x"))
        output.append(b"# Public exponent:")
        output.append(format(pn.public_numbers.e, "x"))
        output.append(b"# Exponent:")
        output.append(format(pn.d, "x"))
        output.append(b"# Prime 1:")
        output.append(format(pn.p, "x"))
        output.append(b"# Prime 2:")
        output.append(format(pn.q, "x"))
        output.append(b"# Prime exponent 1:")
        output.append(format(pn.dmp1, "x"))
        output.append(b"# Prime exponent 2:")
        output.append(format(pn.dmq1, "x"))
        output.append(b"# Coefficient:")
        output.append(format(pn.iqmp, "x"))
        pkey = skey.public_key()
        vectorkey = rsa.RSAPrivateNumbers(
            p=private["p"],
            q=private["q"],
            d=private["private_exponent"],
            dmp1=private["dmp1"],
            dmq1=private["dmq1"],
            iqmp=private["iqmp"],
            public_numbers=rsa.RSAPublicNumbers(
                e=private["public_exponent"], n=private["modulus"]
            ),
        ).private_key(backend)
        count = 1

        for example in examples:
            message = vectorkey.decrypt(
                binascii.unhexlify(example["encryption"]),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None,
                ),
            )
            assert message == binascii.unhexlify(example["message"])
            ct = pkey.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=mgf1alg),
                    algorithm=hashalg,
                    label=None,
                ),
            )
            output.append(
                b"# OAEP Example {0} alg={1} mgf1={2}".format(
                    count, hashalg.name, mgf1alg.name
                )
            )
            count += 1
            output.append(b"# Message:")
            output.append(example["message"])
            output.append(b"# Encryption:")
            output.append(binascii.hexlify(ct))

    return b"\n".join(output)


def write_file(data, filename):
    with open(filename, "w") as f:
        f.write(data)


oaep_path = os.path.join(
    "asymmetric", "RSA", "pkcs-1v2-1d2-vec", "oaep-vect.txt"
)
hashalgs = [
    hashes.SHA1(),
    hashes.SHA224(),
    hashes.SHA256(),
    hashes.SHA384(),
    hashes.SHA512(),
]
for hashtuple in itertools.product(hashalgs, hashalgs):
    if isinstance(hashtuple[0], hashes.SHA1) and isinstance(
        hashtuple[1], hashes.SHA1
    ):
        continue

    write_file(
        build_vectors(hashtuple[0], hashtuple[1], oaep_path),
        "oaep-{0}-{1}.txt".format(hashtuple[0].name, hashtuple[1].name),
    )
