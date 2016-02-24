from __future__ import absolute_import, print_function

import hashlib
import os
from binascii import hexlify
from collections import defaultdict

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigdecode_der, sigencode_der

from cryptography_vectors import open_vector_file

from tests.utils import (
    load_fips_ecdsa_signing_vectors, load_vectors_from_file
)

HASHLIB_HASH_TYPES = {
    "SHA-1": hashlib.sha1,
    "SHA-224": hashlib.sha224,
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
    "SHA-512": hashlib.sha512,
}


class TruncatedHash(object):
    def __init__(self, hasher):
        self.hasher = hasher

    def __call__(self, data):
        self.hasher.update(data)
        return self

    def digest(self):
        return self.hasher.digest()[:256 // 8]


def build_vectors(fips_vectors):
    vectors = defaultdict(list)
    for vector in fips_vectors:
        vectors[vector['digest_algorithm']].append(vector['message'])

    for digest_algorithm, messages in vectors.items():
        if digest_algorithm not in HASHLIB_HASH_TYPES:
            continue

        yield ""
        yield "[K-256,{0}]".format(digest_algorithm)
        yield ""

        for message in messages:
            # Make a hash context
            hash_func = TruncatedHash(HASHLIB_HASH_TYPES[digest_algorithm]())

            # Sign the message using warner/ecdsa
            secret_key = SigningKey.generate(curve=SECP256k1)
            public_key = secret_key.get_verifying_key()
            signature = secret_key.sign(message, hashfunc=hash_func,
                                        sigencode=sigencode_der)

            r, s = sigdecode_der(signature, None)

            yield "Msg = {0}".format(hexlify(message))
            yield "d = {0:x}".format(secret_key.privkey.secret_multiplier)
            yield "Qx = {0:x}".format(public_key.pubkey.point.x())
            yield "Qy = {0:x}".format(public_key.pubkey.point.y())
            yield "R = {0:x}".format(r)
            yield "S = {0:x}".format(s)
            yield ""


def write_file(lines, dest):
    for line in lines:
        print(line)
        print(line, file=dest)

source_path = os.path.join("asymmetric", "ECDSA", "FIPS_186-3", "SigGen.txt")
dest_path = os.path.join("asymmetric", "ECDSA", "SECP256K1", "SigGen.txt")

fips_vectors = load_vectors_from_file(
    source_path,
    load_fips_ecdsa_signing_vectors
)

with open_vector_file(dest_path, "w") as dest_file:
    write_file(
        build_vectors(fips_vectors),
        dest_file
    )
