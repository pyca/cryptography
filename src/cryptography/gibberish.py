# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import base64
import json
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _encode_key_material(data):
    return base64.b64encode(data).rstrip(b"=")


def _decode_key_material(data):
    # Restore our padding
    data += (b"=" * (len(data) % 4))
    return base64.urlsafe_b64decode(data)


class Gibberish(object):

    _algorithm = hashes.SHA512()

    def __init__(self, key, backend=None):
        if backend is None:
            backend = default_backend()

        data = json.loads(_decode_key_material(key).decode("ascii"))

        self._backend = backend
        self._salt = _decode_key_material(data["salt"].encode("ascii"))
        self._secret = _decode_key_material(data["secret"].encode("ascii"))

    @classmethod
    def generate_key(cls):
        data = {
            "salt": _encode_key_material(os.urandom(16)).decode("ascii"),
            "secret": _encode_key_material(os.urandom(16)).decode("ascii"),
        }
        data = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return _encode_key_material(data.encode("ascii"))

    def derive_secret(self, name, length=None):
        if length is None:
            length = 255 * (self._algorithm.digest_size // 8)

        hkdf = HKDF(
            backend=self._backend,
            algorithm=self._algorithm,
            length=length,
            salt=self._salt,
            info=name,
        )

        return hkdf.derive(self._secret)
