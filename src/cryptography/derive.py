# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DEFAULT_BACKEND = default_backend()
DEFAULT_HASH = hashes.SHA256()


def derive_key(key_material, identifier, length=32,
               strong=False, backend=DEFAULT_BACKEND):
    if not isinstance(key_material, bytes):
        raise TypeError('key_material must be bytes.')

    if not isinstance(identifier, bytes):
        raise TypeError('identifier must be bytes.')

    if strong:
        kdf = HKDFExpand(
            algorithm=DEFAULT_HASH,
            length=length,
            info=identifier,
            backend=backend
        )
    else:
        kdf = PBKDF2HMAC(
            algorithm=DEFAULT_HASH,
            length=length,
            salt=identifier,
            iterations=131072,
            backend=backend
        )

    return kdf.derive(key_material)
