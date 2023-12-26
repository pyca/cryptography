# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)

def private_key_from_ptr(
    ptr: int,
    unsafe_skip_rsa_key_validation: bool,
) -> PrivateKeyTypes: ...
def public_key_from_ptr(ptr: int) -> PublicKeyTypes: ...
def load_der_public_key(
    data: bytes,
) -> PublicKeyTypes: ...
