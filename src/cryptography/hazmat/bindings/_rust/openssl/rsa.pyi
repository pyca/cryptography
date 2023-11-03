# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from cryptography.hazmat.primitives.asymmetric import rsa

class RSAPrivateKey: ...
class RSAPublicKey: ...

def generate_private_key(
    public_exponent: int,
    key_size: int,
) -> rsa.RSAPrivateKey: ...
def from_private_numbers(
    numbers: rsa.RSAPrivateNumbers,
    unsafe_skip_rsa_key_validation: bool,
) -> rsa.RSAPrivateKey: ...
def from_public_numbers(numbers: rsa.RSAPublicNumbers) -> rsa.RSAPublicKey: ...
