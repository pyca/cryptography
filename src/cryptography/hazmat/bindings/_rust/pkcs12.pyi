# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import typing

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    PKCS12KeyAndCertificates,
)

def load_key_and_certificates(
    data: bytes,
    password: bytes | None,
    backend: typing.Any = None,
) -> tuple[
    PrivateKeyTypes | None,
    x509.Certificate | None,
    list[x509.Certificate],
]: ...
def load_pkcs12(
    data: bytes,
    password: bytes | None,
    backend: typing.Any = None,
) -> PKCS12KeyAndCertificates: ...
