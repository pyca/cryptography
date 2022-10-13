import typing

from cryptography.hazmat.primitives import serialization
from cryptography import x509

def serialize_certificates(
    certs: typing.List[x509.Certificate],
    encoding: serialization.Encoding,
) -> bytes: ...
