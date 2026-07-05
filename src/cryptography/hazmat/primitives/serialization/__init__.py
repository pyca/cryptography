# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

from cryptography import utils
from cryptography.hazmat.primitives._serialization import (
    BestAvailableEncryption,
    Encoding,
    KeySerializationEncryption,
    NoEncryption,
    ParameterFormat,
    PrivateFormat,
    PublicFormat,
    _KeySerializationEncryption,
)
from cryptography.hazmat.primitives.asymmetric.dh import _FFDH_DEPRECATION_MSG
from cryptography.hazmat.primitives.serialization.base import (
    load_der_parameters,
    load_der_private_key,
    load_der_public_key,
    load_pem_parameters,
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.hazmat.primitives.serialization.ssh import (
    SSHCertificate,
    SSHCertificateBuilder,
    SSHCertificateType,
    SSHCertPrivateKeyTypes,
    SSHCertPublicKeyTypes,
    SSHPrivateKeyTypes,
    SSHPublicKeyTypes,
    load_ssh_private_key,
    load_ssh_public_identity,
    load_ssh_public_key,
    ssh_key_fingerprint,
)

__all__ = [
    "BestAvailableEncryption",
    "Encoding",
    "KeySerializationEncryption",
    "NoEncryption",
    "ParameterFormat",
    "PrivateFormat",
    "PublicFormat",
    "SSHCertPrivateKeyTypes",
    "SSHCertPublicKeyTypes",
    "SSHCertificate",
    "SSHCertificateBuilder",
    "SSHCertificateType",
    "SSHPrivateKeyTypes",
    "SSHPublicKeyTypes",
    "_KeySerializationEncryption",
    "load_der_parameters",
    "load_der_private_key",
    "load_der_public_key",
    "load_pem_parameters",
    "load_pem_private_key",
    "load_pem_public_key",
    "load_ssh_private_key",
    "load_ssh_public_identity",
    "load_ssh_public_key",
    "ssh_key_fingerprint",
]

# These can only load FFDH parameters, so the functions themselves are
# deprecated alongside the rest of FFDH.
utils.deprecated(
    load_pem_parameters,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn50,
    name="load_pem_parameters",
)

utils.deprecated(
    load_der_parameters,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn50,
    name="load_der_parameters",
)
