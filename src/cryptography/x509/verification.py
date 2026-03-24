# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import abc
import typing

from cryptography.hazmat.bindings._rust import x509 as rust_x509
from cryptography.x509.general_name import DNSName, IPAddress

__all__ = [
    "CRLRevocationChecker",
    "ClientVerifier",
    "Criticality",
    "ExtensionPolicy",
    "Policy",
    "PolicyBuilder",
    "RevocationChecker",
    "ServerVerifier",
    "Store",
    "Subject",
    "VerificationError",
    "VerifiedClient",
]

Store = rust_x509.Store
Subject = typing.Union[DNSName, IPAddress]
VerifiedClient = rust_x509.VerifiedClient
ClientVerifier = rust_x509.ClientVerifier
ServerVerifier = rust_x509.ServerVerifier
PolicyBuilder = rust_x509.PolicyBuilder
Policy = rust_x509.Policy
ExtensionPolicy = rust_x509.ExtensionPolicy
Criticality = rust_x509.Criticality
VerificationError = rust_x509.VerificationError
CRLRevocationChecker = rust_x509.CRLRevocationChecker


class RevocationChecker(rust_x509.RevocationChecker, metaclass=abc.ABCMeta):
    """
    An interface for revocation checkers.
    """

    @abc.abstractmethod
    def is_revoked(
        self,
        leaf: rust_x509.Certificate,
        issuer: rust_x509.Certificate,
        policy: Policy,
    ) -> bool | None:
        """
        Returns whether the certificate is revoked. If the revocation status
        cannot be determined, the revocation checker may return None.
        """
