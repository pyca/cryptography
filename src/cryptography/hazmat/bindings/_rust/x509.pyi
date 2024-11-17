# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import datetime
import typing

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.padding import PSS, PKCS1v15
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPublicKeyTypes,
    CertificatePublicKeyTypes,
    PrivateKeyTypes,
)
from cryptography.x509 import certificate_transparency

def load_pem_x509_certificate(
    data: bytes, backend: typing.Any = None
) -> x509.Certificate: ...
def load_der_x509_certificate(
    data: bytes, backend: typing.Any = None
) -> x509.Certificate: ...
def load_pem_x509_certificates(
    data: bytes,
) -> list[x509.Certificate]: ...
def load_pem_x509_crl(
    data: bytes, backend: typing.Any = None
) -> x509.CertificateRevocationList: ...
def load_der_x509_crl(
    data: bytes, backend: typing.Any = None
) -> x509.CertificateRevocationList: ...
def load_pem_x509_csr(
    data: bytes, backend: typing.Any = None
) -> x509.CertificateSigningRequest: ...
def load_der_x509_csr(
    data: bytes, backend: typing.Any = None
) -> x509.CertificateSigningRequest: ...
def encode_name_bytes(name: x509.Name) -> bytes: ...
def encode_extension_value(extension: x509.ExtensionType) -> bytes: ...
def create_x509_certificate(
    builder: x509.CertificateBuilder,
    private_key: PrivateKeyTypes,
    hash_algorithm: hashes.HashAlgorithm | None,
    rsa_padding: PKCS1v15 | PSS | None,
) -> x509.Certificate: ...
def create_x509_csr(
    builder: x509.CertificateSigningRequestBuilder,
    private_key: PrivateKeyTypes,
    hash_algorithm: hashes.HashAlgorithm | None,
    rsa_padding: PKCS1v15 | PSS | None,
) -> x509.CertificateSigningRequest: ...
def create_x509_crl(
    builder: x509.CertificateRevocationListBuilder,
    private_key: PrivateKeyTypes,
    hash_algorithm: hashes.HashAlgorithm | None,
    rsa_padding: PKCS1v15 | PSS | None,
) -> x509.CertificateRevocationList: ...

class Sct:
    @property
    def version(self) -> certificate_transparency.Version: ...
    @property
    def log_id(self) -> bytes: ...
    @property
    def timestamp(self) -> datetime.datetime: ...
    @property
    def entry_type(self) -> certificate_transparency.LogEntryType: ...
    @property
    def signature_hash_algorithm(self) -> hashes.HashAlgorithm: ...
    @property
    def signature_algorithm(
        self,
    ) -> certificate_transparency.SignatureAlgorithm: ...
    @property
    def signature(self) -> bytes: ...
    @property
    def extension_bytes(self) -> bytes: ...

class Certificate:
    def fingerprint(self, algorithm: hashes.HashAlgorithm) -> bytes: ...
    @property
    def serial_number(self) -> int: ...
    @property
    def version(self) -> x509.Version: ...
    def public_key(self) -> CertificatePublicKeyTypes: ...
    @property
    def public_key_algorithm_oid(self) -> x509.ObjectIdentifier: ...
    @property
    def not_valid_before(self) -> datetime.datetime: ...
    @property
    def not_valid_before_utc(self) -> datetime.datetime: ...
    @property
    def not_valid_after(self) -> datetime.datetime: ...
    @property
    def not_valid_after_utc(self) -> datetime.datetime: ...
    @property
    def issuer(self) -> x509.Name: ...
    @property
    def subject(self) -> x509.Name: ...
    @property
    def signature_hash_algorithm(
        self,
    ) -> hashes.HashAlgorithm | None: ...
    @property
    def signature_algorithm_oid(self) -> x509.ObjectIdentifier: ...
    @property
    def signature_algorithm_parameters(
        self,
    ) -> None | PSS | PKCS1v15 | ECDSA: ...
    @property
    def extensions(self) -> x509.Extensions: ...
    @property
    def signature(self) -> bytes: ...
    @property
    def tbs_certificate_bytes(self) -> bytes: ...
    @property
    def tbs_precertificate_bytes(self) -> bytes: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...
    def public_bytes(self, encoding: serialization.Encoding) -> bytes: ...
    def verify_directly_issued_by(self, issuer: Certificate) -> None: ...

class RevokedCertificate: ...

class CertificateRevocationList:
    def public_bytes(self, encoding: serialization.Encoding) -> bytes: ...
    def fingerprint(self, algorithm: hashes.HashAlgorithm) -> bytes: ...
    def get_revoked_certificate_by_serial_number(
        self, serial_number: int
    ) -> RevokedCertificate | None: ...
    @property
    def signature_hash_algorithm(
        self,
    ) -> hashes.HashAlgorithm | None: ...
    @property
    def signature_algorithm_oid(self) -> x509.ObjectIdentifier: ...
    @property
    def signature_algorithm_parameters(
        self,
    ) -> None | PSS | PKCS1v15 | ECDSA: ...
    @property
    def issuer(self) -> x509.Name: ...
    @property
    def next_update(self) -> datetime.datetime | None: ...
    @property
    def next_update_utc(self) -> datetime.datetime | None: ...
    @property
    def last_update(self) -> datetime.datetime: ...
    @property
    def last_update_utc(self) -> datetime.datetime: ...
    @property
    def extensions(self) -> x509.Extensions: ...
    @property
    def signature(self) -> bytes: ...
    @property
    def tbs_certlist_bytes(self) -> bytes: ...
    def __eq__(self, other: object) -> bool: ...
    def __len__(self) -> int: ...
    @typing.overload
    def __getitem__(self, idx: int) -> x509.RevokedCertificate: ...
    @typing.overload
    def __getitem__(self, idx: slice) -> list[x509.RevokedCertificate]: ...
    def __iter__(self) -> typing.Iterator[x509.RevokedCertificate]: ...
    def is_signature_valid(
        self, public_key: CertificateIssuerPublicKeyTypes
    ) -> bool: ...

class CertificateSigningRequest: ...

class PolicyBuilder:
    def time(self, new_time: datetime.datetime) -> PolicyBuilder: ...
    def store(self, new_store: Store) -> PolicyBuilder: ...
    def max_chain_depth(self, new_max_chain_depth: int) -> PolicyBuilder: ...
    def build_client_verifier(self) -> ClientVerifier: ...
    def build_server_verifier(
        self, subject: x509.verification.Subject
    ) -> ServerVerifier: ...

class VerifiedClient:
    @property
    def subjects(self) -> list[x509.GeneralName] | None: ...
    @property
    def chain(self) -> list[x509.Certificate]: ...

class ClientVerifier:
    @property
    def validation_time(self) -> datetime.datetime: ...
    @property
    def store(self) -> Store: ...
    @property
    def max_chain_depth(self) -> int: ...
    def verify(
        self,
        leaf: x509.Certificate,
        intermediates: list[x509.Certificate],
    ) -> VerifiedClient: ...

class ServerVerifier:
    @property
    def subject(self) -> x509.verification.Subject: ...
    @property
    def validation_time(self) -> datetime.datetime: ...
    @property
    def store(self) -> Store: ...
    @property
    def max_chain_depth(self) -> int: ...
    def verify(
        self,
        leaf: x509.Certificate,
        intermediates: list[x509.Certificate],
    ) -> list[x509.Certificate]: ...

class Store:
    def __init__(self, certs: list[x509.Certificate]) -> None: ...

class VerificationError(Exception):
    pass
