# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import typing

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import _serialization
from cryptography.hazmat.primitives.asymmetric import (
    AsymmetricPadding,
    AsymmetricSignatureContext,
    AsymmetricVerificationContext,
    utils as asymmetric_utils,
)

if typing.TYPE_CHECKING:
    from cryptography.hazmat.backends.openssl import backend as openssl_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding


class RSAPrivateKey(typing.Generic[_RSAPrivateKey]):
    @property
    def key_size(self) -> int:
        raise NotImplementedError()

    def signer(
        self,
        padding: AsymmetricPadding,
        algorithm: typing.Union[hashes.HashAlgorithm, utils.Prehashed],
    ) -> AsymmetricSignatureContext:
        raise NotImplementedError()

    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError()

    def private_numbers(self) -> RSAPrivateNumbers:
        raise NotImplementedError()

    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError()

    def public_key(self) -> RSAPublicKey:
        raise NotImplementedError()


class RSAPublicKey(typing.Generic[_RSAPublicKey]):
    @property
    def key_size(self) -> int:
        raise NotImplementedError()

    def verifier(
        self,
        padding: AsymmetricPadding,
        algorithm: typing.Union[hashes.HashAlgorithm, utils.Prehashed],
    ) -> AsymmetricVerificationContext:
        raise NotImplementedError()

    def encrypt(self, plaintext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError()

    def public_numbers(self) -> RSAPublicNumbers:
        raise NotImplementedError()

    def public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat,
    ) -> bytes:
        raise NotImplementedError()

    def recover_data_from_signature(
        self,
        signature: bytes,
        padding: AsymmetricPadding,
        algorithm: typing.Union[hashes.HashAlgorithm, utils.Prehashed],
    ) -> bytes:
        raise NotImplementedError()


class RSAPrivateKeyWithSerialization(RSAPrivateKey[_RSAPrivateKey]):
    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        if not isinstance(encoding, _serialization.Encoding):
            raise TypeError("encoding must be an item from the Encoding enum")

        if not isinstance(format, _serialization.PrivateFormat):
            raise TypeError("format must be an item from the PrivateFormat enum")

        if not isinstance(
            encryption_algorithm, _serialization.KeySerializationEncryption
        ):
            raise TypeError(
                "encryption_algorithm must be an item from the "
                "KeySerializationEncryption enum"
            )

        return self._private_bytes(
            encoding, format, encryption_algorithm
        )

    def _private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError()


class RSAPublicKeyWithSerialization(RSAPublicKey[_RSAPublicKey]):
    def public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat,
    ) -> bytes:
        if not isinstance(encoding, _serialization.Encoding):
            raise TypeError("encoding must be an item from the Encoding enum")

        if not isinstance(format, _serialization.PublicFormat):
            raise TypeError("format must be an item from the PublicFormat enum")

        return self._public_bytes(encoding, format)

    def _public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat,
    ) -> bytes:
        raise NotImplementedError()


class RSAPrivateNumbers:
    def __init__(
        self,
        p: int,
        q: int,
        d: int,
        dmp1: int,
        dmq1: int,
        iqmp: int,
        public_numbers: RSAPublicNumbers,
    ):
        self.p = p
        self.q = q
        self.d = d
        self.dmp1 = dmp1
        self.dmq1 = dmq1
        self.iqmp = iqmp
        self.public_numbers = public_numbers

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RSAPrivateNumbers):
            return NotImplemented

        return (
            self.p == other.p
            and self.q == other.q
            and self.d == other.d
            and self.dmp1 == other.dmp1
            and self.dmq1 == other.dmq1
            and self.iqmp == other.iqmp
            and self.public_numbers == other.public_numbers
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.p,
                self.q,
                self.d,
                self.dmp1,
                self.dmq1,
                self.iqmp,
                self.public_numbers,
            )
        )

    def __repr__(self) -> str:
        return (
            f"RSAPrivateNumbers(p={self.p}, q={self.q}, d={self.d}, "
            f"dmp1={self.dmp1}, dmq1={self.dmq1}, iqmp={self.iqmp}, "
            f"public_numbers={self.public_numbers})"
        )

    def private_key(self, backend: typing.Any) -> RSAPrivateKey:
        from cryptography.hazmat.backends.openssl import backend as openssl_backend

        if not isinstance(backend, openssl_backend.Backend):
            raise UnsupportedAlgorithm(
                "Only OpenSSL backend is supported",
                _Reasons.UNSUPPORTED_BACKEND,
            )

        return backend.load_rsa_private_numbers(self)


class RSAPublicNumbers:
    def __init__(self, e: int, n: int):
        self.e = e
        self.n = n

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RSAPublicNumbers):
            return NotImplemented

        return self.e == other.e and self.n == other.n

    def __hash__(self) -> int:
        return hash((self.e, self.n))

    def __repr__(self) -> str:
        return f"RSAPublicNumbers(e={self.e}, n={self.n})"

    def public_key(self, backend: typing.Any) -> RSAPublicKey:
        from cryptography.hazmat.backends.openssl import backend as openssl_backend

        if not isinstance(backend, openssl_backend.Backend):
            raise UnsupportedAlgorithm(
                "Only OpenSSL backend is supported",
                _Reasons.UNSUPPORTED_BACKEND,
            )

        return backend.load_rsa_public_numbers(self)


class _Reasons:
    UNSUPPORTED_BACKEND = "unsupported_backend"
    UNSUPPORTED_PADDING = "unsupported_padding"
    UNSUPPORTED_HASH = "unsupported_hash"
    UNSUPPORTED_MGF = "unsupported_mgf"


class _RSAPrivateKey:
    pass


class _RSAPublicKey:
    pass


def _verify_rsa_parameters(public_exponent: int, key_size: int) -> None:
    if public_exponent not in (3, 65537):
        raise ValueError("public_exponent must be 3 or 65537")
    if key_size < 2048:
        raise ValueError("key_size must be at least 2048-bits.")


@utils.register_interface(RSAPrivateKey)
class _RSAPrivateKeyImpl:
    def __init__(self, backend: openssl_backend.Backend, rsa_cdata: typing.Any):
        self._backend = backend
        self._rsa_cdata = rsa_cdata

    @property
    def key_size(self) -> int:
        return self._backend._rsa_key_size(self._rsa_cdata)

    def signer(
        self,
        padding: AsymmetricPadding,
        algorithm: typing.Union[hashes.HashAlgorithm, utils.Prehashed],
    ) -> AsymmetricSignatureContext:
        from cryptography.hazmat.primitives.asymmetric import padding as padding_mod

        if isinstance(padding, padding_mod.PSS):
            return _RSAPrivateKeyPSSContext(self._backend, self, padding, algorithm)
        elif isinstance(padding, padding_mod.PKCS1v15):
            return _RSAPrivateKeyPKCS1v15Context(
                self._backend, self, padding, algorithm
            )
        else:
            raise UnsupportedAlgorithm(
                "Padding must be PSS or PKCS1v15",
                _Reasons.UNSUPPORTED_PADDING,
            )

    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        from cryptography.hazmat.primitives.asymmetric import padding as padding_mod

        if isinstance(padding, padding_mod.OAEP):
            return self._backend._rsa_decrypt_oaep(self._rsa_cdata, ciphertext, padding)
        elif isinstance(padding, padding_mod.PKCS1v15):
            return self._backend._rsa_decrypt_pkcs1v15(self._rsa_cdata, ciphertext)
        else:
            raise UnsupportedAlgorithm(
                "Padding must be OAEP or PKCS1v15",
                _Reasons.UNSUPPORTED_PADDING,
            )

    def private_numbers(self) -> RSAPrivateNumbers:
        return self._backend._rsa_private_numbers(self._rsa_cdata)

    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        return self._backend._rsa_private_bytes(
            self._rsa_cdata, encoding, format, encryption_algorithm
        )

    def public_key(self) -> RSAPublicKey:
        return self._backend._rsa_public_key(self._rsa_cdata)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _RSAPrivateKeyImpl):
            return NotImplemented

        return self._backend._rsa_cmp(self._rsa_cdata, other._rsa_cdata)

    def __hash__(self) -> int:
        return hash(self._rsa_cdata)


@utils.register_interface(RSAPublicKey)
class _RSAPublicKeyImpl:
    def __init__(self, backend: openssl_backend.Backend, rsa_cdata: typing.Any):
        self._backend = backend
        self._rsa_cdata = rsa_cdata

    @property
    def key_size(self) -> int:
        return self._backend._rsa_key_size(self._rsa_cdata)

    def verifier(
        self,
        padding: AsymmetricPadding,
        algorithm: typing.Union[hashes.HashAlgorithm, utils.Prehashed],
    ) -> AsymmetricVerificationContext:
        from cryptography.hazmat.primitives.asymmetric import padding as padding_mod

        if isinstance(padding, padding_mod.PSS):
            return _RSAPublicKeyPSSContext(self._backend, self, padding, algorithm)
        elif isinstance(padding, padding_mod.PKCS1v15):
            return _RSAPublicKeyPKCS1v15Context(
                self._backend, self, padding, algorithm
            )
        else:
            raise UnsupportedAlgorithm(
                "Padding must be PSS or PKCS1v15",
                _Reasons.UNSUPPORTED_PADDING,
            )

    def encrypt(self, plaintext: bytes, padding: AsymmetricPadding) -> bytes:
        from cryptography.hazmat.primitives.asymmetric import padding as padding_mod

        if isinstance(padding, padding_mod.OAEP):
            return self._backend._rsa_encrypt_oaep(self._rsa_cdata, plaintext, padding)
        elif isinstance(padding, padding_mod.PKCS1v15):
            return self._backend._rsa_encrypt_pkcs1v15(self._rsa_cdata, plaintext)
        else:
            raise UnsupportedAlgorithm(
                "Padding must be OAEP or PKCS1v15",
                _Reasons.UNSUPPORTED_PADDING,
            )

    def public_numbers(self) -> RSAPublicNumbers:
        return self._backend._rsa_public_numbers(self._rsa_cdata)

    def public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat,
    ) -> bytes:
        return self._backend._rsa_public_bytes(self._rsa_cdata, encoding, format)

    def recover_data_from_signature(
        self,
        signature: bytes,
        padding: AsymmetricPadding,
        algorithm: typing.Union[hashes.HashAlgorithm, utils.Prehashed],
    ) -> bytes:
        from cryptography.hazmat.primitives.asymmetric import padding as padding_mod

        if isinstance(padding, padding_mod.PKCS1v15):
            return self._backend._rsa_recover_pkcs1v15(
                self._rsa_cdata, signature, algorithm
            )
        else:
            raise UnsupportedAlgorithm(
                "Padding must be PKCS1v15",
                _Reasons.UNSUPPORTED_PADDING,
            )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _RSAPublicKeyImpl):
            return NotImplemented

        return self._backend._rsa_cmp(self._rsa_cdata, other._rsa_cdata)

    def __hash__(self) -> int:
        return hash(self._rsa_cdata)


class _RSAPrivateKeyPSSContext(AsymmetricSignatureContext):
    def __init__(
        self,
        backend: openssl_backend.Backend,
        private_key: _RSAPrivateKeyImpl,
        padding: padding.PSS,
        algorithm: typing.Union[hashes.HashAlgorithm, utils.Prehashed],
    ):
        self._backend = backend
        self._private_key = private_key
        self._padding = padding
        self._algorithm = algorithm

    def update(self, data: bytes) -> None:
        self._backend._rsa_sig_sign_setup(
            self._private_key._rsa_cdata, self._padding, self._algorithm
        )
        self._backend._rsa_sig_sign_update(self._private_key._rsa_cdata, data)

    def finalize(self) -> bytes:
        return self._backend._rsa_sig_sign_finalize(self._private_key._rsa_cdata)

    def verify(self, signature: bytes) -> None:
        raise TypeError("verify() can only be called on a verification context")


class _RSAPrivateKeyPKCS1v15Context(AsymmetricSignatureContext):
    def __init__(
        self,
        backend: openssl_backend.Backend,
        private_key: _RSAPrivateKeyImpl,
        padding: padding.PKCS1v15,
        algorithm: typing.Union[hashes.HashAlgorithm, utils.Prehashed],
    ):
        self._backend = backend
        self._private_key = private_key
        self._padding = padding
        self._algorithm = algorithm

    def update(self, data: bytes) -> None:
        self._backend._rsa_sig_sign_setup(
            self._private_key._rsa_cdata, self._padding, self._algorithm
        )
        self._backend._rsa_sig_sign_update(self._private_key._rsa_cdata, data)

    def finalize(self) -> bytes:
        return self._backend._rsa_sig_sign_finalize(self._private_key._rsa_cdata)

    def verify(self, signature: bytes) -> None:
        raise TypeError("verify() can only be called on a verification context")


class _RSAPublicKeyPSSContext(AsymmetricVerificationContext):
    def __init__(
        self,
        backend: openssl_backend.Backend,
        public_key: _RSAPublicKeyImpl,
        padding: padding.PSS,
        algorithm: typing.Union[hashes.HashAlgorithm, utils.Prehashed],
    ):
        self._backend = backend
        self._public_key = public_key
        self._padding = padding
        self._algorithm = algorithm

    def update(self, data: bytes) -> None:
        self._backend._rsa_sig_verify_setup(
            self._public_key._rsa_cdata, self._padding, self._algorithm
        )
        self._backend._rsa_sig_verify_update(self._public_key._rsa_cdata, data)

    def verify(self, signature: bytes) -> None:
        self._backend._rsa_sig_verify_finalize(
            self._public_key._rsa_cdata, signature
        )

    def finalize(self) -> bytes:
        raise TypeError("finalize() can only be called on a signing context")


class _RSAPublicKeyPKCS1v15Context(AsymmetricVerificationContext):
    def __init__(
        self,
        backend: openssl_backend.Backend,
        public_key: _RSAPublicKeyImpl,
        padding: padding.PKCS1v15,
        algorithm: typing.Union[hashes.HashAlgorithm, utils.Prehashed],
    ):
        self._backend = backend
        self._public_key = public_key
        self._padding = padding
        self._algorithm = algorithm

    def update(self, data: bytes) -> None:
        self._backend._rsa_sig_verify_setup(
            self._public_key._rsa_cdata, self._padding, self._algorithm
        )
        self._backend._rsa_sig_verify_update(self._public_key._rsa_cdata, data)

    def verify(self, signature: bytes) -> None:
        self._backend._rsa_sig_verify_finalize(
            self._public_key._rsa_cdata, signature
        )

    def finalize(self) -> bytes:
        raise TypeError("finalize() can only be called on a signing context")


def generate_private_key(
    public_exponent: int,
    key_size: int,
    backend: typing.Any,
) -> RSAPrivateKey:
    from cryptography.hazmat.backends.openssl import backend as openssl_backend

    _verify_rsa_parameters(public_exponent, key_size)

    if not isinstance(backend, openssl_backend.Backend):
        raise UnsupportedAlgorithm(
            "Only OpenSSL backend is supported",
            _Reasons.UNSUPPORTED_BACKEND,
        )

    return backend.generate_rsa_private_key(public_exponent, key_size)
