# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.exceptions import (
    AlreadyFinalized, AlreadyUpdated, NotYetFinalized, UnsupportedAlgorithm,
    _Reasons
)
from cryptography.hazmat.backends.interfaces import CipherBackend
from cryptography.hazmat.primitives import interfaces


class Cipher(object):
    def __init__(self, algorithm, mode, backend):
        if not isinstance(backend, CipherBackend):
            raise UnsupportedAlgorithm(
                "Backend object does not implement CipherBackend.",
                _Reasons.BACKEND_MISSING_INTERFACE
            )

        if not isinstance(algorithm, interfaces.CipherAlgorithm):
            raise TypeError(
                "Expected interface of interfaces.CipherAlgorithm."
            )

        if mode is not None:
            mode.validate_for_algorithm(algorithm)

        self.algorithm = algorithm
        self.mode = mode
        self._backend = backend

    def encryptor(self):
        if isinstance(self.mode, interfaces.ModeWithAuthenticationTag):
            if self.mode.tag is not None:
                raise ValueError(
                    "Authentication tag must be None when encrypting."
                )
        ctx = self._backend.create_symmetric_encryption_ctx(
            self.algorithm, self.mode
        )
        return self._wrap_ctx(ctx, encrypt=True)

    def decryptor(self):
        if isinstance(self.mode, interfaces.ModeWithAuthenticationTag):
            if self.mode.tag is None:
                raise ValueError(
                    "Authentication tag must be provided when decrypting."
                )
        ctx = self._backend.create_symmetric_decryption_ctx(
            self.algorithm, self.mode
        )
        return self._wrap_ctx(ctx, encrypt=False)

    def _wrap_ctx(self, ctx, encrypt):
        if isinstance(self.mode, interfaces.ModeWithAuthenticationTag):
            if encrypt:
                return _AEADEncryptionContext(ctx)
            else:
                return _AEADCipherContext(ctx)
        else:
            return _CipherContext(ctx)


@utils.register_interface(interfaces.CipherContext)
class _CipherContext(object):
    def __init__(self, ctx):
        self._ctx = ctx

    def update(self, data):
        if self._ctx is None:
            raise AlreadyFinalized("Context was already finalized.")
        return self._ctx.update(data)

    def finalize(self):
        if self._ctx is None:
            raise AlreadyFinalized("Context was already finalized.")
        data = self._ctx.finalize()
        self._ctx = None
        return data


@utils.register_interface(interfaces.AEADCipherContext)
@utils.register_interface(interfaces.CipherContext)
class _AEADCipherContext(object):
    def __init__(self, ctx):
        self._ctx = ctx
        self._tag = None
        self._updated = False

    def update(self, data):
        if self._ctx is None:
            raise AlreadyFinalized("Context was already finalized.")
        self._updated = True
        return self._ctx.update(data)

    def finalize(self):
        if self._ctx is None:
            raise AlreadyFinalized("Context was already finalized.")
        data = self._ctx.finalize()
        self._tag = self._ctx.tag
        self._ctx = None
        return data

    def authenticate_additional_data(self, data):
        if self._ctx is None:
            raise AlreadyFinalized("Context was already finalized.")
        if self._updated:
            raise AlreadyUpdated("Update has been called on this context.")
        self._ctx.authenticate_additional_data(data)


@utils.register_interface(interfaces.AEADEncryptionContext)
class _AEADEncryptionContext(_AEADCipherContext):
    @property
    def tag(self):
        if self._ctx is not None:
            raise NotYetFinalized("You must finalize encryption before "
                                  "getting the tag.")
        return self._tag
