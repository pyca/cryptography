# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from os import urandom

import pytest

from cryptography.derive import derive_key
from cryptography.hazmat.backends.interfaces import HMACBackend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


@pytest.mark.requires_backend_interface(interface=HMACBackend)
class TestDeriveKey(object):
    def test_random_source_verify(self, backend):
        key_material = urandom(16)
        identifier = b'region123'
        derived_key = derive_key(
            key_material, identifier, strong=True, backend=backend)
        kdf = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=32,
            info=identifier,
            backend=backend
        )

        kdf.verify(key_material, derived_key)

    def test_random_source_verify_default_backend(self, backend):
        key_material = urandom(16)
        identifier = b'region123'
        derived_key = derive_key(key_material, identifier, strong=True)
        kdf = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=32,
            info=identifier,
            backend=backend
        )

        kdf.verify(key_material, derived_key)

    def test_random_source_length(self, backend):
        key_material = urandom(16)
        identifier = b'region123'
        length = 1020
        derived_key = derive_key(
            key_material, identifier, length=length,
            strong=True, backend=backend
        )

        assert len(derived_key) == length

    def test_random_source_length_default(self, backend):
        key_material = urandom(16)
        identifier = b'region123'
        derived_key = derive_key(
            key_material, identifier, strong=True, backend=backend)

        assert len(derived_key) == 32

    def test_random_source_key_material_non_bytes(self, backend):
        key_material = u'key'
        identifier = b'region123'

        with pytest.raises(TypeError):
            derive_key(key_material, identifier, backend=backend)

    def test_random_source_identifier_non_bytes(self, backend):
        key_material = urandom(16)
        identifier = u'region123'

        with pytest.raises(TypeError):
            derive_key(key_material, identifier, backend=backend)

    def test_password_source_verify(self, backend):
        key_material = b'password'
        salt = urandom(16)
        derived_key = derive_key(key_material, salt, backend=backend)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=131072,
            backend=backend
        )

        kdf.verify(key_material, derived_key)

    def test_password_source_verify_default_backend(self, backend):
        key_material = b'password'
        salt = urandom(16)
        derived_key = derive_key(key_material, salt)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=131072,
            backend=backend
        )

        kdf.verify(key_material, derived_key)

    def test_password_source_length(self, backend):
        key_material = b'password'
        salt = urandom(16)
        length = 4096
        derived_key = derive_key(
            key_material, salt, length=length, backend=backend)

        assert len(derived_key) == length

    def test_password_source_length_default(self, backend):
        key_material = b'password'
        salt = urandom(16)
        derived_key = derive_key(
            key_material, salt, backend=backend)

        assert len(derived_key) == 32

    def test_password_source_key_material_non_bytes(self, backend):
        key_material = u'password'
        salt = urandom(16)

        with pytest.raises(TypeError):
            derive_key(key_material, salt, backend=backend)

    def test_password_source_identifier_non_bytes(self, backend):
        key_material = b'password'
        salt = u'salt'

        with pytest.raises(TypeError):
            derive_key(key_material, salt, backend=backend)
