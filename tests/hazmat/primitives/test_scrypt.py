# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii
import os

import pytest

from cryptography.exceptions import (
    AlreadyFinalized, InvalidKey, UnsupportedAlgorithm
)
from cryptography.hazmat.backends.interfaces import ScryptBackend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt, _MEM_LIMIT

from tests.utils import load_nist_vectors, load_vectors_from_file

vectors = load_vectors_from_file(
    os.path.join("KDF", "scrypt.txt"), load_nist_vectors)


def _skip_if_memory_limited(memory_limit, params):
    # Memory calc adapted from OpenSSL (URL split over 2 lines, thanks PEP8)
    # https://github.com/openssl/openssl/blob/6286757141a8c6e14d647ec733634a
    # e0c83d9887/crypto/evp/scrypt.c#L189-L221
    blen = int(params["p"]) * 128 * int(params["r"])
    vlen = 32 * int(params["r"]) * (int(params["n"]) + 2) * 4
    memory_required = blen + vlen
    if memory_limit < memory_required:
        pytest.skip("Test exceeds Scrypt memory limit. "
                    "This is likely a 32-bit platform.")


def test_memory_limit_skip():
    with pytest.raises(pytest.skip.Exception):
        _skip_if_memory_limited(1000, {"p": 16, "r": 64, "n": 1024})

    _skip_if_memory_limited(2 ** 31, {"p": 16, "r": 64, "n": 1024})


@pytest.mark.requires_backend_interface(interface=ScryptBackend)
class TestScrypt(object):
    @pytest.mark.parametrize("params", vectors)
    def test_derive(self, backend, params):
        _skip_if_memory_limited(_MEM_LIMIT, params)
        password = params["password"]
        work_factor = int(params["n"])
        block_size = int(params["r"])
        parallelization_factor = int(params["p"])
        length = int(params["length"])
        salt = params["salt"]
        derived_key = params["derived_key"]

        scrypt = Scrypt(salt, length, work_factor, block_size,
                        parallelization_factor, backend)
        assert binascii.hexlify(scrypt.derive(password)) == derived_key

    def test_unsupported_backend(self):
        work_factor = 1024
        block_size = 8
        parallelization_factor = 16
        length = 64
        salt = b"NaCl"
        backend = object()

        with pytest.raises(UnsupportedAlgorithm):
            Scrypt(salt, length, work_factor, block_size,
                   parallelization_factor, backend)

    def test_salt_not_bytes(self, backend):
        work_factor = 1024
        block_size = 8
        parallelization_factor = 16
        length = 64
        salt = 1

        with pytest.raises(TypeError):
            Scrypt(salt, length, work_factor, block_size,
                   parallelization_factor, backend)

    def test_password_not_bytes(self, backend):
        password = 1
        work_factor = 1024
        block_size = 8
        parallelization_factor = 16
        length = 64
        salt = b"NaCl"

        scrypt = Scrypt(salt, length, work_factor, block_size,
                        parallelization_factor, backend)

        with pytest.raises(TypeError):
            scrypt.derive(password)

    @pytest.mark.parametrize("params", vectors)
    def test_verify(self, backend, params):
        _skip_if_memory_limited(_MEM_LIMIT, params)
        password = params["password"]
        work_factor = int(params["n"])
        block_size = int(params["r"])
        parallelization_factor = int(params["p"])
        length = int(params["length"])
        salt = params["salt"]
        derived_key = params["derived_key"]

        scrypt = Scrypt(salt, length, work_factor, block_size,
                        parallelization_factor, backend)
        assert scrypt.verify(password, binascii.unhexlify(derived_key)) is None

    def test_invalid_verify(self, backend):
        password = b"password"
        work_factor = 1024
        block_size = 8
        parallelization_factor = 16
        length = 64
        salt = b"NaCl"
        derived_key = b"fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e773"

        scrypt = Scrypt(salt, length, work_factor, block_size,
                        parallelization_factor, backend)

        with pytest.raises(InvalidKey):
            scrypt.verify(password, binascii.unhexlify(derived_key))

    def test_already_finalized(self, backend):
        password = b"password"
        work_factor = 1024
        block_size = 8
        parallelization_factor = 16
        length = 64
        salt = b"NaCl"

        scrypt = Scrypt(salt, length, work_factor, block_size,
                        parallelization_factor, backend)
        scrypt.derive(password)
        with pytest.raises(AlreadyFinalized):
            scrypt.derive(password)

    def test_invalid_n(self, backend):
        # n is less than 2
        with pytest.raises(ValueError):
            Scrypt(b"NaCl", 64, 1, 8, 16, backend)

        # n is not a power of 2
        with pytest.raises(ValueError):
            Scrypt(b"NaCl", 64, 3, 8, 16, backend)

    def test_invalid_r(self, backend):
        with pytest.raises(ValueError):
            Scrypt(b"NaCl", 64, 2, 0, 16, backend)

    def test_invalid_p(self, backend):
        with pytest.raises(ValueError):
            Scrypt(b"NaCl", 64, 2, 8, 0, backend)
