# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import binascii
import os
import random
import sys

import pytest

from cryptography.exceptions import AlreadyFinalized, UnsupportedAlgorithm
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives import hashes

from ...utils import load_nist_vectors
from .utils import _load_all_params


@pytest.mark.supported(
    only_if=lambda backend: (
        not rust_openssl.CRYPTOGRAPHY_OPENSSL_330_OR_GREATER
        or rust_openssl.CRYPTOGRAPHY_IS_LIBRESSL
        or rust_openssl.CRYPTOGRAPHY_IS_BORINGSSL
        or rust_openssl.CRYPTOGRAPHY_IS_AWSLC
    ),
    skip_message="Requires backend without XOF support",
)
def test_unsupported_boring_libre(backend):
    with pytest.raises(UnsupportedAlgorithm):
        hashes.XOFHash(hashes.SHAKE128(digest_size=32))


@pytest.mark.supported(
    only_if=lambda backend: rust_openssl.CRYPTOGRAPHY_OPENSSL_330_OR_GREATER,
    skip_message="Requires backend with XOF support",
)
class TestXOFHash:
    def test_hash_reject_unicode(self, backend):
        m = hashes.XOFHash(hashes.SHAKE128(sys.maxsize))
        with pytest.raises(TypeError):
            m.update("\u00fc")  # type: ignore[arg-type]

    def test_incorrect_hash_algorithm_type(self, backend):
        with pytest.raises(TypeError):
            # Instance required
            hashes.XOFHash(hashes.SHAKE128)  # type: ignore[arg-type]

        with pytest.raises(TypeError):
            hashes.XOFHash(hashes.SHA256())  # type: ignore[arg-type]

    def test_raises_update_after_squeeze(self, backend):
        h = hashes.XOFHash(hashes.SHAKE128(digest_size=256))
        h.update(b"foo")
        h.squeeze(5)

        with pytest.raises(AlreadyFinalized):
            h.update(b"bar")

    def test_copy(self, backend):
        h = hashes.XOFHash(hashes.SHAKE128(digest_size=256))
        h.update(b"foo")
        h.update(b"bar")
        h2 = h.copy()
        assert h2.squeeze(10) == h.squeeze(10)

    def test_exhaust_bytes(self, backend):
        h = hashes.XOFHash(hashes.SHAKE128(digest_size=256))
        h.update(b"foo")
        with pytest.raises(ValueError):
            h.squeeze(257)
        h.squeeze(200)
        h.squeeze(56)
        with pytest.raises(ValueError):
            h.squeeze(1)


@pytest.mark.supported(
    only_if=lambda backend: rust_openssl.CRYPTOGRAPHY_OPENSSL_330_OR_GREATER,
    skip_message="Requires backend with XOF support",
)
class TestXOFSHAKE128:
    def test_shake128_variable(self, backend, subtests):
        vectors = _load_all_params(
            os.path.join("hashes", "SHAKE"),
            ["SHAKE128VariableOut.rsp"],
            load_nist_vectors,
        )
        for vector in vectors:
            with subtests.test():
                output_length = int(vector["outputlen"]) // 8
                msg = binascii.unhexlify(vector["msg"])
                shake = hashes.SHAKE128(digest_size=output_length)
                m = hashes.XOFHash(shake)
                m.update(msg)
                remaining = output_length
                data = b""
                stride = random.randint(1, 128)
                while remaining > 0:
                    stride = min(stride, remaining)
                    data += m.squeeze(stride)
                    remaining -= stride
                assert data == binascii.unhexlify(vector["output"])


@pytest.mark.supported(
    only_if=lambda backend: rust_openssl.CRYPTOGRAPHY_OPENSSL_330_OR_GREATER,
    skip_message="Requires backend with XOF support",
)
class TestXOFSHAKE256:
    def test_shake256_variable(self, backend, subtests):
        vectors = _load_all_params(
            os.path.join("hashes", "SHAKE"),
            ["SHAKE256VariableOut.rsp"],
            load_nist_vectors,
        )
        for vector in vectors:
            with subtests.test():
                output_length = int(vector["outputlen"]) // 8
                msg = binascii.unhexlify(vector["msg"])
                shake = hashes.SHAKE256(digest_size=output_length)
                m = hashes.XOFHash(shake)
                m.update(msg)
                remaining = output_length
                data = b""
                stride = random.randint(1, 128)
                while remaining > 0:
                    stride = min(stride, remaining)
                    data += m.squeeze(stride)
                    remaining -= stride
                assert data == binascii.unhexlify(vector["output"])
