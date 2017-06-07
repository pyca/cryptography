# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii
import os

import pytest

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends.interfaces import DHBackend
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)

from ...utils import load_nist_vectors, load_vectors_from_file


@pytest.mark.supported(
    only_if=lambda backend: not backend.x25519_supported(),
    skip_message="Requires OpenSSL without X25519 support"
)
@pytest.mark.requires_backend_interface(interface=DHBackend)
def test_x25519_unsupported(backend):
    with pytest.raises(UnsupportedAlgorithm):
        X25519PublicKey.from_public_bytes(b"0" * 32)

    with pytest.raises(UnsupportedAlgorithm):
        X25519PrivateKey.generate()


@pytest.mark.supported(
    only_if=lambda backend: backend.x25519_supported(),
    skip_message="Requires OpenSSL with X25519 support"
)
@pytest.mark.requires_backend_interface(interface=DHBackend)
class TestX25519Exchange(object):
    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("asymmetric", "X25519", "rfc7748.txt"),
            load_nist_vectors
        )
    )
    def test_rfc7748(self, vector, backend):
        private = binascii.unhexlify(vector["input_scalar"])
        public = binascii.unhexlify(vector["input_u"])
        shared_key = binascii.unhexlify(vector["output_u"])
        private_key = X25519PrivateKey._from_private_bytes(private)
        public_key = X25519PublicKey.from_public_bytes(public)
        computed_shared_key = private_key.exchange(public_key)
        assert computed_shared_key == shared_key

    def test_rfc7748_1000_iteration(self, backend):
        old_private = private = public = binascii.unhexlify(
            b"090000000000000000000000000000000000000000000000000000000000"
            b"0000"
        )
        shared_key = binascii.unhexlify(
            b"684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d9953"
            b"2c51"
        )
        private_key = X25519PrivateKey._from_private_bytes(private)
        public_key = X25519PublicKey.from_public_bytes(public)
        for _ in range(1000):
            computed_shared_key = private_key.exchange(public_key)
            private_key = X25519PrivateKey._from_private_bytes(
                computed_shared_key
            )
            public_key = X25519PublicKey.from_public_bytes(old_private)
            old_private = computed_shared_key

        assert computed_shared_key == shared_key
