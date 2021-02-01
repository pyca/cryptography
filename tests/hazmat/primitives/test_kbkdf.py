# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import pytest

from cryptography.exceptions import AlreadyFinalized, InvalidKey, _Reasons
from cryptography.hazmat.backends.interfaces import HMACBackend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import (
    CounterLocation,
    KBKDFHMAC,
    Mode,
)

from ...doubles import DummyHashAlgorithm
from ...utils import raises_unsupported_algorithm


@pytest.mark.requires_backend_interface(interface=HMACBackend)
class TestKBKDFHMAC(object):
    def test_invalid_key(self, backend):
        kdf = KBKDFHMAC(
            hashes.SHA256(),
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        key = kdf.derive(b"material")

        kdf = KBKDFHMAC(
            hashes.SHA256(),
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        with pytest.raises(InvalidKey):
            kdf.verify(b"material2", key)

    def test_already_finalized(self, backend):
        kdf = KBKDFHMAC(
            hashes.SHA256(),
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        kdf.derive(b"material")

        with pytest.raises(AlreadyFinalized):
            kdf.derive(b"material2")

        kdf = KBKDFHMAC(
            hashes.SHA256(),
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        key = kdf.derive(b"material")

        with pytest.raises(AlreadyFinalized):
            kdf.verify(b"material", key)

        kdf = KBKDFHMAC(
            hashes.SHA256(),
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )
        kdf.verify(b"material", key)

        with pytest.raises(AlreadyFinalized):
            kdf.verify(b"material", key)

    def test_key_length(self, backend):
        kdf = KBKDFHMAC(
            hashes.SHA1(),
            Mode.CounterMode,
            85899345920,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        with pytest.raises(ValueError):
            kdf.derive(b"material")

    def test_rlen(self, backend):
        with pytest.raises(ValueError):
            KBKDFHMAC(
                hashes.SHA256(),
                Mode.CounterMode,
                32,
                5,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_r_type(self, backend):
        with pytest.raises(TypeError):
            KBKDFHMAC(
                hashes.SHA1(),
                Mode.CounterMode,
                32,
                b"r",  # type: ignore[arg-type]
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_l_type(self, backend):
        with pytest.raises(TypeError):
            KBKDFHMAC(
                hashes.SHA1(),
                Mode.CounterMode,
                32,
                4,
                b"l",  # type: ignore[arg-type]
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_l(self, backend):
        with pytest.raises(ValueError):
            KBKDFHMAC(
                hashes.SHA1(),
                Mode.CounterMode,
                32,
                4,
                None,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_unsupported_mode(self, backend):
        with pytest.raises(TypeError):
            KBKDFHMAC(
                hashes.SHA256(),
                None,  # type: ignore[arg-type]
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_unsupported_location(self, backend):
        with pytest.raises(TypeError):
            KBKDFHMAC(
                hashes.SHA256(),
                Mode.CounterMode,
                32,
                4,
                4,
                None,  # type: ignore[arg-type]
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_unsupported_parameters(self, backend):
        with pytest.raises(ValueError):
            KBKDFHMAC(
                hashes.SHA256(),
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                b"fixed",
                backend=backend,
            )

    def test_unsupported_hash(self, backend):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            KBKDFHMAC(
                object(),  # type: ignore[arg-type]
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_unsupported_algorithm(self, backend):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            KBKDFHMAC(
                DummyHashAlgorithm(),
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_invalid_backend(self, backend):
        with raises_unsupported_algorithm(_Reasons.BACKEND_MISSING_INTERFACE):
            KBKDFHMAC(
                hashes.SHA256(),
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=object(),
            )

    def test_unicode_error_label(self, backend):
        with pytest.raises(TypeError):
            KBKDFHMAC(
                hashes.SHA256(),
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                "label",  # type: ignore[arg-type]
                b"context",
                None,
                backend=backend,
            )

    def test_unicode_error_context(self, backend):
        with pytest.raises(TypeError):
            KBKDFHMAC(
                hashes.SHA256(),
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                "context",  # type: ignore[arg-type]
                None,
                backend=backend,
            )

    def test_unicode_error_key_material(self, backend):
        with pytest.raises(TypeError):
            kdf = KBKDFHMAC(
                hashes.SHA256(),
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )
            kdf.derive("material")  # type: ignore[arg-type]

    def test_buffer_protocol(self, backend):
        kdf = KBKDFHMAC(
            hashes.SHA256(),
            Mode.CounterMode,
            10,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        key = kdf.derive(bytearray(b"material"))
        assert key == b"\xb7\x01\x05\x98\xf5\x1a\x12L\xc7."
