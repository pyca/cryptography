# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography.exceptions import (
    AlreadyFinalized, InvalidKey, _Reasons
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import (
    CounterLocation, KBKDFHMAC, Mode
)

from ...doubles import DummyHashAlgorithm
from ...utils import raises_unsupported_algorithm


class TestKBKDFHMAC(object):
    def test_invalid_key(self):
        kdf = KBKDFHMAC(hashes.SHA256(), Mode.CounterMode, 32, 4, 4,
                        CounterLocation.BeforeFixed, b'label', b'context',
                        None, backend=default_backend())

        key = kdf.derive(b"material")

        kdf = KBKDFHMAC(hashes.SHA256(), Mode.CounterMode, 32, 4, 4,
                        CounterLocation.BeforeFixed, b'label', b'context',
                        None, backend=default_backend())

        with pytest.raises(InvalidKey):
            kdf.verify(b"material2", key)

    def test_already_finalized(self):
        kdf = KBKDFHMAC(hashes.SHA256(), Mode.CounterMode, 32, 4, 4,
                        CounterLocation.BeforeFixed, b'label', b'context',
                        None, backend=default_backend())

        kdf.derive(b'material')

        with pytest.raises(AlreadyFinalized):
            kdf.derive(b'material2')

        kdf = KBKDFHMAC(hashes.SHA256(), Mode.CounterMode, 32, 4, 4,
                        CounterLocation.BeforeFixed, b'label', b'context',
                        None, backend=default_backend())

        key = kdf.derive(b'material')

        with pytest.raises(AlreadyFinalized):
            kdf.verify(b'material', key)

        kdf = KBKDFHMAC(hashes.SHA256(), Mode.CounterMode, 32, 4, 4,
                        CounterLocation.BeforeFixed, b'label', b'context',
                        None, backend=default_backend())
        kdf.verify(b'material', key)

        with pytest.raises(AlreadyFinalized):
            kdf.verify(b"material", key)

    def test_key_length(self):
        kdf = KBKDFHMAC(hashes.SHA1(), Mode.CounterMode, 85899345920, 4, 4,
                        CounterLocation.BeforeFixed, b'label', b'context',
                        None, backend=default_backend())

        with pytest.raises(ValueError):
            kdf.derive(b'material')

    def test_rlen(self):
        with pytest.raises(ValueError):
            KBKDFHMAC(hashes.SHA256(), Mode.CounterMode, 32, 5, 4,
                      CounterLocation.BeforeFixed, b'label', b'context',
                      None, backend=default_backend())

    def test_r_type(self):
        with pytest.raises(TypeError):
            KBKDFHMAC(hashes.SHA1(), Mode.CounterMode, 32, b'r', 4,
                      CounterLocation.BeforeFixed, b'label', b'context',
                      None, backend=default_backend())

    def test_l_type(self):
        with pytest.raises(TypeError):
            KBKDFHMAC(hashes.SHA1(), Mode.CounterMode, 32, 4, b'l',
                      CounterLocation.BeforeFixed, b'label', b'context',
                      None, backend=default_backend())

    def test_l(self):
        with pytest.raises(ValueError):
            KBKDFHMAC(hashes.SHA1(), Mode.CounterMode, 32, 4, None,
                      CounterLocation.BeforeFixed, b'label', b'context',
                      None, backend=default_backend())

    def test_unsupported_mode(self):
        with pytest.raises(TypeError):
            KBKDFHMAC(hashes.SHA256(), None, 32, 4, 4,
                      CounterLocation.BeforeFixed, b'label', b'context',
                      None, backend=default_backend())

    def test_unsupported_location(self):
        with pytest.raises(TypeError):
            KBKDFHMAC(hashes.SHA256(), Mode.CounterMode, 32, 4, 4,
                      None, b'label', b'context', None,
                      backend=default_backend())

    def test_unsupported_parameters(self):
        with pytest.raises(ValueError):
            KBKDFHMAC(hashes.SHA256(), Mode.CounterMode, 32, 4, 4,
                      CounterLocation.BeforeFixed, b'label', b'context',
                      b'fixed', backend=default_backend())

    def test_unsupported_hash(self):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            KBKDFHMAC(object(), Mode.CounterMode, 32, 4, 4,
                      CounterLocation.BeforeFixed, b'label', b'context',
                      None, backend=default_backend())

    def test_unsupported_algorithm(self):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            KBKDFHMAC(DummyHashAlgorithm(), Mode.CounterMode, 32, 4, 4,
                      CounterLocation.BeforeFixed, b'label', b'context',
                      None, backend=default_backend())

    def test_invalid_backend(self):
        mock_backend = object

        with raises_unsupported_algorithm(_Reasons.BACKEND_MISSING_INTERFACE):
            KBKDFHMAC(hashes.SHA256(), Mode.CounterMode, 32, 4, 4,
                      CounterLocation.BeforeFixed, b'label', b'context',
                      None, backend=mock_backend())

    def test_unicode_error_label(self):
        with pytest.raises(TypeError):
            KBKDFHMAC(hashes.SHA256(), Mode.CounterMode, 32, 4, 4,
                      CounterLocation.BeforeFixed, u'label', b'context',
                      backend=default_backend())

    def test_unicode_error_context(self):
        with pytest.raises(TypeError):
            KBKDFHMAC(hashes.SHA256(), Mode.CounterMode, 32, 4, 4,
                      CounterLocation.BeforeFixed, b'label', u'context',
                      None, backend=default_backend())

    def test_unicode_error_key_material(self):
        with pytest.raises(TypeError):
            kdf = KBKDFHMAC(hashes.SHA256(), Mode.CounterMode, 32, 4, 4,
                            CounterLocation.BeforeFixed, b'label',
                            b'context', None, backend=default_backend())
            kdf.derive(u'material')
