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
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDF

from ...utils import raises_unsupported_algorithm


class UnsupportedMockHash(object):
    name = "unsupported-mock-hash"
    block_size = None
    digest_size = None


class TestCounterKDF(object):
    def test_invalid_key(self):
        kdf = KBKDF(hashes.SHA256(), KBKDF.CTR_MODE, 32, b'label', b'context',
                    backend=default_backend())
        key = kdf.derive(b"material")

        kdf = KBKDF(hashes.SHA256(), KBKDF.CTR_MODE, 32, b'label', b'context',
                    backend=default_backend())
        with pytest.raises(InvalidKey):
            kdf.verify(b"material2", key)

    def test_already_finalized(self):
        kdf = KBKDF(hashes.SHA256(), KBKDF.CTR_MODE, 32, b'label', b'context',
                    backend=default_backend())
        kdf.derive(b'material')
        with pytest.raises(AlreadyFinalized):
            kdf.derive(b'material2')

        kdf = KBKDF(hashes.SHA256(), KBKDF.CTR_MODE, 32, b'label', b'context',
                    backend=default_backend())
        key = kdf.derive(b'material')
        with pytest.raises(AlreadyFinalized):
            kdf.verify(b'material', key)

        kdf = KBKDF(hashes.SHA256(), KBKDF.CTR_MODE, 32, b'label', b'context',
                    backend=default_backend())
        kdf.verify(b'material', key)
        with pytest.raises(AlreadyFinalized):
            kdf.verify(b"material", key)

    def test_key_length(self):
        kdf = KBKDF(hashes.SHA1(), KBKDF.CTR_MODE, 40960, b'label', b'context',
                    backend=default_backend())
        with pytest.raises(ValueError):
            kdf.derive(b'material')

    def test_unsupported_algorithm(self):
        mock_hash = UnsupportedMockHash
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            KBKDF(mock_hash(), KBKDF.CTR_MODE, 32, b'label', b'context',
                  backend=default_backend())

    def test_invalid_backend(self):
        mock_backend = object

        with raises_unsupported_algorithm(_Reasons.BACKEND_MISSING_INTERFACE):
            KBKDF(hashes.SHA256(), KBKDF.CTR_MODE, 32, b'label', b'context',
                  backend=mock_backend())

    def test_unicode_error_label(self):
        with pytest.raises(TypeError):
            KBKDF(hashes.SHA256(), KBKDF.CTR_MODE, 32, u'label', b'context',
                  backend=default_backend())

    def test_unicode_error_context(self):
        with pytest.raises(TypeError):
            KBKDF(hashes.SHA256(), KBKDF.CTR_MODE, 32, b'label', u'context',
                  backend=default_backend())

    def test_unicode_error_key_material(self):
        with pytest.raises(TypeError):
            kdf = KBKDF(hashes.SHA256(), KBKDF.CTR_MODE, 32, b'label',
                        b'context', backend=default_backend())
            kdf.derive(u'material')
