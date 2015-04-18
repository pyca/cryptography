# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography.hazmat.backends.utils import _GCMSizeValidator


class TestGcmSizeValidator(object):
    def test_update_and_validate_valid(self):
        gcm_size_validator = _GCMSizeValidator()
        assert gcm_size_validator.update_and_validate_plaintext(b"") is None
        assert gcm_size_validator.update_and_validate_plaintext(b"0") is None
        gcm_size_validator._plaintext_len = (
            _GCMSizeValidator._PLAINTEXT_BYTE_LIMIT)
        assert gcm_size_validator.update_and_validate_plaintext(b"") is None

    def test_update_and_validate_invalid(self):
        gcm_size_validator = _GCMSizeValidator()
        gcm_size_validator._plaintext_len = (
            _GCMSizeValidator._PLAINTEXT_BYTE_LIMIT)
        with pytest.raises(ValueError):
            gcm_size_validator.update_and_validate_plaintext(b"0")

    def test_validate_plaintext_len_valid(self):
        gcm_size_validator = _GCMSizeValidator()
        assert gcm_size_validator.validate_plaintext_len() is None
        gcm_size_validator._plaintext_len = 1024
        assert gcm_size_validator.validate_plaintext_len() is None
        gcm_size_validator._plaintext_len = (
            _GCMSizeValidator._PLAINTEXT_BYTE_LIMIT)
        assert gcm_size_validator.validate_plaintext_len() is None

    def test_validate_plaintext_len_invalid(self):
        gcm_size_validator = _GCMSizeValidator()
        gcm_size_validator._plaintext_len = (
            _GCMSizeValidator._PLAINTEXT_BYTE_LIMIT + 1)
        with pytest.raises(ValueError):
            gcm_size_validator.validate_plaintext_len()
        gcm_size_validator._plaintext_len = -1
        with pytest.raises(ValueError):
            gcm_size_validator.validate_plaintext_len()

    def test_validate_aad_len_valid(self):
        gcm_size_validator = _GCMSizeValidator()
        assert gcm_size_validator.validate_aad_len(0) is None
        assert gcm_size_validator.validate_aad_len(1024) is None
        assert gcm_size_validator.validate_aad_len(
            _GCMSizeValidator._AAD_BYTE_LIMIT) is None

    def test_validate_aad_len_invalid(self):
        gcm_size_validator = _GCMSizeValidator()
        with pytest.raises(ValueError):
            gcm_size_validator.validate_aad_len(
                _GCMSizeValidator._AAD_BYTE_LIMIT + 1)
        with pytest.raises(ValueError):
            gcm_size_validator.validate_aad_len(-1)
