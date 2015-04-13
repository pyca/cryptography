# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography.hazmat.backends.utils import GcmSizeValidator


class TestGcmSizeValidator(object):
    def test_validate_plaintext_len_valid(self):
        gcm_size_validator = GcmSizeValidator()
        assert gcm_size_validator.validate_plaintext_len() is None
        gcm_size_validator._plaintext_len = 1024
        assert gcm_size_validator.validate_plaintext_len() is None
        gcm_size_validator._plaintext_len = (
            GcmSizeValidator._PLAINTEXT_BIT_LIMIT)
        assert gcm_size_validator.validate_plaintext_len() is None

    def test_validate_plaintext_len_invalid(self):
        gcm_size_validator = GcmSizeValidator()
        gcm_size_validator._plaintext_len = (
            GcmSizeValidator._PLAINTEXT_BIT_LIMIT + 1)
        with pytest.raises(ValueError):
            gcm_size_validator.validate_plaintext_len()
        gcm_size_validator._plaintext_len = -1
        with pytest.raises(ValueError):
            gcm_size_validator.validate_plaintext_len()

    def test_validate_aad_len_valid(self):
        gcm_size_validator = GcmSizeValidator()
        assert gcm_size_validator.validate_aad_len(0) is None
        assert gcm_size_validator.validate_aad_len(1024) is None
        assert gcm_size_validator.validate_aad_len(
            GcmSizeValidator._AAD_BIT_LIMIT) is None

    def test_validate_aad_len_invalid(self):
        gcm_size_validator = GcmSizeValidator()
        with pytest.raises(ValueError):
            gcm_size_validator.validate_aad_len(
                GcmSizeValidator._AAD_BIT_LIMIT + 1)
        with pytest.raises(ValueError):
            gcm_size_validator.validate_aad_len(-1)
