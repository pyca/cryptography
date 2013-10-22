import pytest

from .utils import (
    base_hash_test, encrypt_test, hash_test, long_string_hash_test
)


class TestEncryptTest(object):
    def test_skips_if_only_if_returns_false(self):
        with pytest.raises(pytest.skip.Exception) as exc_info:
            encrypt_test(
                None, None, None, None,
                only_if=lambda api: False,
                skip_message="message!"
            )
        assert exc_info.value.args[0] == "message!"


class TestHashTest(object):
    def test_skips_if_only_if_returns_false(self):
        with pytest.raises(pytest.skip.Exception) as exc_info:
            hash_test(
                None, None, None,
                only_if=lambda api: False,
                skip_message="message!"
            )
        assert exc_info.value.args[0] == "message!"


class TestBaseHashTest(object):
    def test_skips_if_only_if_returns_false(self):
        with pytest.raises(pytest.skip.Exception) as exc_info:
            base_hash_test(
                None, None, None, None,
                only_if=lambda api: False,
                skip_message="message!"
            )
        assert exc_info.value.args[0] == "message!"


class TestLongHashTest(object):
    def test_skips_if_only_if_returns_false(self):
        with pytest.raises(pytest.skip.Exception) as exc_info:
            long_string_hash_test(
                None, None, None,
                only_if=lambda api: False,
                skip_message="message!"
            )
        assert exc_info.value.args[0] == "message!"
