import pytest

from cryptography.hazmat.backends.interfaces import (
    HMACBackend, CipherBackend, HashBackend
)

from .skip_check import skip_check


def pytest_generate_tests(metafunc):
    from cryptography.hazmat.backends import _ALL_BACKENDS

    if "backend" in metafunc.fixturenames:
        metafunc.parametrize("backend", _ALL_BACKENDS)


@pytest.mark.trylast
def pytest_runtest_setup(item):
    skip_check('hmac', HMACBackend, item)
    skip_check('cipher', CipherBackend, item)
    skip_check('hash', HashBackend, item)
