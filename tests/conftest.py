import pytest

from cryptography.hazmat.backends import _ALL_BACKENDS
from cryptography.hazmat.backends.interfaces import (
    HMACBackend, CipherBackend, HashBackend
)

from .utils import check_for_iface, check_backend_support


@pytest.fixture(params=_ALL_BACKENDS)
def backend(request):
    return request.param


@pytest.mark.trylast
def pytest_runtest_setup(item):
    check_for_iface("hmac", HMACBackend, item)
    check_for_iface("cipher", CipherBackend, item)
    check_for_iface("hash", HashBackend, item)
    check_backend_support(item)
