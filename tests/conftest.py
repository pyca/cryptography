import pytest

from cryptography.hazmat.backends import _ALL_BACKENDS
from cryptography.hazmat.backends.interfaces import (
    HMACBackend, CipherBackend, HashBackend
)

from .utils import check_for_iface, check_backend_support, select_backends


# copy all backends so we can mutate it.This variable is used in generate
# tests to allow us to target a single backend without changing _ALL_BACKENDS
_SELECTED_BACKENDS = list(_ALL_BACKENDS)


def pytest_generate_tests(metafunc):
    global _SELECTED_BACKENDS
    names = metafunc.config.getoption("--backend")
    _SELECTED_BACKENDS = select_backends(names, _SELECTED_BACKENDS)


@pytest.fixture(params=_SELECTED_BACKENDS)
def backend(request):
    return request.param


@pytest.mark.trylast
def pytest_runtest_setup(item):
    check_for_iface("hmac", HMACBackend, item)
    check_for_iface("cipher", CipherBackend, item)
    check_for_iface("hash", HashBackend, item)
    check_backend_support(item)


def pytest_addoption(parser):
    parser.addoption(
        "--backend", action="store", metavar="NAME",
        help="Only run tests matching the backend NAME."
    )
