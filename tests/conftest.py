import pytest

from cryptography.hazmat.backends import _ALL_BACKENDS
from cryptography.hazmat.backends.interfaces import (
    HMACBackend, CipherBackend, HashBackend, PBKDF2HMACBackend
)

from .utils import check_for_iface, check_backend_support, select_backends


def pytest_generate_tests(metafunc):
    names = metafunc.config.getoption("--backend")
    selected_backends = select_backends(names, _ALL_BACKENDS)

    if "backend" in metafunc.fixturenames:
        metafunc.parametrize("backend", selected_backends)


@pytest.mark.trylast
def pytest_runtest_setup(item):
    check_for_iface("hmac", HMACBackend, item)
    check_for_iface("cipher", CipherBackend, item)
    check_for_iface("hash", HashBackend, item)
    check_for_iface("pbkdf2hmac", PBKDF2HMACBackend, item)
    check_backend_support(item)


def pytest_addoption(parser):
    parser.addoption(
        "--backend", action="store", metavar="NAME",
        help="Only run tests matching the backend NAME."
    )
