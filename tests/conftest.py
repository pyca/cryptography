import sys

import pytest

from cryptography.hazmat.backends.interfaces import (
    HMACBackend, CipherBackend, HashBackend
)

from .utils import check_for_iface


def pytest_generate_tests(metafunc):
    from cryptography.hazmat.backends import _ALL_BACKENDS

    if "backend" in metafunc.fixturenames:
        metafunc.parametrize("backend", _ALL_BACKENDS)


@pytest.mark.trylast
def pytest_runtest_setup(item):
    check_for_iface("hmac", HMACBackend, item)
    check_for_iface("cipher", CipherBackend, item)
    check_for_iface("hash", HashBackend, item)
    if ('commoncrypto' in item.keywords and
            item.funcargs.get('backend') is not None and
            not sys.platform == 'darwin'):
        pytest.skip('CommonCrypto is only available on OS X')
