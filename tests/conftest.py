# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography.hazmat.backends import _available_backends
from cryptography.hazmat.backends.interfaces import (
    CMACBackend, CipherBackend, DSABackend, EllipticCurveBackend, HMACBackend,
    HashBackend, PBKDF2HMACBackend, PKCS8SerializationBackend, RSABackend,
    TraditionalOpenSSLSerializationBackend
)
from .utils import check_backend_support, check_for_iface, select_backends


def pytest_generate_tests(metafunc):
    names = metafunc.config.getoption("--backend")
    selected_backends = select_backends(names, _available_backends())

    if "backend" in metafunc.fixturenames:
        metafunc.parametrize("backend", selected_backends)


@pytest.mark.trylast
def pytest_runtest_setup(item):
    check_for_iface("hmac", HMACBackend, item)
    check_for_iface("cipher", CipherBackend, item)
    check_for_iface("cmac", CMACBackend, item)
    check_for_iface("hash", HashBackend, item)
    check_for_iface("pbkdf2hmac", PBKDF2HMACBackend, item)
    check_for_iface("dsa", DSABackend, item)
    check_for_iface("rsa", RSABackend, item)
    check_for_iface(
        "traditional_openssl_serialization",
        TraditionalOpenSSLSerializationBackend,
        item
    )
    check_for_iface("pkcs8_serialization", PKCS8SerializationBackend, item)
    check_for_iface("elliptic", EllipticCurveBackend, item)
    check_backend_support(item)


def pytest_addoption(parser):
    parser.addoption(
        "--backend", action="store", metavar="NAME",
        help="Only run tests matching the backend NAME."
    )
