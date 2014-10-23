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

from .utils import check_backend_support, select_backends


def pytest_generate_tests(metafunc):
    names = metafunc.config.getoption("--backend")
    selected_backends = select_backends(names, _available_backends())

    if "backend" in metafunc.fixturenames:
        metafunc.parametrize("backend", selected_backends)


@pytest.mark.trylast
def pytest_runtest_setup(item):
    required = item.keywords.get("requires_backend_interface")
    if required is not None and "backend" in item.funcargs:
        required_interfaces = tuple(
            kwargs["interface"] for args, kwargs in required._arglist
        )
        if not isinstance(item.funcargs["backend"], required_interfaces):
            pytest.skip("{0} backend does not support {1}".format(
                item.funcargs["backend"],
                ", ".join(iface.__name__ for iface in required_interfaces)
            ))

    check_backend_support(item)


def pytest_addoption(parser):
    parser.addoption(
        "--backend", action="store", metavar="NAME",
        help="Only run tests matching the backend NAME."
    )
