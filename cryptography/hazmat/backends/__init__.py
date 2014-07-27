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

import pkg_resources

from cryptography.hazmat.backends.multibackend import MultiBackend


_available_backends_list = None


def _available_backends():
    global _available_backends_list

    if _available_backends_list is None:
        _available_backends_list = []

        for backend in pkg_resources.iter_entry_points(
            "cryptography.hazmat.backends"
        ):
            is_backend_available = pkg_resources.get_entry_info(
                backend.dist,
                "cryptography.hazmat.is_backend_available",
                backend.name
            )

            if is_backend_available is not None:
                is_backend_available = is_backend_available.load(require=False)
                if not is_backend_available():
                    continue

            _available_backends_list.append(backend.load(require=False))

    return _available_backends_list

_default_backend = None


def default_backend():
    global _default_backend

    if _default_backend is None:
        _default_backend = MultiBackend(_available_backends())

    return _default_backend
