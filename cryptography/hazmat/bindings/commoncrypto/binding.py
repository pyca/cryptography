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

import platform

from pkg_resources import parse_version

from cryptography.hazmat.bindings.utils import build_ffi


class Binding(object):
    """
    CommonCrypto API wrapper.
    """
    _module_prefix = "cryptography.hazmat.bindings.commoncrypto."
    _modules = [
        "common_digest",
        "common_hmac",
        "common_key_derivation",
        "common_cryptor",
    ]

    ffi = None
    lib = None

    def __init__(self):
        self._ensure_ffi_initialized()

    @classmethod
    def _ensure_ffi_initialized(cls):
        if cls.ffi is not None and cls.lib is not None:
            return

        cls.ffi, cls.lib = build_ffi(cls._module_prefix, cls._modules,
                                     "", "", [])

    @classmethod
    def is_available(cls):
        version = parse_version(platform.mac_ver()[0])
        return version >= parse_version("10.8")
