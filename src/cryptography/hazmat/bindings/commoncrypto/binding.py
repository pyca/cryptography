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

from cryptography.hazmat.bindings.utils import (
    build_ffi_for_binding, load_library_for_binding,
)


class Binding(object):
    """
    CommonCrypto API wrapper.
    """
    _module_prefix = "cryptography.hazmat.bindings.commoncrypto."
    _modules = [
        "cf",
        "common_digest",
        "common_hmac",
        "common_key_derivation",
        "common_cryptor",
        "secimport",
        "secitem",
        "seckey",
        "seckeychain",
        "sectransform",
    ]

    ffi = build_ffi_for_binding(
        module_prefix=_module_prefix,
        modules=_modules,
        extra_link_args=[
            "-framework", "Security", "-framework", "CoreFoundation"
        ],
    )
    lib = None

    def __init__(self):
        self._ensure_ffi_initialized()

    @classmethod
    def _ensure_ffi_initialized(cls):
        if cls.lib is not None:
            return

        cls.lib = load_library_for_binding(
            cls.ffi,
            module_prefix=cls._module_prefix,
            modules=cls._modules,
        )
