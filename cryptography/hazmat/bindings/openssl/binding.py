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

import sys

import cffi

_OSX_PRE_INCLUDE = """
#ifdef __APPLE__
#include <AvailabilityMacros.h>
#define __ORIG_DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER \
    DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#undef DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#define DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#endif
"""

_OSX_POST_INCLUDE = """
#ifdef __APPLE__
#undef DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#define DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER \
    __ORIG_DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#endif
"""


class Binding(object):
    """
    OpenSSL API wrapper.

    Modules listed in the ``_modules`` listed should have the following
    attributes:

    * ``INCLUDES``: A string containg C includes.
    * ``TYPES``: A string containing C declarations for types.
    * ``FUNCTIONS``: A string containing C declarations for functions.
    * ``MACROS``: A string containing C declarations for any macros.
    * ``CUSTOMIZATIONS``: A string containing arbitrary top-level C code, this
        can be used to do things like test for a define and provide an
        alternate implementation based on that.
    * ``CONDITIONAL_NAMES``: A dict mapping strings of condition names from the
        library to a list of names which will not be present without the
        condition.
    """
    _module_prefix = "cryptography.hazmat.bindings.openssl."
    _modules = [
        "asn1",
        "bignum",
        "bio",
        "conf",
        "crypto",
        "dh",
        "dsa",
        "engine",
        "err",
        "evp",
        "hmac",
        "nid",
        "objects",
        "opensslv",
        "osrand_engine",
        "pem",
        "pkcs7",
        "pkcs12",
        "rand",
        "rsa",
        "ssl",
        "x509",
        "x509name",
        "x509v3",
    ]

    ffi = None
    lib = None

    def __init__(self):
        self._ensure_ffi_initialized()

    @classmethod
    def _ensure_ffi_initialized(cls):
        if cls.ffi is not None and cls.lib is not None:
            return

        ffi = cffi.FFI()
        includes = []
        functions = []
        macros = []
        customizations = []
        for name in cls._modules:
            module_name = cls._module_prefix + name
            __import__(module_name)
            module = sys.modules[module_name]

            ffi.cdef(module.TYPES)

            macros.append(module.MACROS)
            functions.append(module.FUNCTIONS)
            includes.append(module.INCLUDES)
            customizations.append(module.CUSTOMIZATIONS)

        # loop over the functions & macros after declaring all the types
        # so we can set interdependent types in different files and still
        # have them all defined before we parse the funcs & macros
        for func in functions:
            ffi.cdef(func)
        for macro in macros:
            ffi.cdef(macro)

        # We include functions here so that if we got any of their definitions
        # wrong, the underlying C compiler will explode. In C you are allowed
        # to re-declare a function if it has the same signature. That is:
        #   int foo(int);
        #   int foo(int);
        # is legal, but the following will fail to compile:
        #   int foo(int);
        #   int foo(short);

        lib = ffi.verify(
            source="\n".join(
                [_OSX_PRE_INCLUDE] +
                includes +
                [_OSX_POST_INCLUDE] +
                functions +
                customizations
            ),
            libraries=["crypto", "ssl"],
        )

        for name in cls._modules:
            module_name = cls._module_prefix + name
            module = sys.modules[module_name]
            for condition, names in module.CONDITIONAL_NAMES.items():
                if not getattr(lib, condition):
                    for name in names:
                        delattr(lib, name)

        res = lib.Cryptography_add_osrandom_engine()
        assert res == 1

        cls.ffi = ffi
        cls.lib = lib
