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


def build_ffi(module_prefix, modules, pre_include, post_include, libraries):
    """
    Modules listed in ``modules`` should have the following attributes:

    * ``INCLUDES``: A string containing C includes.
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
    ffi = cffi.FFI()
    types = []
    includes = []
    functions = []
    macros = []
    customizations = []
    for name in modules:
        module_name = module_prefix + name
        __import__(module_name)
        module = sys.modules[module_name]

        types.append(module.TYPES)
        macros.append(module.MACROS)
        functions.append(module.FUNCTIONS)
        includes.append(module.INCLUDES)
        customizations.append(module.CUSTOMIZATIONS)

    ffi.cdef("\n".join(types + functions + macros))

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
            [pre_include] +
            includes +
            [post_include] +
            functions +
            customizations
        ),
        libraries=libraries,
        ext_package="cryptography",
    )

    for name in modules:
        module_name = module_prefix + name
        module = sys.modules[module_name]
        for condition, names in module.CONDITIONAL_NAMES.items():
            if not getattr(lib, condition):
                for name in names:
                    delattr(lib, name)

    return ffi, lib
