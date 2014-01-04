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


def build_ffi(modules, module_prefix, verify_kwargs):
    ffi = cffi.FFI()
    includes = []
    functions = []
    macros = []
    customizations = []
    for name in modules:
        module_name = module_prefix + name
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
    lib = ffi.verify(**verify_kwargs(includes, functions, customizations))

    for name in modules:
        module_name = module_prefix + name
        module = sys.modules[module_name]
        for condition, names in module.CONDITIONAL_NAMES.items():
            if not getattr(lib, condition):
                for name in names:
                    delattr(lib, name)

    return ffi, lib
