# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import sys
from distutils.ccompiler import new_compiler
from distutils.dist import Distribution

from cffi import FFI


def build_ffi_for_binding(module_name, module_prefix, modules, libraries=[],
                          extra_compile_args=[], extra_link_args=[]):
    """
    Modules listed in ``modules`` should have the following attributes:

    * ``INCLUDES``: A string containing C includes.
    * ``TYPES``: A string containing C declarations for types.
    * ``FUNCTIONS``: A string containing C declarations for functions & macros.
    * ``CUSTOMIZATIONS``: A string containing arbitrary top-level C code, this
        can be used to do things like test for a define and provide an
        alternate implementation based on that.
    """
    types = []
    includes = []
    functions = []
    customizations = []
    for name in modules:
        __import__(module_prefix + name)
        module = sys.modules[module_prefix + name]

        types.append(module.TYPES)
        functions.append(module.FUNCTIONS)
        includes.append(module.INCLUDES)
        customizations.append(module.CUSTOMIZATIONS)

    verify_source = "\n".join(
        includes +
        customizations
    )
    ffi = build_ffi(
        module_name,
        cdef_source="\n".join(types + functions),
        verify_source=verify_source,
        libraries=libraries,
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
    )

    return ffi


def build_ffi(module_name, cdef_source, verify_source, libraries=[],
              extra_compile_args=[], extra_link_args=[]):
    ffi = FFI()
    ffi.cdef(cdef_source)
    ffi.set_source(
        module_name,
        verify_source,
        libraries=libraries,
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
    )
    return ffi


def extra_link_args(compiler_type):
    if compiler_type == 'msvc':
        # Enable NX and ASLR for Windows builds on MSVC. These are enabled by
        # default on Python 3.3+ but not on 2.x.
        return ['/NXCOMPAT', '/DYNAMICBASE']
    else:
        return []


def compiler_type():
    """
    Gets the compiler type from distutils. On Windows with MSVC it will be
    "msvc". On macOS and linux it is "unix".
    """
    dist = Distribution()
    dist.parse_config_files()
    cmd = dist.get_command_obj('build')
    cmd.ensure_finalized()
    compiler = new_compiler(compiler=cmd.compiler)
    return compiler.compiler_type
