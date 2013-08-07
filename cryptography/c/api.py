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

import atexit
from collections import namedtuple

from cffi import FFI


class API(object):
    """OpenSSL API wrapper."""

    SSLVersion = namedtuple('SSLVersion',
        ['major', 'minor', 'fix', 'patch', 'status']
    )

    _modules = [
        'asn1',
        'bio',
        'bio_filter',
        'bio_sink',
        'err',
        'evp',
        'evp_md',
        'evp_cipher',
        'evp_cipher_listing',
        'hmac',
        'obj',
        'openssl',
        'nid',
        'pkcs5',
        'rand',
        'ssl',
        'ssleay',
        'stdio',
    ]

    def __init__(self):
        self.ffi = FFI()
        self.INCLUDES = []
        self.TYPES = []
        self.FUNCTIONS = []
        self.C_CUSTOMIZATION = []
        self.OVERRIDES = []
        self.SETUP = []
        self.TEARDOWN = []
        self._import()
        self._define()
        self._verify()
        self._override()
        self._populate()
        self._initialise()

    def _import(self):
        "import all library definitions"
        for name in self._modules:
            module = __import__(__name__ + '.' + name, fromlist=['*'])
            self._import_definitions(module, 'INCLUDES')
            self._import_definitions(module, 'TYPES')
            self._import_definitions(module, 'FUNCTIONS')
            self._import_definitions(module, 'C_CUSTOMIZATION')
            self._import_definitions(module, 'OVERRIDES')
            self._import_definitions(module, 'SETUP')
            self._import_definitions(module, 'TEARDOWN')

    def _import_definitions(self, module, name):
        "import defintions named definitions from module"
        container = getattr(self, name)
        for definition in getattr(module, name, ()):
            if definition not in container:
                container.append(definition)

    def _define(self):
        "parse function definitions"
        for typedef in self.TYPES:
            self.ffi.cdef(typedef)
        for function in self.FUNCTIONS:
            self.ffi.cdef(function)

    def _verify(self):
        "load openssl, create function attributes"
        self.openssl = self.ffi.verify(
            source="\n".join(self.INCLUDES + self.C_CUSTOMIZATION),
            # ext_package must agree with the value in setup.py
            ext_package="tls",
            extra_compile_args=[
                '-Wno-deprecated-declarations',
            ],
            libraries=['ssl']
        )

    def _override(self):
        """
        Create any Python-level overrides of the cffi-based wrappers.
        """
        self._overrides = {}
        for func in self.OVERRIDES:
            name = func.__name__
            from_openssl = getattr(self.openssl, name)
            override = func(self.openssl, from_openssl)
            self._overrides[name] = override

    def _populate(self):
        """
        Bind some aliases for FFI APIs on self.
        """
        self.NULL = self.ffi.NULL
        self.buffer = self.ffi.buffer
        self.callback = self.ffi.callback
        self.cast = self.ffi.cast
        self.new = self.ffi.new
        self.gc = self.ffi.gc
        self.string = self.ffi.string

    def __getattr__(self, name):
        """
        Try to resolve any attribute that does not exist on self as an
        attribute of the OpenSSL FFI object (in other words, as an OpenSSL
        API).
        """
        return self._overrides.get(name, getattr(self.openssl, name))

    def _initialise(self):
        "initialise openssl, schedule cleanup at exit"
        for function in self.SETUP:
            getattr(self, function)()
        for function in self.TEARDOWN:
            atexit.register(getattr(self, function))

    def version_info(self):
        "Return SSL version information"
        version = self.SSLeay()
        major = version >> (7 * 4) & 0xFF
        minor = version >> (5 * 4) & 0xFF
        fix = version >> (3 * 4) & 0xFF
        patch = version >> (1 * 4) & 0xFF
        patch = '' if not patch else chr(96 + patch)
        status = version & 0x0F
        if status == 0x0F:
            status = 'release'
        elif status == 0x00:
            status = 'dev'
        else:
            status = 'beta{}'.format(status)
        return self.SSLVersion(major, minor, fix, patch, status)

    def version(self, detail=None):
        "Return SSL version string"
        detail = self.SSLEAY_VERSION if detail is None else detail
        buff = self.SSLeay_version(detail)
        return self.string(buff)


api = API()
