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

import array
import binascii
import inspect
import threading
import hashlib as python_hashlib

import six

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, interfaces

# Python will always provide these for us

_algorithms_guaranteed = {
    "md5": python_hashlib.md5,
    "sha1": python_hashlib.sha1,
    "sha224": python_hashlib.sha224,
    "sha256": python_hashlib.sha256,
    "sha384": python_hashlib.sha384,
    "sha512": python_hashlib.sha512,
}

_notset = object()


class _Hashlib(object):
    def __init__(self, backend, python_algorithms):
        algorithms = {}

        # Add the implementations in our backend, we'll fall back to the
        # Python implementations if the backend doesn't provide the guaranteed
        # ones.

        for hash_class in _find_supported_hash_algorithms(backend):
            hashlib_class = _new_hashlib_adapter(hash_class, backend)
            algorithms[hash_class.name.lower()] = hashlib_class
            algorithms[hash_class.name.upper()] = hashlib_class

        # Make sure the ones with attributes point at the right implementations

        for name in _algorithms_guaranteed:
            setattr(self, name, algorithms[name])

        self._algorithm_map = algorithms

    def new(self, name, string=_notset):
        try:
            return self._algorithm_map[name](string)
        except KeyError:
            if string is _notset:
                return python_hashlib.new(name)
            else:
                return python_hashlib.new(name, string)


class _Hashlib2(_Hashlib):
    def __init__(self, backend):
        super(_Hashlib2, self).__init__(
            backend,
            getattr(python_hashlib, "algorithms",
                    _algorithms_guaranteed.keys())
        )
        self.algorithms = tuple(self._algorithm_map.keys())


class _Hashlib3(_Hashlib):
    def __init__(self, backend):
        # Python 3 provides some weird ones, such as "dsaEncryption"
        super(_Hashlib3, self).__init__(backend,
                                        python_hashlib.algorithms_available)

        self.algorithms_guaranteed = python_hashlib.algorithms_guaranteed
        self.algorithms_available = set(self._algorithm_map.keys())


if six.PY2:
    # Python 2 hashlib API
    Hashlib = _Hashlib2
    _buffer = getattr(six.moves.builtins, "buffer")
else:
    # Python 3 hashlib API
    Hashlib = _Hashlib3
    _buffer = getattr(six.moves.builtins, "memoryview")


class HashlibHashAdapter(object):
    def __init__(self, arg=_notset, _context=None):
        self._lock = threading.Lock()

        self.digest_size = self._algorithm_class.digest_size
        self.block_size = self._algorithm_class.block_size

        if _context is None:
            self._context = hashes.Hash(self._algorithm_class(), self._backend)
        else:
            self._context = _context

        if arg is not _notset:
            self.update(arg)

    def update(self, arg):
        if six.PY2 and isinstance(arg, six.text_type):
            arg = arg.encode()
        elif isinstance(arg, array.array):
            if six.PY2:
                arg = arg.tostring()
            else:
                arg = arg.tobytes()
        elif isinstance(arg, _buffer):
            arg = six.binary_type(arg)

        if not isinstance(arg, six.binary_type):
            raise TypeError("must be string or buffer, not {0}".format(arg))

        with self._lock:
            self._context.update(arg)

    def digest(self):
        with self._lock:
            return self._context.copy().finalize()

    def hexdigest(self):
        return str(binascii.hexlify(self.digest()).decode())

    def copy(self):
        with self._lock:
            return type(self)(_context=self._context.copy())


def _new_hashlib_adapter(hash_class, backend):
    return type(
        hash_class.name,
        (HashlibHashAdapter,),
        {
            "_algorithm_class": hash_class,
            "_backend": backend
        }
    )


def _find_supported_hash_algorithms(backend):
    for name, klass in inspect.getmembers(hashes):
        if (
            inspect.isclass(klass) and
            issubclass(klass, interfaces.HashAlgorithm)
        ):
            try:
                hashes.Hash(klass(), backend)
            except UnsupportedAlgorithm:
                continue
            else:
                yield klass
