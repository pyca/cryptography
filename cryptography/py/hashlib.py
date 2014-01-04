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

import six

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, interfaces


class Hashlib(object):
    def __init__(self, backend):
        algorithms = {}

        for hash_class in _find_supported_hash_algorithms(backend):
            hashlib_class = _new_hashlib_adapter(hash_class, backend)
            setattr(self, hash_class.name, hashlib_class)

            algorithms[hash_class.name] = hashlib_class

        self._algorithm_map = algorithms
        self.algorithms = tuple(algorithms.keys())

    def new(self, name, string=None):
        try:
            return self._algorithm_map[name.lower()](string)
        except KeyError:
            raise ValueError("unsupported hash type {0}".format(name))


class HashlibHashAdapter(object):
    def __init__(self, arg=None, _context=None):
        self._lock = threading.Lock()

        self.digest_size = self._algorithm_class.digest_size
        self.block_size = self._algorithm_class.block_size

        if _context is None:
            self._context = hashes.Hash(self._algorithm_class(), self._backend)
        else:
            self._context = _context

        if arg is not None:
            self.update(arg)

    def update(self, arg):
        if isinstance(arg, six.text_type):
            arg = arg.encode()
        elif isinstance(arg, array.array):
            arg = arg.tostring()

        with self._lock:
            self._context.update(arg)

    def digest(self):
        with self._lock:
            return self._context.copy().finalize()

    def hexdigest(self):
        return binascii.hexlify(self.digest())

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
