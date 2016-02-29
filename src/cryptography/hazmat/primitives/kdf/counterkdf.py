# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import struct

import six

from cryptography import utils
from cryptography.exceptions import (
    AlreadyFinalized, InvalidKey, UnsupportedAlgorithm, _Reasons
)
from cryptography.hazmat.backends.interfaces import HMACBackend
from cryptography.hazmat.primitives import constant_time, hashes, hmac
from cryptography.hazmat.primitives.kdf import KeyDerivationFunction


@utils.register_interface(KeyDerivationFunction)
class CounterKDF(object):
    def __init__(self, algorithm, length, label, context, backend):
        if not isinstance(backend, HMACBackend):
            raise UnsupportedAlgorithm(
                "Backend object does not implement HMACBackend.",
                _Reasons.BACKEND_MISSING_INTERFACE
            )

        if not isinstance(algorithm, hashes.HashAlgorithm):
            raise UnsupportedAlgorithm(
                "Algorithm supplied is not a supported hash algorithm.",
                _Reasons.UNSUPPORTED_HASH
            )

        if label is None:
            label = b''

        if context is None:
            context = b''

        if not isinstance(label, bytes) \
                or not isinstance(context, bytes):
            raise TypeError('label and context must be of type bytes')

        self._algorithm = algorithm
        self._length = length
        self._label = label
        self._context = context
        self._backend = backend
        self._used = False
        self.fixed_data = None

    def derive(self, key_material):
        if self._used:
            raise AlreadyFinalized

        if not isinstance(key_material, bytes):
            raise TypeError('key_material must be bytes')
        self._used = True

        output = [b'']
        # inverse floor division (equivalent to ceiling)
        rounds = -(-self._length // self._algorithm.digest_size)

        # 8 is the length of an unsigned int used by struct.pack('>I', n)
        if rounds > pow(2, 8) - 1:
            raise ValueError('There are too many iterations.')

        for i in range(1, rounds + 1):
            h = hmac.HMAC(key_material, self._algorithm, backend=self._backend)
            h.update(struct.pack('>I', i))
            h.update(self.generate_fixed_input())
            output.append(h.finalize())

        return b''.join(output)[:self._length]

    def generate_fixed_input(self):
        """
        Combine the fixed data (label and context) to a binary string

        :return: binary string
        """
        if self.fixed_data and isinstance(self.fixed_data, bytes):
            # NIST's test vectors only supply Fixed input data
            return self.fixed_data

        fixed_input = list()
        fixed_input.append(self._label)
        fixed_input.append(six.int2byte(0))
        fixed_input.append(self._context)
        fixed_input.append(struct.pack('>I', self._length * 8))
        return b''.join(fixed_input)

    def verify(self, key_material, expected_key):
        if not constant_time.bytes_eq(self.derive(key_material), expected_key):
            raise InvalidKey
