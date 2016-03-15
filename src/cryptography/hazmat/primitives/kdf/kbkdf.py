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
class KBKDF(object):
    COUNTER_MODE = 'ctr'

    LOCATION_BEFORE_FIXED = 'before_fixed'
    LOCATION_AFTER_FIXED = 'after_fixed'

    def __init__(self, algorithm, mode, length, rlen,
                 location, label, context, backend):
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

        if mode is None:
            mode = KBKDF.COUNTER_MODE

        if location is None:
            location = KBKDF.LOCATION_BEFORE_FIXED

        if rlen is None:
            rlen = 8

        if label is None:
            label = b''

        if context is None:
            context = b''

        if not isinstance(label, bytes) \
                or not isinstance(context, bytes):
            raise TypeError('label and context must be of type bytes')

        if rlen not in [1, 2, 4]:
            raise ValueError('rlen must be 2, 4 or 8')

        self._algorithm = algorithm
        self._mode = mode
        self._length = length
        self._rlen = rlen
        self._location = location
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

        struct_frmt = '>I'
        if self._rlen == 1:
            struct_frmt = '>B'
        if self._rlen == 2:
            struct_frmt = '>H'

        for i in range(1, rounds + 1):
            h = hmac.HMAC(key_material, self._algorithm, backend=self._backend)
            if self._location == KBKDF.LOCATION_BEFORE_FIXED:
                h.update(struct.pack(struct_frmt, i))

            h.update(self.generate_fixed_input())

            if self._location == KBKDF.LOCATION_AFTER_FIXED:
                h.update(struct.pack(struct_frmt, i))
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
