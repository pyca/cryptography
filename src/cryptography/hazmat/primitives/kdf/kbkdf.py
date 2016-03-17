# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii
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

    def __init__(self, algorithm, mode, length, rlen, llen,
                 location, label, context, fixed, backend):
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

        if (label or context) and fixed:
            raise ValueError("When supplying fixed data, "
                             "label and context is ignored.")

        if mode is None:
            mode = KBKDF.COUNTER_MODE

        if location is None:
            location = KBKDF.LOCATION_BEFORE_FIXED

        if rlen is None:
            rlen = 4

        if llen is None:
            llen = 4

        if label is None:
            label = b''

        if context is None:
            context = b''

        if not isinstance(label, bytes) \
                or not isinstance(context, bytes):
            raise TypeError('label and context must be of type bytes')

        if not self._valid_byte_length(rlen):
            raise ValueError('rlen must be between 1 and 4')

        if not self._valid_byte_length(llen):
            raise ValueError('llen must be between 1 and 4')

        self._algorithm = algorithm
        self._mode = mode
        self._length = length
        self._rlen = rlen
        self._llen = llen
        self._location = location
        self._label = label
        self._context = context
        self._backend = backend
        self._used = False
        self._fixed_data = fixed

    def _valid_byte_length(self, value):
        if not isinstance(value, int):
            raise TypeError('value must be of type int')

        if not 1 <= value <= 4:
            return False
        return True

    def _int_as_binary_representation(self, length, value):
        if not self._valid_byte_length(length):
            raise ValueError('binary length must be between 1 and 4')

        if length == 1:
            return struct.pack(">B", value)
        elif length == 2:
            return struct.pack(">H", value)
        elif length == 3:
            return struct.pack(">L", value)[1:]
        else:
            return struct.pack(">L", value)

    def derive(self, key_material):
        if self._used:
            raise AlreadyFinalized

        if not isinstance(key_material, bytes):
            raise TypeError('key_material must be bytes')
        self._used = True

        # inverse floor division (equivalent to ceiling)
        rounds = -(-self._length // self._algorithm.digest_size)

        output = [b'']
        r_bin_len = self._int_as_binary_representation(self._rlen, 1)
        r_bin_rep = binascii.hexlify(r_bin_len)
        if rounds > pow(2, min(len(r_bin_rep), 32)) - 1:
            raise ValueError('There are too many iterations.')

        for i in range(1, rounds + 1):
            h = hmac.HMAC(key_material, self._algorithm, backend=self._backend)
            counter = self._int_as_binary_representation(self._rlen, i)
            if self._location == KBKDF.LOCATION_BEFORE_FIXED:
                h.update(counter)

            h.update(self._generate_fixed_input())

            if self._location == KBKDF.LOCATION_AFTER_FIXED:
                h.update(counter)

            output.append(h.finalize())

        return b''.join(output)[:self._length]

    def _generate_fixed_input(self):
        """
        Combine the fixed data (label and context) to a binary string

        :return: binary string
        """
        if self._fixed_data and isinstance(self._fixed_data, bytes):
            # NIST's test vectors are only supply Fixed input data
            return self._fixed_data

        l = self._int_as_binary_representation(self._llen, self._length * 8)

        fixed_input = list()
        fixed_input.append(self._label)
        fixed_input.append(six.int2byte(0))
        fixed_input.append(self._context)
        fixed_input.append(l)
        return b''.join(fixed_input)

    def verify(self, key_material, expected_key):
        if not constant_time.bytes_eq(self.derive(key_material), expected_key):
            raise InvalidKey
