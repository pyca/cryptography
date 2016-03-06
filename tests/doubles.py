# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import CipherAlgorithm
from cryptography.hazmat.primitives.ciphers.modes import Mode


@utils.register_interface(CipherAlgorithm)
class DummyCipherAlgorithm(object):
    name = "dummy-cipher"
    block_size = 128
    key_size = None


@utils.register_interface(Mode)
class DummyMode(object):
    name = "dummy-mode"

    def validate_for_algorithm(self, algorithm):
        pass


@utils.register_interface(hashes.HashAlgorithm)
class DummyHashAlgorithm(object):
    name = "dummy-hash"
    block_size = None
    digest_size = None


@utils.register_interface(serialization.KeySerializationEncryption)
class DummyKeySerializationEncryption(object):
    pass


@utils.register_interface(padding.AsymmetricPadding)
class DummyAsymmetricPadding(object):
    name = "dummy-padding"
