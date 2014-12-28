# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.hazmat.primitives import interfaces


def _check_iv_length(self, algorithm):
    if len(self.initialization_vector) * 8 != algorithm.block_size:
        raise ValueError("Invalid IV size ({0}) for {1}.".format(
            len(self.initialization_vector), self.name
        ))


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
class CBC(object):
    name = "CBC"

    def __init__(self, initialization_vector):
        self._initialization_vector = initialization_vector

    initialization_vector = utils.read_only_property("_initialization_vector")
    validate_for_algorithm = _check_iv_length


@utils.register_interface(interfaces.Mode)
class ECB(object):
    name = "ECB"

    def validate_for_algorithm(self, algorithm):
        pass


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
class OFB(object):
    name = "OFB"

    def __init__(self, initialization_vector):
        self._initialization_vector = initialization_vector

    initialization_vector = utils.read_only_property("_initialization_vector")
    validate_for_algorithm = _check_iv_length


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
class CFB(object):
    name = "CFB"

    def __init__(self, initialization_vector):
        self._initialization_vector = initialization_vector

    initialization_vector = utils.read_only_property("_initialization_vector")
    validate_for_algorithm = _check_iv_length


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
class CFB8(object):
    name = "CFB8"

    def __init__(self, initialization_vector):
        self._initialization_vector = initialization_vector

    initialization_vector = utils.read_only_property("_initialization_vector")
    validate_for_algorithm = _check_iv_length


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithNonce)
class CTR(object):
    name = "CTR"

    def __init__(self, nonce):
        self._nonce = nonce

    nonce = utils.read_only_property("_nonce")

    def validate_for_algorithm(self, algorithm):
        if len(self.nonce) * 8 != algorithm.block_size:
            raise ValueError("Invalid nonce size ({0}) for {1}.".format(
                len(self.nonce), self.name
            ))


@utils.register_interface(interfaces.Mode)
@utils.register_interface(interfaces.ModeWithInitializationVector)
@utils.register_interface(interfaces.ModeWithAuthenticationTag)
class GCM(object):
    name = "GCM"

    def __init__(self, initialization_vector, tag=None, min_tag_length=16):
        # len(initialization_vector) must in [1, 2 ** 64), but it's impossible
        # to actually construct a bytes object that large, so we don't check
        # for it
        if min_tag_length < 4:
            raise ValueError("min_tag_length must be >= 4")
        if tag is not None and len(tag) < min_tag_length:
            raise ValueError(
                "Authentication tag must be {0} bytes or longer.".format(
                    min_tag_length)
            )

        self._initialization_vector = initialization_vector
        self._tag = tag

    tag = utils.read_only_property("_tag")
    initialization_vector = utils.read_only_property("_initialization_vector")

    def validate_for_algorithm(self, algorithm):
        pass
