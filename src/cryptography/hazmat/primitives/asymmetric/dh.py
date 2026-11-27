# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

from cryptography import utils
from cryptography.hazmat.decrepit.asymmetric import dh as _decrepit_dh

_FFDH_DEPRECATION_MSG = (
    "Diffie-Hellman over finite fields (FFDH) is deprecated and has been "
    "moved to cryptography.hazmat.decrepit.asymmetric.dh. Starting in "
    "53.0.0 it will only be available from that module."
)

# Every name is taken from the decrepit module directly (rather than from a
# module-level alias) because each ``utils.deprecated`` call replaces the
# module attribute it names, so a later call reading that attribute would
# wrap the deprecation marker instead of the underlying object.
utils.deprecated(
    _decrepit_dh.generate_parameters,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn51,
    name="generate_parameters",
)

utils.deprecated(
    _decrepit_dh.DHPrivateNumbers,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn51,
    name="DHPrivateNumbers",
)

utils.deprecated(
    _decrepit_dh.DHPublicNumbers,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn51,
    name="DHPublicNumbers",
)

utils.deprecated(
    _decrepit_dh.DHParameterNumbers,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn51,
    name="DHParameterNumbers",
)

utils.deprecated(
    _decrepit_dh.DHParameters,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn51,
    name="DHParameters",
)

utils.deprecated(
    _decrepit_dh.DHParameters,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn51,
    name="DHParametersWithSerialization",
)

utils.deprecated(
    _decrepit_dh.DHPublicKey,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn51,
    name="DHPublicKey",
)

utils.deprecated(
    _decrepit_dh.DHPublicKey,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn51,
    name="DHPublicKeyWithSerialization",
)

utils.deprecated(
    _decrepit_dh.DHPrivateKey,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn51,
    name="DHPrivateKey",
)

utils.deprecated(
    _decrepit_dh.DHPrivateKey,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn51,
    name="DHPrivateKeyWithSerialization",
)
