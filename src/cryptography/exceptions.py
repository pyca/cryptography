# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function


class _Reasons(object):
    BACKEND_MISSING_INTERFACE = object()
    UNSUPPORTED_HASH = object()
    UNSUPPORTED_CIPHER = object()
    UNSUPPORTED_PADDING = object()
    UNSUPPORTED_MGF = object()
    UNSUPPORTED_PUBLIC_KEY_ALGORITHM = object()
    UNSUPPORTED_ELLIPTIC_CURVE = object()
    UNSUPPORTED_SERIALIZATION = object()
    UNSUPPORTED_X509 = object()


class UnsupportedAlgorithm(Exception):
    def __init__(self, message, reason=None):
        super(UnsupportedAlgorithm, self).__init__(message)
        self._reason = reason


class AlreadyFinalized(Exception):
    pass


class AlreadyUpdated(Exception):
    pass


class NotYetFinalized(Exception):
    pass


class InvalidTag(Exception):
    pass


class InvalidSignature(Exception):
    pass


class InternalError(Exception):
    pass


class InvalidKey(Exception):
    pass


class InvalidToken(Exception):
    pass
