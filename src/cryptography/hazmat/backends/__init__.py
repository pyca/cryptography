# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import typing

from cryptography.hazmat.backends.interfaces import Backend

_default_backend: typing.Optional[Backend] = None


def default_backend() -> Backend:
    global _default_backend

    if _default_backend is None:
        from cryptography.hazmat.backends.openssl.backend import backend

        _default_backend = backend

    return _default_backend


def _get_backend(backend: typing.Optional[Backend]) -> Backend:
    if backend is None:
        return default_backend()
    else:
        return backend
