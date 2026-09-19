# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import cryptography
from cryptography.exceptions import InternalError
from cryptography.hazmat.bindings import _rust
from cryptography.hazmat.bindings._rust import openssl


def _openssl_assert(ok: bool) -> None:
    if not ok:
        errors = openssl.capture_error_stack()

        raise InternalError(
            "Unknown OpenSSL error. This error is commonly encountered when "
            "another library is not cleaning up the OpenSSL error stack. If "
            "you are using cryptography with another library that uses "
            "OpenSSL try disabling it before reporting a bug. Otherwise "
            "please file an issue at https://github.com/pyca/cryptography/"
            "issues with information on how to reproduce "
            f"this. ({errors!r})",
            errors,
        )


def _verify_package_version(version: str) -> None:
    if version != _rust._PACKAGE_VERSION:
        raise ImportError(
            "The version of cryptography does not match the loaded shared "
            "object. Check for multiple installations in your Python path. "
            f"Loaded Python version: {version}, "
            f"shared object version: {_rust._PACKAGE_VERSION}"
        )


_verify_package_version(cryptography.__version__)
