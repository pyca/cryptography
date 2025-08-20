# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import pytest

from cryptography.hazmat.bindings._rust import _openssl, pyopenssl


class TestContext:
    def test_create(self):
        for method in [
            pyopenssl.SSLv23_METHOD,
            pyopenssl.TLSv1_METHOD,
            pyopenssl.TLSv1_1_METHOD,
            pyopenssl.TLSv1_2_METHOD,
            pyopenssl.TLS_METHOD,
            pyopenssl.TLS_SERVER_METHOD,
            pyopenssl.TLS_CLIENT_METHOD,
            pyopenssl.DTLS_METHOD,
            pyopenssl.DTLS_SERVER_METHOD,
            pyopenssl.DTLS_CLIENT_METHOD,
        ]:
            ctx = pyopenssl.Context(method)
            assert ctx

        with pytest.raises(TypeError):
            pyopenssl.Context(object())  # type: ignore[arg-type]

        with pytest.raises(ValueError):
            pyopenssl.Context(12324213)

    def test__context(self):
        ctx = pyopenssl.Context(pyopenssl.TLS_METHOD)
        assert ctx._context
        assert _openssl.ffi.typeof(ctx._context).cname == "SSL_CTX *"
        assert _openssl.ffi.cast("uintptr_t", ctx._context) > 0
