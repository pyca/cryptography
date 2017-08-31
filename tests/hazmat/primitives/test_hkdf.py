# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii

import pytest

from cryptography.exceptions import (
    AlreadyFinalized, InvalidKey, _Reasons
)
from cryptography.hazmat.backends.interfaces import HMACBackend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from ...utils import raises_unsupported_algorithm


@pytest.mark.requires_backend_interface(interface=HMACBackend)
class TestHKDF(object):
    def test_length_limit(self, backend):
        big_length = 255 * (hashes.SHA256().digest_size // 8) + 1

        with pytest.raises(ValueError):
            HKDF(
                hashes.SHA256(),
                big_length,
                salt=None,
                info=None,
                backend=backend
            )

    def test_already_finalized(self, backend):
        hkdf = HKDF(
            hashes.SHA256(),
            16,
            salt=None,
            info=None,
            backend=backend
        )

        hkdf.derive(b"\x01" * 16)

        with pytest.raises(AlreadyFinalized):
            hkdf.derive(b"\x02" * 16)

        hkdf = HKDF(
            hashes.SHA256(),
            16,
            salt=None,
            info=None,
            backend=backend
        )

        hkdf.verify(b"\x01" * 16, b"gJ\xfb{\xb1Oi\xc5sMC\xb7\xe4@\xf7u")

        with pytest.raises(AlreadyFinalized):
            hkdf.verify(b"\x02" * 16, b"gJ\xfb{\xb1Oi\xc5sMC\xb7\xe4@\xf7u")

        hkdf = HKDF(
            hashes.SHA256(),
            16,
            salt=None,
            info=None,
            backend=backend
        )

    def test_verify(self, backend):
        hkdf = HKDF(
            hashes.SHA256(),
            16,
            salt=None,
            info=None,
            backend=backend
        )

        hkdf.verify(b"\x01" * 16, b"gJ\xfb{\xb1Oi\xc5sMC\xb7\xe4@\xf7u")

    def test_verify_invalid(self, backend):
        hkdf = HKDF(
            hashes.SHA256(),
            16,
            salt=None,
            info=None,
            backend=backend
        )

        with pytest.raises(InvalidKey):
            hkdf.verify(b"\x02" * 16, b"gJ\xfb{\xb1Oi\xc5sMC\xb7\xe4@\xf7u")

    def test_unicode_typeerror(self, backend):
        with pytest.raises(TypeError):
            HKDF(
                hashes.SHA256(),
                16,
                salt=u"foo",
                info=None,
                backend=backend
            )

        with pytest.raises(TypeError):
            HKDF(
                hashes.SHA256(),
                16,
                salt=None,
                info=u"foo",
                backend=backend
            )

        with pytest.raises(TypeError):
            hkdf = HKDF(
                hashes.SHA256(),
                16,
                salt=None,
                info=None,
                backend=backend
            )

            hkdf.derive(u"foo")

        with pytest.raises(TypeError):
            hkdf = HKDF(
                hashes.SHA256(),
                16,
                salt=None,
                info=None,
                backend=backend
            )

            hkdf.verify(u"foo", b"bar")

        with pytest.raises(TypeError):
            hkdf = HKDF(
                hashes.SHA256(),
                16,
                salt=None,
                info=None,
                backend=backend
            )

            hkdf.verify(b"foo", u"bar")

    def test_derive_short_output(self, backend):
        hkdf = HKDF(
            hashes.SHA256(),
            4,
            salt=None,
            info=None,
            backend=backend
        )

        assert hkdf.derive(b"\x01" * 16) == b"gJ\xfb{"


@pytest.mark.requires_backend_interface(interface=HMACBackend)
class TestHKDFExpand(object):
    def test_derive(self, backend):
        prk = binascii.unhexlify(
            b"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        )

        okm = (b"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c"
               b"5bf34007208d5b887185865")

        info = binascii.unhexlify(b"f0f1f2f3f4f5f6f7f8f9")
        hkdf = HKDFExpand(hashes.SHA256(), 42, info, backend)

        assert binascii.hexlify(hkdf.derive(prk)) == okm

    def test_verify(self, backend):
        prk = binascii.unhexlify(
            b"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        )

        okm = (b"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c"
               b"5bf34007208d5b887185865")

        info = binascii.unhexlify(b"f0f1f2f3f4f5f6f7f8f9")
        hkdf = HKDFExpand(hashes.SHA256(), 42, info, backend)

        assert hkdf.verify(prk, binascii.unhexlify(okm)) is None

    def test_invalid_verify(self, backend):
        prk = binascii.unhexlify(
            b"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        )

        info = binascii.unhexlify(b"f0f1f2f3f4f5f6f7f8f9")
        hkdf = HKDFExpand(hashes.SHA256(), 42, info, backend)

        with pytest.raises(InvalidKey):
            hkdf.verify(prk, b"wrong key")

    def test_already_finalized(self, backend):
        info = binascii.unhexlify(b"f0f1f2f3f4f5f6f7f8f9")
        hkdf = HKDFExpand(hashes.SHA256(), 42, info, backend)

        hkdf.derive(b"first")

        with pytest.raises(AlreadyFinalized):
            hkdf.derive(b"second")

    def test_unicode_error(self, backend):
        info = binascii.unhexlify(b"f0f1f2f3f4f5f6f7f8f9")
        hkdf = HKDFExpand(hashes.SHA256(), 42, info, backend)

        with pytest.raises(TypeError):
            hkdf.derive(u"first")


def test_invalid_backend():
    pretend_backend = object()

    with raises_unsupported_algorithm(_Reasons.BACKEND_MISSING_INTERFACE):
        HKDF(hashes.SHA256(), 16, None, None, pretend_backend)

    with raises_unsupported_algorithm(_Reasons.BACKEND_MISSING_INTERFACE):
        HKDFExpand(hashes.SHA256(), 16, None, pretend_backend)
