# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function


class _GCMSizeValidator(object):
    """
    GCM may only encrypt up to 2**39 - 256 bits of plaintext, so we
    must track the number of bytes we see.
    """
    _PLAINTEXT_BYTE_LIMIT = (2 ** 39 - 256) / 8
    _AAD_BYTE_LIMIT = (2 ** 64) / 8

    def __init__(self):
        self._plaintext_len = 0

    def update_and_validate_plaintext(self, data):
        self._plaintext_len += len(data)
        self.validate_plaintext_len()

    def validate_plaintext_len(self):
        # Technically a size of 0 is invalid, but there are a couple hacks
        # around some things that call update(b"") on a newly initialized
        # CipherContext, and we can't interfere with that.
        # Also size 0 plaintext shouldn't produce any output so I don't
        # think we need to worry about it.
        if (self._plaintext_len < 0 or
                self._plaintext_len > self._PLAINTEXT_BYTE_LIMIT):
            raise ValueError("Exceeded GCM mode plaintext byte limit.")

    def validate_aad(self, data):
        return self.validate_aad_len(len(data))

    def validate_aad_len(self, datalen):
        if datalen < 0 or datalen > self._AAD_BYTE_LIMIT:
            raise ValueError("Exceeded GCM mode AAD byte limit.")
