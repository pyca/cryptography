import base64

import six

from cryptography.fernet import Fernet


class TestFernet(object):
    def test_generate(self):
        f = Fernet(base64.urlsafe_b64decode(
            b"cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
        ))
        token = f._encrypt_from_parts(
            b"hello",
            499162800,
            b"".join(map(six.int2byte, range(16))),
        )
        assert token == (b"gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM"
                         b"4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==")

    def test_verify(self):
        f = Fernet(base64.urlsafe_b64decode(
            b"cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
        ))
        payload = f.decrypt(
            (b"gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dO"
             b"PmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA=="),
            ttl=60,
            current_time=499162801
        )
        assert payload == b"hello"
