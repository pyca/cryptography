import base64

from cryptography.fernet import Fernet


class TestFernet(object):
    def test_generate(self):
        f = Fernet(base64.urlsafe_b64decode(
            b"cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
        ))
        token = f._encrypt_from_parts(
            b"hello",
            499162800,
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
        )
        assert token == (b"gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM"
                          "4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==")

    def test_verify(self):
        f = Fernet(base64.urlsafe_b64decode(
            b"cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
        ))
        payload = f.decrypt(
            (b"gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dO"
              "PmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA=="),
            ttl=60,
            current_time=499162801
        )
        assert payload == b"hello"
