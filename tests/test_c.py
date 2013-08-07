from cryptography.c import api


class TestC(object):
    def test_api_exists(self):
        assert api
