import binascii
import os

import pytest

from cryptography.bindings import _ALL_APIS
from cryptography.primitives.block import BlockCipher


def generate_encrypt_test(param_loader, path, file_names, cipher_factory,
                          mode_factory, only_if=lambda api: True):
    def test_encryption(self):
        for api in _ALL_APIS:
            if not only_if(api):
                yield encrypt_skipped
            else:
                for file_name in file_names:
                    for params in param_loader(os.path.join(path, file_name)):
                        yield encrypt_test, api, cipher_factory, mode_factory, params
    return test_encryption


def encrypt_test(api, cipher_factory, mode_factory, params):
    plaintext = params.pop("plaintext")
    ciphertext = params.pop("ciphertext")
    cipher = BlockCipher(
        cipher_factory(**params),
        mode_factory(**params),
        api
    )
    actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
    actual_ciphertext += cipher.finalize()
    assert binascii.hexlify(actual_ciphertext) == ciphertext


def encrypt_skipped():
    pytest.skip("because reasons")
