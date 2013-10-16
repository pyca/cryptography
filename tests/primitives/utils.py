import binascii
import os

import pytest

from cryptography.bindings import _ALL_APIS
from cryptography.primitives.block import BlockCipher


def generate_encrypt_test(param_loader, path, file_names, cipher_factory,
                          mode_factory, only_if=lambda api: True,
                          skip_message=None):
    def test_encryption(self):
        for api in _ALL_APIS:
            for file_name in file_names:
                for params in param_loader(os.path.join(path, file_name)):
                    yield (
                        encrypt_test,
                        api,
                        cipher_factory,
                        mode_factory,
                        params,
                        only_if,
                        skip_message
                    )
    return test_encryption


def encrypt_test(api, cipher_factory, mode_factory, params, only_if,
                 skip_message):
    if not only_if(api):
        pytest.skip(skip_message)
    plaintext = params.pop("plaintext")
    ciphertext = params.pop("ciphertext")
    cipher = BlockCipher(
        cipher_factory(**params),
        mode_factory(**params),
        api
    )
    actual_ciphertext = cipher.encrypt(binascii.unhexlify(plaintext))
    actual_ciphertext += cipher.finalize()
    assert actual_ciphertext == binascii.unhexlify(ciphertext)
