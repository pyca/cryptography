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


def generate_hash_test(param_loader, path, file_names, hash_cls,
                       only_if=lambda api: True, skip_message=None):
    def test_hash(self):
        for api in _ALL_APIS:
            for file_name in file_names:
                for params in param_loader(os.path.join(path, file_name)):
                    yield (
                        hash_test,
                        api,
                        hash_cls,
                        params,
                        only_if,
                        skip_message
                    )
    return test_hash


def hash_test(api, hash_cls, params, only_if, skip_message):
    if not only_if(api):
        pytest.skip(skip_message)
    msg = params[0]
    md = params[1]
    m = hash_cls(api=api)
    m.update(binascii.unhexlify(msg))
    assert m.hexdigest() == md.replace(" ", "").lower()


def generate_base_hash_test(hash_cls, digest_size, block_size,
                            only_if=lambda api: True, skip_message=None):
    def test_base_hash(self):
        for api in _ALL_APIS:
            yield (
                base_hash_test,
                api,
                hash_cls,
                digest_size,
                block_size,
                only_if,
                skip_message,
            )
    return test_base_hash


def base_hash_test(api, hash_cls, digest_size, block_size, only_if,
                   skip_message):
    if not only_if(api):
        pytest.skip(skip_message)
    m = hash_cls(api=api)
    assert m.digest_size == digest_size
    assert m.block_size == block_size
    m_copy = m.copy()
    assert m != m_copy
    assert m._ctx != m_copy._ctx
