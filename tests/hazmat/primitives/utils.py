import binascii
import os

import pytest

from cryptography.hazmat.bindings import _ALL_BACKENDS
from cryptography.hazmat.primitives.block import BlockCipher


def generate_encrypt_test(param_loader, path, file_names, cipher_factory,
                          mode_factory, only_if=lambda backend: True,
                          skip_message=None):
    def test_encryption(self):
        for backend in _ALL_BACKENDS:
            for file_name in file_names:
                for params in param_loader(os.path.join(path, file_name)):
                    yield (
                        encrypt_test,
                        backend,
                        cipher_factory,
                        mode_factory,
                        params,
                        only_if,
                        skip_message
                    )
    return test_encryption


def encrypt_test(backend, cipher_factory, mode_factory, params, only_if,
                 skip_message):
    if not only_if(backend):
        pytest.skip(skip_message)
    plaintext = params.pop("plaintext")
    ciphertext = params.pop("ciphertext")
    cipher = BlockCipher(
        cipher_factory(**params),
        mode_factory(**params),
        backend
    )
    encryptor = cipher.encryptor()
    actual_ciphertext = encryptor.update(binascii.unhexlify(plaintext))
    actual_ciphertext += encryptor.finalize()
    assert actual_ciphertext == binascii.unhexlify(ciphertext)
    decryptor = cipher.decryptor()
    actual_plaintext = decryptor.update(binascii.unhexlify(ciphertext))
    actual_plaintext += decryptor.finalize()
    assert actual_plaintext == binascii.unhexlify(plaintext)


def generate_hash_test(param_loader, path, file_names, hash_cls,
                       only_if=None, skip_message=None):
    def test_hash(self):
        for backend in _ALL_BACKENDS:
            for file_name in file_names:
                for params in param_loader(os.path.join(path, file_name)):
                    yield (
                        hash_test,
                        backend,
                        hash_cls,
                        params,
                        only_if,
                        skip_message
                    )
    return test_hash


def hash_test(backend, hash_cls, params, only_if, skip_message):
    if only_if is not None and not only_if(backend):
        pytest.skip(skip_message)
    msg = params[0]
    md = params[1]
    m = hash_cls(backend=backend)
    m.update(binascii.unhexlify(msg))
    assert m.hexdigest() == md.replace(" ", "").lower()
    digst = hash_cls(backend=backend, data=binascii.unhexlify(msg)).hexdigest()
    assert digst == md.replace(" ", "").lower()


def generate_base_hash_test(hash_cls, digest_size, block_size,
                            only_if=None, skip_message=None):
    def test_base_hash(self):
        for backend in _ALL_BACKENDS:
            yield (
                base_hash_test,
                backend,
                hash_cls,
                digest_size,
                block_size,
                only_if,
                skip_message,
            )
    return test_base_hash


def base_hash_test(backend, hash_cls, digest_size, block_size, only_if,
                   skip_message):
    if only_if is not None and not only_if(backend):
        pytest.skip(skip_message)
    m = hash_cls(backend=backend)
    assert m.digest_size == digest_size
    assert m.block_size == block_size
    m_copy = m.copy()
    assert m != m_copy
    assert m._ctx != m_copy._ctx


def generate_long_string_hash_test(hash_factory, md, only_if=None,
                                   skip_message=None):
    def test_long_string_hash(self):
        for backend in _ALL_BACKENDS:
            yield(
                long_string_hash_test,
                backend,
                hash_factory,
                md,
                only_if,
                skip_message
            )
    return test_long_string_hash


def long_string_hash_test(backend, hash_factory, md, only_if, skip_message):
    if only_if is not None and not only_if(backend):
        pytest.skip(skip_message)
    m = hash_factory(backend=backend)
    m.update(b"a" * 1000000)
    assert m.hexdigest() == md.lower()
