import binascii
import os

import pytest

from cryptography.hazmat.bindings import _ALL_BACKENDS
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher


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
    cipher = Cipher(
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


def hash_test(backend, algorithm, params, only_if, skip_message):
    if only_if is not None and not only_if(backend):
        pytest.skip(skip_message)
    msg = params[0]
    md = params[1]
    m = hashes.Hash(algorithm, backend=backend)
    m.update(binascii.unhexlify(msg))
    expected_md = md.replace(" ", "").lower().encode("ascii")
    assert m.finalize() == binascii.unhexlify(expected_md)


def generate_base_hash_test(algorithm, digest_size, block_size,
                            only_if=None, skip_message=None):
    def test_base_hash(self):
        for backend in _ALL_BACKENDS:
            yield (
                base_hash_test,
                backend,
                algorithm,
                digest_size,
                block_size,
                only_if,
                skip_message,
            )
    return test_base_hash


def base_hash_test(backend, algorithm, digest_size, block_size, only_if,
                   skip_message):
    if only_if is not None and not only_if(backend):
        pytest.skip(skip_message)

    m = hashes.Hash(algorithm, backend=backend)
    assert m.algorithm.digest_size == digest_size
    assert m.algorithm.block_size == block_size
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


def long_string_hash_test(backend, algorithm, md, only_if, skip_message):
    if only_if is not None and not only_if(backend):
        pytest.skip(skip_message)
    m = hashes.Hash(algorithm, backend=backend)
    m.update(b"a" * 1000000)
    assert m.finalize() == binascii.unhexlify(md.lower().encode("ascii"))


def generate_hmac_test(param_loader, path, file_names, algorithm,
                       only_if=None, skip_message=None):
    def test_hmac(self):
        for backend in _ALL_BACKENDS:
            for file_name in file_names:
                for params in param_loader(os.path.join(path, file_name)):
                    yield (
                        hmac_test,
                        backend,
                        algorithm,
                        params,
                        only_if,
                        skip_message
                    )
    return test_hmac


def hmac_test(backend, algorithm, params, only_if, skip_message):
    if only_if is not None and not only_if(backend):
        pytest.skip(skip_message)
    msg = params[0]
    md = params[1]
    key = params[2]
    h = hmac.HMAC(binascii.unhexlify(key), algorithm)
    h.update(binascii.unhexlify(msg))
    assert h.finalize() == binascii.unhexlify(md.encode("ascii"))


def generate_base_hmac_test(hash_cls, only_if=None, skip_message=None):
    def test_base_hmac(self):
        for backend in _ALL_BACKENDS:
            yield (
                base_hmac_test,
                backend,
                hash_cls,
                only_if,
                skip_message,
            )
    return test_base_hmac


def base_hmac_test(backend, algorithm, only_if, skip_message):
    if only_if is not None and not only_if(backend):
        pytest.skip(skip_message)
    key = b"ab"
    h = hmac.HMAC(binascii.unhexlify(key), algorithm)
    h_copy = h.copy()
    assert h != h_copy
    assert h._ctx != h_copy._ctx
