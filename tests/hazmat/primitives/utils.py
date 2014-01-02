import binascii
import os

import pytest

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.exceptions import (
    AlreadyFinalized, NotYetFinalized, AlreadyUpdated, InvalidTag,
)

from ...utils import load_vectors_from_file


def _load_all_params(path, file_names, param_loader):
    all_params = []
    for file_name in file_names:
        all_params.extend(
            load_vectors_from_file(os.path.join(path, file_name), param_loader)
        )
    return all_params


def generate_encrypt_test(param_loader, path, file_names, cipher_factory,
                          mode_factory):
    all_params = _load_all_params(path, file_names, param_loader)

    @pytest.mark.parametrize("params", all_params)
    def test_encryption(self, backend, params):
        encrypt_test(backend, cipher_factory, mode_factory, params)

    return test_encryption


def encrypt_test(backend, cipher_factory, mode_factory, params):
    plaintext = params["plaintext"]
    ciphertext = params["ciphertext"]
    cipher = Cipher(
        cipher_factory(**params),
        mode_factory(**params),
        backend=backend
    )
    encryptor = cipher.encryptor()
    actual_ciphertext = encryptor.update(binascii.unhexlify(plaintext))
    actual_ciphertext += encryptor.finalize()
    assert actual_ciphertext == binascii.unhexlify(ciphertext)
    decryptor = cipher.decryptor()
    actual_plaintext = decryptor.update(binascii.unhexlify(ciphertext))
    actual_plaintext += decryptor.finalize()
    assert actual_plaintext == binascii.unhexlify(plaintext)


def generate_aead_test(param_loader, path, file_names, cipher_factory,
                       mode_factory):
    all_params = _load_all_params(path, file_names, param_loader)

    @pytest.mark.parametrize("params", all_params)
    def test_aead(self, backend, params):
        aead_test(backend, cipher_factory, mode_factory, params)

    return test_aead


def aead_test(backend, cipher_factory, mode_factory, params):
    if params.get("pt") is not None:
        plaintext = params["pt"]
    ciphertext = params["ct"]
    aad = params["aad"]
    if params.get("fail") is True:
        cipher = Cipher(
            cipher_factory(binascii.unhexlify(params["key"])),
            mode_factory(binascii.unhexlify(params["iv"]),
                         binascii.unhexlify(params["tag"])),
            backend
        )
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(binascii.unhexlify(aad))
        actual_plaintext = decryptor.update(binascii.unhexlify(ciphertext))
        with pytest.raises(InvalidTag):
            decryptor.finalize()
    else:
        cipher = Cipher(
            cipher_factory(binascii.unhexlify(params["key"])),
            mode_factory(binascii.unhexlify(params["iv"]), None),
            backend
        )
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(binascii.unhexlify(aad))
        actual_ciphertext = encryptor.update(binascii.unhexlify(plaintext))
        actual_ciphertext += encryptor.finalize()
        tag_len = len(params["tag"])
        assert binascii.hexlify(encryptor.tag)[:tag_len] == params["tag"]
        cipher = Cipher(
            cipher_factory(binascii.unhexlify(params["key"])),
            mode_factory(binascii.unhexlify(params["iv"]),
                         binascii.unhexlify(params["tag"])),
            backend
        )
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(binascii.unhexlify(aad))
        actual_plaintext = decryptor.update(binascii.unhexlify(ciphertext))
        actual_plaintext += decryptor.finalize()
        assert actual_plaintext == binascii.unhexlify(plaintext)


def generate_stream_encryption_test(param_loader, path, file_names,
                                    cipher_factory):
    all_params = _load_all_params(path, file_names, param_loader)

    @pytest.mark.parametrize("params", all_params)
    def test_stream_encryption(self, backend, params):
        stream_encryption_test(backend, cipher_factory, params)
    return test_stream_encryption


def stream_encryption_test(backend, cipher_factory, params):
    plaintext = params["plaintext"]
    ciphertext = params["ciphertext"]
    offset = params["offset"]
    cipher = Cipher(cipher_factory(**params), None, backend=backend)
    encryptor = cipher.encryptor()
    # throw away offset bytes
    encryptor.update(b"\x00" * int(offset))
    actual_ciphertext = encryptor.update(binascii.unhexlify(plaintext))
    actual_ciphertext += encryptor.finalize()
    assert actual_ciphertext == binascii.unhexlify(ciphertext)
    decryptor = cipher.decryptor()
    decryptor.update(b"\x00" * int(offset))
    actual_plaintext = decryptor.update(binascii.unhexlify(ciphertext))
    actual_plaintext += decryptor.finalize()
    assert actual_plaintext == binascii.unhexlify(plaintext)


def generate_hash_test(param_loader, path, file_names, hash_cls):
    all_params = _load_all_params(path, file_names, param_loader)

    @pytest.mark.parametrize("params", all_params)
    def test_hash(self, backend, params):
        hash_test(backend, hash_cls, params)
    return test_hash


def hash_test(backend, algorithm, params):
    msg = params[0]
    md = params[1]
    m = hashes.Hash(algorithm, backend=backend)
    m.update(binascii.unhexlify(msg))
    expected_md = md.replace(" ", "").lower().encode("ascii")
    assert m.finalize() == binascii.unhexlify(expected_md)


def generate_base_hash_test(algorithm, digest_size, block_size):
    def test_base_hash(self, backend):
        base_hash_test(backend, algorithm, digest_size, block_size)
    return test_base_hash


def base_hash_test(backend, algorithm, digest_size, block_size):
    m = hashes.Hash(algorithm, backend=backend)
    assert m.algorithm.digest_size == digest_size
    assert m.algorithm.block_size == block_size
    m_copy = m.copy()
    assert m != m_copy
    assert m._ctx != m_copy._ctx

    m.update(b"abc")
    copy = m.copy()
    copy.update(b"123")
    m.update(b"123")
    assert copy.finalize() == m.finalize()


def generate_long_string_hash_test(hash_factory, md):
    def test_long_string_hash(self, backend):
        long_string_hash_test(backend, hash_factory, md)
    return test_long_string_hash


def long_string_hash_test(backend, algorithm, md):
    m = hashes.Hash(algorithm, backend=backend)
    m.update(b"a" * 1000000)
    assert m.finalize() == binascii.unhexlify(md.lower().encode("ascii"))


def generate_base_hmac_test(hash_cls):
    def test_base_hmac(self, backend):
        base_hmac_test(backend, hash_cls)
    return test_base_hmac


def base_hmac_test(backend, algorithm):
    key = b"ab"
    h = hmac.HMAC(binascii.unhexlify(key), algorithm, backend=backend)
    h_copy = h.copy()
    assert h != h_copy
    assert h._ctx != h_copy._ctx


def generate_hmac_test(param_loader, path, file_names, algorithm):
    all_params = _load_all_params(path, file_names, param_loader)

    @pytest.mark.parametrize("params", all_params)
    def test_hmac(self, backend, params):
        hmac_test(backend, algorithm, params)
    return test_hmac


def hmac_test(backend, algorithm, params):
    msg = params[0]
    md = params[1]
    key = params[2]
    h = hmac.HMAC(binascii.unhexlify(key), algorithm, backend=backend)
    h.update(binascii.unhexlify(msg))
    assert h.finalize() == binascii.unhexlify(md.encode("ascii"))


def generate_aead_exception_test(cipher_factory, mode_factory):
    def test_aead_exception(self, backend):
        aead_exception_test(backend, cipher_factory, mode_factory)
    return test_aead_exception


def aead_exception_test(backend, cipher_factory, mode_factory):
    cipher = Cipher(
        cipher_factory(binascii.unhexlify(b"0" * 32)),
        mode_factory(binascii.unhexlify(b"0" * 24)),
        backend
    )
    encryptor = cipher.encryptor()
    encryptor.update(b"a" * 16)
    with pytest.raises(NotYetFinalized):
        encryptor.tag
    with pytest.raises(AlreadyUpdated):
        encryptor.authenticate_additional_data(b"b" * 16)
    encryptor.finalize()
    with pytest.raises(AlreadyFinalized):
        encryptor.authenticate_additional_data(b"b" * 16)
    with pytest.raises(AlreadyFinalized):
        encryptor.update(b"b" * 16)
    with pytest.raises(AlreadyFinalized):
        encryptor.finalize()
    cipher = Cipher(
        cipher_factory(binascii.unhexlify(b"0" * 32)),
        mode_factory(binascii.unhexlify(b"0" * 24), b"0" * 16),
        backend
    )
    decryptor = cipher.decryptor()
    decryptor.update(b"a" * 16)
    with pytest.raises(AttributeError):
        decryptor.tag


def generate_aead_tag_exception_test(cipher_factory, mode_factory):
    def test_aead_tag_exception(self, backend):
        aead_tag_exception_test(backend, cipher_factory, mode_factory)
    return test_aead_tag_exception


def aead_tag_exception_test(backend, cipher_factory, mode_factory):
    cipher = Cipher(
        cipher_factory(binascii.unhexlify(b"0" * 32)),
        mode_factory(binascii.unhexlify(b"0" * 24)),
        backend
    )
    with pytest.raises(ValueError):
        cipher.decryptor()

    with pytest.raises(ValueError):
        mode_factory(binascii.unhexlify(b"0" * 24), b"000")

    cipher = Cipher(
        cipher_factory(binascii.unhexlify(b"0" * 32)),
        mode_factory(binascii.unhexlify(b"0" * 24), b"0" * 16),
        backend
    )
    with pytest.raises(ValueError):
        cipher.encryptor()
