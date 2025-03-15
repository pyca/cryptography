# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import sys
import threading

import pytest

from cryptography.exceptions import AlreadyFinalized
from cryptography.hazmat.primitives import padding

from .utils import SwitchIntervalContext, run_threaded

IS_PYPY = sys.implementation.name == "pypy"


class TestPKCS7:
    @pytest.mark.parametrize("size", [127, 4096, -2])
    def test_invalid_block_size(self, size):
        with pytest.raises(ValueError):
            padding.PKCS7(size)

    @pytest.mark.parametrize(
        ("size", "padded"),
        [
            (128, b"1111"),
            (128, b"1111111111111111"),
            (128, b"111111111111111\x06"),
            (128, b""),
            (128, b"\x06" * 6),
            (128, b"\x00" * 16),
        ],
    )
    def test_invalid_padding(self, size, padded):
        unpadder = padding.PKCS7(size).unpadder()
        with pytest.raises(ValueError):
            unpadder.update(padded)
            unpadder.finalize()

    def test_non_bytes(self):
        padder = padding.PKCS7(128).padder()
        with pytest.raises(TypeError):
            padder.update("abc")  # type: ignore[arg-type]
        unpadder = padding.PKCS7(128).unpadder()
        with pytest.raises(TypeError):
            unpadder.update("abc")  # type: ignore[arg-type]

    def test_zany_py2_bytes_subclass(self):
        class mybytes(bytes):  # noqa: N801
            def __str__(self):
                return "broken"

        str(mybytes())
        padder = padding.PKCS7(128).padder()
        data = padder.update(mybytes(b"abc")) + padder.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadder.update(mybytes(data))
        assert unpadder.finalize() == b"abc"

    @pytest.mark.parametrize(
        ("size", "unpadded", "padded"),
        [
            (128, b"1111111111", b"1111111111\x06\x06\x06\x06\x06\x06"),
            (
                128,
                b"111111111111111122222222222222",
                b"111111111111111122222222222222\x02\x02",
            ),
            (128, b"1" * 16, b"1" * 16 + b"\x10" * 16),
            (128, b"1" * 17, b"1" * 17 + b"\x0f" * 15),
        ],
    )
    def test_pad(self, size, unpadded, padded):
        padder = padding.PKCS7(size).padder()
        result = padder.update(unpadded)
        result += padder.finalize()
        assert result == padded

    @pytest.mark.parametrize(
        ("size", "unpadded", "padded"),
        [
            (128, b"1111111111", b"1111111111\x06\x06\x06\x06\x06\x06"),
            (
                128,
                b"111111111111111122222222222222",
                b"111111111111111122222222222222\x02\x02",
            ),
            (128, b"1" * 16, b"1" * 16 + b"\x10" * 16),
            (128, b"1" * 17, b"1" * 17 + b"\x0f" * 15),
        ],
    )
    def test_unpad(self, size, unpadded, padded):
        unpadder = padding.PKCS7(size).unpadder()
        result = unpadder.update(padded)
        result += unpadder.finalize()
        assert result == unpadded

    def test_use_after_finalize(self):
        padder = padding.PKCS7(128).padder()
        b = padder.finalize()
        with pytest.raises(AlreadyFinalized):
            padder.update(b"")
        with pytest.raises(AlreadyFinalized):
            padder.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadder.update(b)
        unpadder.finalize()
        with pytest.raises(AlreadyFinalized):
            unpadder.update(b"")
        with pytest.raises(AlreadyFinalized):
            unpadder.finalize()

    def test_large_padding(self):
        padder = padding.PKCS7(2040).padder()
        padded_data = padder.update(b"")
        padded_data += padder.finalize()

        for i in padded_data:
            assert i == 255

        unpadder = padding.PKCS7(2040).unpadder()
        data = unpadder.update(padded_data)
        data += unpadder.finalize()

        assert data == b""

    def test_bytearray(self):
        padder = padding.PKCS7(128).padder()
        unpadded = bytearray(b"t" * 38)
        padded = (
            padder.update(unpadded)
            + padder.update(unpadded)
            + padder.finalize()
        )
        unpadder = padding.PKCS7(128).unpadder()
        final = unpadder.update(padded) + unpadder.finalize()
        assert final == unpadded + unpadded

    def test_block_size_padding(self):
        padder = padding.PKCS7(64).padder()
        data = padder.update(b"a" * 8) + padder.finalize()
        assert data == b"a" * 8 + b"\x08" * 8


class TestANSIX923:
    @pytest.mark.parametrize("size", [127, 4096, -2])
    def test_invalid_block_size(self, size):
        with pytest.raises(ValueError):
            padding.ANSIX923(size)

    @pytest.mark.parametrize(
        ("size", "padded"),
        [
            (128, b"1111"),
            (128, b"1111111111111111"),
            (128, b"111111111111111\x06"),
            (128, b"1111111111\x06\x06\x06\x06\x06\x06"),
            (128, b""),
            (128, b"\x06" * 6),
            (128, b"\x00" * 16),
        ],
    )
    def test_invalid_padding(self, size, padded):
        unpadder = padding.ANSIX923(size).unpadder()
        with pytest.raises(ValueError):
            unpadder.update(padded)
            unpadder.finalize()

    def test_non_bytes(self):
        padder = padding.ANSIX923(128).padder()
        with pytest.raises(TypeError):
            padder.update("abc")  # type: ignore[arg-type]
        unpadder = padding.ANSIX923(128).unpadder()
        with pytest.raises(TypeError):
            unpadder.update("abc")  # type: ignore[arg-type]

    def test_zany_py2_bytes_subclass(self):
        class mybytes(bytes):  # noqa: N801
            def __str__(self):
                return "broken"

        str(mybytes())
        padder = padding.ANSIX923(128).padder()
        data = padder.update(mybytes(b"abc")) + padder.finalize()
        unpadder = padding.ANSIX923(128).unpadder()
        unpadder.update(mybytes(data))
        assert unpadder.finalize() == b"abc"

    @pytest.mark.parametrize(
        ("size", "unpadded", "padded"),
        [
            (128, b"1111111111", b"1111111111\x00\x00\x00\x00\x00\x06"),
            (
                128,
                b"111111111111111122222222222222",
                b"111111111111111122222222222222\x00\x02",
            ),
            (128, b"1" * 16, b"1" * 16 + b"\x00" * 15 + b"\x10"),
            (128, b"1" * 17, b"1" * 17 + b"\x00" * 14 + b"\x0f"),
        ],
    )
    def test_pad(self, size, unpadded, padded):
        padder = padding.ANSIX923(size).padder()
        result = padder.update(unpadded)
        result += padder.finalize()
        assert result == padded

    @pytest.mark.parametrize(
        ("size", "unpadded", "padded"),
        [
            (128, b"1111111111", b"1111111111\x00\x00\x00\x00\x00\x06"),
            (
                128,
                b"111111111111111122222222222222",
                b"111111111111111122222222222222\x00\x02",
            ),
        ],
    )
    def test_unpad(self, size, unpadded, padded):
        unpadder = padding.ANSIX923(size).unpadder()
        result = unpadder.update(padded)
        result += unpadder.finalize()
        assert result == unpadded

    def test_use_after_finalize(self):
        padder = padding.ANSIX923(128).padder()
        b = padder.finalize()
        with pytest.raises(AlreadyFinalized):
            padder.update(b"")
        with pytest.raises(AlreadyFinalized):
            padder.finalize()

        unpadder = padding.ANSIX923(128).unpadder()
        unpadder.update(b)
        unpadder.finalize()
        with pytest.raises(AlreadyFinalized):
            unpadder.update(b"")
        with pytest.raises(AlreadyFinalized):
            unpadder.finalize()

    def test_bytearray(self):
        padder = padding.ANSIX923(128).padder()
        unpadded = bytearray(b"t" * 38)
        padded = (
            padder.update(unpadded)
            + padder.update(unpadded)
            + padder.finalize()
        )
        unpadder = padding.ANSIX923(128).unpadder()
        final = unpadder.update(padded) + unpadder.finalize()
        assert final == unpadded + unpadded

    def test_block_size_padding(self):
        padder = padding.ANSIX923(64).padder()
        data = padder.update(b"a" * 8) + padder.finalize()
        assert data == b"a" * 8 + b"\x00" * 7 + b"\x08"


@SwitchIntervalContext(0.0000001)
@pytest.mark.parametrize(
    "algorithm",
    [
        padding.PKCS7,
        padding.ANSIX923,
    ],
)
def test_multithreaded_padding(algorithm):
    num_threads = 4
    chunk = b"abcd1234"
    data = chunk * 2048
    block_size = 1024  # in bits

    padder = algorithm(block_size).padder()
    validate_padder = algorithm(block_size).padder()
    expected_pad = validate_padder.update(data * num_threads)
    expected_pad += validate_padder.finalize()
    calculated_pad = b""

    b = threading.Barrier(num_threads)
    lock = threading.Lock()

    def pad_in_chunks(chunk_size):
        nonlocal calculated_pad
        index = 0
        b.wait()
        while index < len(data):
            new_content = padder.update(data[index : index + chunk_size])
            if sys.version_info < (3, 10) or IS_PYPY:
                # appending to a bytestring is racey on some Python versions
                lock.acquire()
                calculated_pad += new_content
                lock.release()
            else:
                calculated_pad += new_content
            index += chunk_size

    def prepare_args(threadnum):
        chunk_size = len(data) // (2**threadnum)
        assert chunk_size > 0
        assert chunk_size % len(chunk) == 0
        return (chunk_size,)

    run_threaded(num_threads, pad_in_chunks, prepare_args)

    calculated_pad += padder.finalize()
    assert expected_pad == calculated_pad


@SwitchIntervalContext(0.0000001)
@pytest.mark.parametrize(
    "algorithm, padding_bytes",
    [(padding.PKCS7, b"\x04" * 4), (padding.ANSIX923, b"\x00" * 3 + b"\x04")],
)
def test_multithreaded_unpadding(algorithm, padding_bytes):
    num_threads = 4
    num_repeats = 1000
    chunk = b"abcd"
    block = chunk + padding_bytes

    padder = algorithm(len(block) * 8).unpadder()
    validate_padder = algorithm(len(block) * 8).unpadder()
    expected_unpadded_message = b""
    for _ in range(num_threads * num_repeats):
        expected_unpadded_message += validate_padder.update(block)
    expected_unpadded_message += validate_padder.finalize()
    calculated_unpadded_message = b""

    b = threading.Barrier(num_threads)
    lock = threading.Lock()

    def unpad_in_chunks():
        nonlocal calculated_unpadded_message
        index = 0
        b.wait()
        while index < num_repeats:
            new_content = padder.update(block)
            if sys.version_info < (3, 10) or IS_PYPY:
                # appending to a bytestring is racey on 3.9 and older
                lock.acquire()
                calculated_unpadded_message += new_content
                lock.release()
            else:
                calculated_unpadded_message += new_content
            index += 1

    run_threaded(num_threads, unpad_in_chunks, lambda x: tuple())

    calculated_unpadded_message += padder.finalize()
    assert expected_unpadded_message == calculated_unpadded_message
