# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 Radim Rehurek <me@radimrehurek.com>
#
# This code is distributed under the terms and conditions
# from the MIT License (MIT).
#
import io
import random
import unittest

import smart_open.bytebuffer


CHUNK_SIZE = 1024


def int2byte(i):
    return bytes((i, ))


def random_byte_string(length=CHUNK_SIZE):
    rand_bytes = [int2byte(random.randint(0, 255)) for _ in range(length)]
    return b''.join(rand_bytes)


def bytebuffer_and_random_contents():
    buf = smart_open.bytebuffer.ByteBuffer(CHUNK_SIZE)
    contents = random_byte_string(CHUNK_SIZE)
    content_reader = io.BytesIO(contents)
    buf.fill(content_reader)

    return [buf, contents]


class ByteBufferTest(unittest.TestCase):
    def test_len(self):
        buf = smart_open.bytebuffer.ByteBuffer(CHUNK_SIZE)
        self.assertEqual(len(buf), 0)

        contents = b'foo bar baz'
        buf._bytes = contents
        self.assertEqual(len(buf), len(contents))

        pos = 4
        buf._pos = pos
        self.assertEqual(len(buf), len(contents) - pos)

    def test_fill_from_reader(self):
        buf = smart_open.bytebuffer.ByteBuffer(CHUNK_SIZE)
        contents = random_byte_string(CHUNK_SIZE)
        content_reader = io.BytesIO(contents)

        bytes_filled = buf.fill(content_reader)
        self.assertEqual(bytes_filled, CHUNK_SIZE)
        self.assertEqual(len(buf), CHUNK_SIZE)
        self.assertEqual(buf._bytes, contents)

    def test_fill_from_iterable(self):
        buf = smart_open.bytebuffer.ByteBuffer(CHUNK_SIZE)
        contents = random_byte_string(CHUNK_SIZE)
        contents_iter = (contents[i:i+8] for i in range(0, CHUNK_SIZE, 8))

        bytes_filled = buf.fill(contents_iter)
        self.assertEqual(bytes_filled, CHUNK_SIZE)
        self.assertEqual(len(buf), CHUNK_SIZE)
        self.assertEqual(buf._bytes, contents)

    def test_fill_from_list(self):
        buf = smart_open.bytebuffer.ByteBuffer(CHUNK_SIZE)
        contents = random_byte_string(CHUNK_SIZE)
        contents_list = [contents[i:i+7] for i in range(0, CHUNK_SIZE, 7)]

        bytes_filled = buf.fill(contents_list)
        self.assertEqual(bytes_filled, CHUNK_SIZE)
        self.assertEqual(len(buf), CHUNK_SIZE)
        self.assertEqual(buf._bytes, contents)

    def test_fill_multiple(self):
        buf = smart_open.bytebuffer.ByteBuffer(CHUNK_SIZE)
        long_contents = random_byte_string(CHUNK_SIZE * 4)
        long_content_reader = io.BytesIO(long_contents)

        first_bytes_filled = buf.fill(long_content_reader)
        self.assertEqual(first_bytes_filled, CHUNK_SIZE)

        second_bytes_filled = buf.fill(long_content_reader)
        self.assertEqual(second_bytes_filled, CHUNK_SIZE)
        self.assertEqual(len(buf), 2 * CHUNK_SIZE)

    def test_fill_size(self):
        buf = smart_open.bytebuffer.ByteBuffer(CHUNK_SIZE)
        contents = random_byte_string(CHUNK_SIZE * 2)
        content_reader = io.BytesIO(contents)
        fill_size = int(CHUNK_SIZE / 2)

        bytes_filled = buf.fill(content_reader, size=fill_size)

        self.assertEqual(bytes_filled, fill_size)
        self.assertEqual(len(buf), fill_size)

        second_bytes_filled = buf.fill(content_reader, size=CHUNK_SIZE+1)
        self.assertEqual(second_bytes_filled, CHUNK_SIZE)
        self.assertEqual(len(buf), fill_size + CHUNK_SIZE)

    def test_fill_reader_exhaustion(self):
        buf = smart_open.bytebuffer.ByteBuffer(CHUNK_SIZE)
        short_content_size = int(CHUNK_SIZE / 4)
        short_contents = random_byte_string(short_content_size)
        short_content_reader = io.BytesIO(short_contents)

        bytes_filled = buf.fill(short_content_reader)
        self.assertEqual(bytes_filled, short_content_size)
        self.assertEqual(len(buf), short_content_size)

    def test_fill_iterable_exhaustion(self):
        buf = smart_open.bytebuffer.ByteBuffer(CHUNK_SIZE)
        short_content_size = int(CHUNK_SIZE / 4)
        short_contents = random_byte_string(short_content_size)
        short_contents_iter = (short_contents[i:i+8]
                               for i in range(0, short_content_size, 8))

        bytes_filled = buf.fill(short_contents_iter)
        self.assertEqual(bytes_filled, short_content_size)
        self.assertEqual(len(buf), short_content_size)

    def test_empty(self):
        buf, _ = bytebuffer_and_random_contents()

        self.assertEqual(len(buf), CHUNK_SIZE)
        buf.empty()
        self.assertEqual(len(buf), 0)

    def test_peek(self):
        buf, contents = bytebuffer_and_random_contents()

        self.assertEqual(buf.peek(), contents)
        self.assertEqual(len(buf), CHUNK_SIZE)
        self.assertEqual(buf.peek(64), contents[0:64])
        self.assertEqual(buf.peek(CHUNK_SIZE * 10), contents)

    def test_read(self):
        buf, contents = bytebuffer_and_random_contents()

        self.assertEqual(buf.read(), contents)
        self.assertEqual(len(buf), 0)
        self.assertEqual(buf.read(), b'')

    def test_read_size(self):
        buf, contents = bytebuffer_and_random_contents()
        read_size = 128

        self.assertEqual(buf.read(read_size), contents[:read_size])
        self.assertEqual(len(buf), CHUNK_SIZE - read_size)

        self.assertEqual(buf.read(CHUNK_SIZE*2), contents[read_size:])
        self.assertEqual(len(buf), 0)

    def test_readline(self):
        """Does the readline function work as expected in the simple case?"""
        expected = (b'this is the very first line\n', b'and this the second')
        buf = smart_open.bytebuffer.ByteBuffer()
        buf.fill(io.BytesIO(b''.join(expected)))

        first_line = buf.readline(b'\n')
        self.assertEqual(expected[0], first_line)

        second_line = buf.readline(b'\n')
        self.assertEqual(expected[1], second_line)

    def test_readline_middle(self):
        """Does the readline function work when we're in the middle of the buffer?"""
        expected = (b'this is the very first line\n', b'and this the second')
        buf = smart_open.bytebuffer.ByteBuffer()
        buf.fill(io.BytesIO(b''.join(expected)))

        buf.read(5)
        first_line = buf.readline(b'\n')
        self.assertEqual(expected[0][5:], first_line)

        buf.read(5)
        second_line = buf.readline(b'\n')
        self.assertEqual(expected[1][5:], second_line)

    def test_readline_terminator(self):
        """Does the readline function respect the terminator parameter?"""
        buf = smart_open.bytebuffer.ByteBuffer()
        buf.fill(io.BytesIO(b'one!two.three,'))
        expected = [b'one!', b'two.', b'three,']
        actual = [buf.readline(b'!'), buf.readline(b'.'), buf.readline(b',')]
        self.assertEqual(expected, actual)
