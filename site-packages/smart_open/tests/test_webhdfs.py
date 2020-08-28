# -*- coding: utf-8 -*-
#
# Copyright (C) 2020 Radim Rehurek <me@radimrehurek.com>
#
# This code is distributed under the terms and conditions
# from the MIT License (MIT).
#
import contextlib
import io
import os.path
import unittest

import responses

from smart_open import webhdfs

CURR_DIR = os.path.abspath(os.path.dirname(__file__))
URL = 'https://dummy.com/hello'


class Test(unittest.TestCase):

    @responses.activate
    def test_read_all(self):
        expected = b'hello world!'
        responses.add(responses.GET, URL, body=expected, status=200, stream=True)
        with webhdfs.open(URL, 'rb') as fin:
            actual = fin.read()
        self.assertEqual(expected, actual)

    @responses.activate
    def test_read_part(self):
        expected = b'hello world!'
        responses.add(responses.GET, URL, body=expected, status=200, stream=True)
        with webhdfs.open(URL, 'rb') as fin:
            actual = fin.read(5)
        self.assertEqual(expected[:5], actual)

    @responses.activate
    def test_read_large(self):
        with open(os.path.join(CURR_DIR, 'test_data/crime-and-punishment.txt'), 'rb') as fin:
            expected = fin.read(1024)

        responses.add(responses.GET, URL, body=expected, status=200, stream=True)
        actual = io.BytesIO()
        with webhdfs.open(URL, 'rb') as fin:
            with temporary_buffer_size(256):
                actual.write(fin.read(128))
                actual.write(fin.read(256))
                actual.write(fin.read())

        self.assertEqual(expected, actual.getvalue())


@contextlib.contextmanager
def temporary_buffer_size(size):
    io.DEFAULT_BUFFER_SIZE, old_size = size, io.DEFAULT_BUFFER_SIZE
    yield
    io.DEFAULT_BUFFER_SIZE = old_size
