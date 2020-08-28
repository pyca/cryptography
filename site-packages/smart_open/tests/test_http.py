# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 Radim Rehurek <me@radimrehurek.com>
#
# This code is distributed under the terms and conditions
# from the MIT License (MIT).
#
import unittest

import responses

import smart_open.http
import smart_open.s3
import smart_open.constants


BYTES = b'i tried so hard and got so far but in the end it doesn\'t even matter'
URL = 'http://localhost'
HTTPS_URL = 'https://localhost'
HEADERS = {
    'Content-Length': str(len(BYTES)),
    'Accept-Ranges': 'bytes',
}


def request_callback(request):
    try:
        range_string = request.headers['range']
    except KeyError:
        return (200, HEADERS, BYTES)

    start, end = range_string.replace('bytes=', '').split('-', 1)
    start = int(start)
    if end:
        end = int(end)
    else:
        end = len(BYTES)
    return (200, HEADERS, BYTES[start:end])


class HttpTest(unittest.TestCase):

    @responses.activate
    def test_read_all(self):
        responses.add(responses.GET, URL, body=BYTES, stream=True)
        reader = smart_open.http.SeekableBufferedInputBase(URL)
        read_bytes = reader.read()
        self.assertEqual(BYTES, read_bytes)

    @responses.activate
    def test_seek_from_start(self):
        responses.add_callback(responses.GET, URL, callback=request_callback)
        reader = smart_open.http.SeekableBufferedInputBase(URL)

        reader.seek(10)
        self.assertEqual(reader.tell(), 10)
        read_bytes = reader.read(size=10)
        self.assertEqual(reader.tell(), 20)
        self.assertEqual(BYTES[10:20], read_bytes)

        reader.seek(20)
        read_bytes = reader.read(size=10)
        self.assertEqual(BYTES[20:30], read_bytes)

        reader.seek(0)
        read_bytes = reader.read(size=10)
        self.assertEqual(BYTES[:10], read_bytes)

    @responses.activate
    def test_seek_from_current(self):
        responses.add_callback(responses.GET, URL, callback=request_callback)
        reader = smart_open.http.SeekableBufferedInputBase(URL)

        reader.seek(10)
        read_bytes = reader.read(size=10)
        self.assertEqual(BYTES[10:20], read_bytes)

        self.assertEqual(reader.tell(), 20)
        reader.seek(10, whence=smart_open.constants.WHENCE_CURRENT)
        self.assertEqual(reader.tell(), 30)
        read_bytes = reader.read(size=10)
        self.assertEqual(reader.tell(), 40)
        self.assertEqual(BYTES[30:40], read_bytes)

    @responses.activate
    def test_seek_from_end(self):
        responses.add_callback(responses.GET, URL, callback=request_callback)
        reader = smart_open.http.SeekableBufferedInputBase(URL)

        reader.seek(-10, whence=smart_open.constants.WHENCE_END)
        self.assertEqual(reader.tell(), len(BYTES) - 10)
        read_bytes = reader.read(size=10)
        self.assertEqual(reader.tell(), len(BYTES))
        self.assertEqual(BYTES[-10:], read_bytes)

    @responses.activate
    def test_headers_are_as_assigned(self):
        responses.add_callback(responses.GET, URL, callback=request_callback)

        # use default _HEADERS
        x = smart_open.http.BufferedInputBase(URL)
        # set different ones
        x.headers['Accept-Encoding'] = 'compress, gzip'
        x.headers['Other-Header'] = 'value'

        # use default again, global shoudn't overwritten from x
        y = smart_open.http.BufferedInputBase(URL)
        # should be default headers
        self.assertEqual(y.headers, {'Accept-Encoding': 'identity'})
        # should be assigned headers
        self.assertEqual(x.headers, {'Accept-Encoding': 'compress, gzip', 'Other-Header': 'value'})

    @responses.activate
    def test_headers(self):
        """Does the top-level http.open function handle headers correctly?"""
        responses.add_callback(responses.GET, URL, callback=request_callback)
        reader = smart_open.http.open(URL, 'rb', headers={'Foo': 'bar'})
        self.assertEqual(reader.headers['Foo'], 'bar')

    @responses.activate
    def test_https_seek_start(self):
        """Did the seek start over HTTPS work?"""
        responses.add_callback(responses.GET, HTTPS_URL, callback=request_callback)

        with smart_open.open(HTTPS_URL, "rb") as fin:
            read_bytes_1 = fin.read(size=10)
            fin.seek(0)
            read_bytes_2 = fin.read(size=10)
            self.assertEqual(read_bytes_1, read_bytes_2)

    @responses.activate
    def test_https_seek_forward(self):
        """Did the seek forward over HTTPS work?"""
        responses.add_callback(responses.GET, HTTPS_URL, callback=request_callback)

        with smart_open.open(HTTPS_URL, "rb") as fin:
            fin.seek(10)
            read_bytes = fin.read(size=10)
            self.assertEqual(BYTES[10:20], read_bytes)

    @responses.activate
    def test_https_seek_reverse(self):
        """Did the seek in reverse over HTTPS work?"""
        responses.add_callback(responses.GET, HTTPS_URL, callback=request_callback)

        with smart_open.open(HTTPS_URL, "rb") as fin:
            read_bytes_1 = fin.read(size=10)
            fin.seek(-10, whence=smart_open.constants.WHENCE_CURRENT)
            read_bytes_2 = fin.read(size=10)
            self.assertEqual(read_bytes_1, read_bytes_2)
