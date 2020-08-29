# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 Radim Rehurek <me@radimrehurek.com>
#
# This code is distributed under the terms and conditions
# from the MIT License (MIT).
#

import bz2
import csv
import contextlib
import io
import unittest
import logging
import tempfile
import os
import hashlib

import boto3
import mock
from moto import mock_s3
import responses
import gzip

import smart_open
from smart_open import smart_open_lib
from smart_open import webhdfs
from smart_open.smart_open_lib import patch_pathlib, _patch_pathlib

logger = logging.getLogger(__name__)

CURR_DIR = os.path.abspath(os.path.dirname(__file__))
SAMPLE_TEXT = 'Hello, world!'
SAMPLE_BYTES = SAMPLE_TEXT.encode('utf-8')


#
# For Windows platforms, under which tempfile.NamedTemporaryFile has some
# unwanted quirks.
#
# https://docs.python.org/3.8/library/tempfile.html#tempfile.NamedTemporaryFile
# https://stackoverflow.com/a/58955530
#
@contextlib.contextmanager
def named_temporary_file(mode='w+b', prefix=None, suffix=None, delete=True):
    filename = io.StringIO()
    if prefix:
        filename.write(prefix)
    filename.write(os.urandom(8).hex())
    if suffix:
        filename.write(suffix)
    pathname = os.path.join(tempfile.gettempdir(), filename.getvalue())

    with open(pathname, mode) as f:
        yield f

    if delete:
        os.unlink(pathname)


class ParseUriTest(unittest.TestCase):
    """
    Test ParseUri class.

    """
    def test_scheme(self):
        """Do URIs schemes parse correctly?"""
        # supported schemes
        for scheme in ("s3", "s3a", "s3n", "hdfs", "file", "http", "https", "gs", "azure"):
            parsed_uri = smart_open_lib._parse_uri(scheme + "://mybucket/mykey")
            self.assertEqual(parsed_uri.scheme, scheme)

        # unsupported scheme => NotImplementedError
        self.assertRaises(NotImplementedError, smart_open_lib._parse_uri, "foobar://mybucket/mykey")

        # unknown scheme => default_scheme
        parsed_uri = smart_open_lib._parse_uri("blah blah")
        self.assertEqual(parsed_uri.scheme, "file")

    def test_s3_uri(self):
        """Do S3 URIs parse correctly?"""
        # correct uri without credentials
        parsed_uri = smart_open_lib._parse_uri("s3://mybucket/mykey")
        self.assertEqual(parsed_uri.scheme, "s3")
        self.assertEqual(parsed_uri.bucket_id, "mybucket")
        self.assertEqual(parsed_uri.key_id, "mykey")
        self.assertEqual(parsed_uri.access_id, None)
        self.assertEqual(parsed_uri.access_secret, None)

    def test_s3_uri_contains_slash(self):
        parsed_uri = smart_open_lib._parse_uri("s3://mybucket/mydir/mykey")
        self.assertEqual(parsed_uri.scheme, "s3")
        self.assertEqual(parsed_uri.bucket_id, "mybucket")
        self.assertEqual(parsed_uri.key_id, "mydir/mykey")
        self.assertEqual(parsed_uri.access_id, None)
        self.assertEqual(parsed_uri.access_secret, None)

    def test_s3_uri_with_credentials(self):
        parsed_uri = smart_open_lib._parse_uri("s3://ACCESSID456:acces/sse_cr-et@mybucket/mykey")
        self.assertEqual(parsed_uri.scheme, "s3")
        self.assertEqual(parsed_uri.bucket_id, "mybucket")
        self.assertEqual(parsed_uri.key_id, "mykey")
        self.assertEqual(parsed_uri.access_id, "ACCESSID456")
        self.assertEqual(parsed_uri.access_secret, "acces/sse_cr-et")

    def test_s3_uri_with_credentials2(self):
        parsed_uri = smart_open_lib._parse_uri("s3://accessid:access/secret@mybucket/mykey")
        self.assertEqual(parsed_uri.scheme, "s3")
        self.assertEqual(parsed_uri.bucket_id, "mybucket")
        self.assertEqual(parsed_uri.key_id, "mykey")
        self.assertEqual(parsed_uri.access_id, "accessid")
        self.assertEqual(parsed_uri.access_secret, "access/secret")

    def test_s3_uri_has_atmark_in_key_name(self):
        parsed_uri = smart_open_lib._parse_uri("s3://accessid:access/secret@mybucket/my@ke@y")
        self.assertEqual(parsed_uri.scheme, "s3")
        self.assertEqual(parsed_uri.bucket_id, "mybucket")
        self.assertEqual(parsed_uri.key_id, "my@ke@y")
        self.assertEqual(parsed_uri.access_id, "accessid")
        self.assertEqual(parsed_uri.access_secret, "access/secret")

    def test_s3_uri_has_atmark_in_key_name2(self):
        parsed_uri = smart_open_lib._parse_uri(
            "s3://accessid:access/secret@hostname:1234@mybucket/dir/my@ke@y"
        )
        self.assertEqual(parsed_uri.scheme, "s3")
        self.assertEqual(parsed_uri.bucket_id, "mybucket")
        self.assertEqual(parsed_uri.key_id, "dir/my@ke@y")
        self.assertEqual(parsed_uri.access_id, "accessid")
        self.assertEqual(parsed_uri.access_secret, "access/secret")
        self.assertEqual(parsed_uri.host, "hostname")
        self.assertEqual(parsed_uri.port, 1234)

    def test_s3_uri_has_atmark_in_key_name3(self):
        parsed_uri = smart_open_lib._parse_uri("s3://accessid:access/secret@hostname@mybucket/dir/my@ke@y")
        self.assertEqual(parsed_uri.scheme, "s3")
        self.assertEqual(parsed_uri.bucket_id, "mybucket")
        self.assertEqual(parsed_uri.key_id, "dir/my@ke@y")
        self.assertEqual(parsed_uri.access_id, "accessid")
        self.assertEqual(parsed_uri.access_secret, "access/secret")
        self.assertEqual(parsed_uri.host, "hostname")
        self.assertEqual(parsed_uri.port, 443)

    def test_s3_handles_fragments(self):
        uri_str = 's3://bucket-name/folder/picture #1.jpg'
        parsed_uri = smart_open_lib._parse_uri(uri_str)
        self.assertEqual(parsed_uri.key_id, "folder/picture #1.jpg")

    def test_s3_handles_querystring(self):
        uri_str = 's3://bucket-name/folder/picture1.jpg?bar'
        parsed_uri = smart_open_lib._parse_uri(uri_str)
        self.assertEqual(parsed_uri.key_id, "folder/picture1.jpg?bar")

    def test_s3_invalid_url_atmark_in_bucket_name(self):
        self.assertRaises(
            ValueError, smart_open_lib._parse_uri,
            "s3://access_id:access_secret@my@bucket@port/mykey",
        )

    def test_s3_invalid_uri_missing_colon(self):
        self.assertRaises(
            ValueError, smart_open_lib._parse_uri,
            "s3://access_id@access_secret@mybucket@port/mykey",
        )

    def test_webhdfs_uri_to_http(self):
        parsed_uri = smart_open_lib._parse_uri("webhdfs://host:14000/path/file")
        actual = webhdfs.convert_to_http_uri(parsed_uri)
        expected = "http://host:14000/webhdfs/v1/path/file"
        self.assertEqual(actual, expected)

    def test_webhdfs_uri_to_http_with_query(self):
        parsed_uri = smart_open_lib._parse_uri("webhdfs://host:14000/path/file?a=1")
        actual = webhdfs.convert_to_http_uri(parsed_uri)
        expected = "http://host:14000/webhdfs/v1/path/file?a=1"
        self.assertEqual(actual, expected)

    def test_webhdfs_uri_to_http_with_user(self):
        parsed_uri = smart_open_lib._parse_uri("webhdfs://user@host:14000/path")
        actual = webhdfs.convert_to_http_uri(parsed_uri)
        expected = "http://host:14000/webhdfs/v1/path?user.name=user"
        self.assertEqual(actual, expected)

    def test_webhdfs_uri_to_http_with_user_and_query(self):
        parsed_uri = smart_open_lib._parse_uri("webhdfs://user@host:14000/path?a=1")
        actual = webhdfs.convert_to_http_uri(parsed_uri)
        expected = "http://host:14000/webhdfs/v1/path?a=1&user.name=user"
        self.assertEqual(actual, expected)

    def test_uri_from_issue_223_works(self):
        uri = "s3://:@omax-mis/twilio-messages-media/final/MEcd7c36e75f87dc6dd9e33702cdcd8fb6"
        parsed_uri = smart_open_lib._parse_uri(uri)
        self.assertEqual(parsed_uri.scheme, "s3")
        self.assertEqual(parsed_uri.bucket_id, "omax-mis")
        self.assertEqual(parsed_uri.key_id, "twilio-messages-media/final/MEcd7c36e75f87dc6dd9e33702cdcd8fb6")
        self.assertEqual(parsed_uri.access_id, "")
        self.assertEqual(parsed_uri.access_secret, "")

    def test_s3_uri_with_colon_in_key_name(self):
        """ Correctly parse the s3 url if there is a colon in the key or dir """
        parsed_uri = smart_open_lib._parse_uri("s3://mybucket/mydir/my:key")
        self.assertEqual(parsed_uri.scheme, "s3")
        self.assertEqual(parsed_uri.bucket_id, "mybucket")
        self.assertEqual(parsed_uri.key_id, "mydir/my:key")
        self.assertEqual(parsed_uri.access_id, None)
        self.assertEqual(parsed_uri.access_secret, None)

    def test_s3_uri_contains_question_mark(self):
        parsed_uri = smart_open_lib._parse_uri("s3://mybucket/mydir/mykey?param")
        self.assertEqual(parsed_uri.scheme, "s3")
        self.assertEqual(parsed_uri.bucket_id, "mybucket")
        self.assertEqual(parsed_uri.key_id, "mydir/mykey?param")

    def test_host_and_port(self):
        as_string = 's3u://user:secret@host:1234@mybucket/mykey.txt'
        uri = smart_open_lib._parse_uri(as_string)
        self.assertEqual(uri.scheme, "s3u")
        self.assertEqual(uri.bucket_id, "mybucket")
        self.assertEqual(uri.key_id, "mykey.txt")
        self.assertEqual(uri.access_id, "user")
        self.assertEqual(uri.access_secret, "secret")
        self.assertEqual(uri.host, "host")
        self.assertEqual(uri.port, 1234)

    def test_invalid_port(self):
        as_string = 's3u://user:secret@host:port@mybucket/mykey.txt'
        self.assertRaises(ValueError, smart_open_lib._parse_uri, as_string)

    def test_invalid_port2(self):
        as_string = 's3u://user:secret@host:port:foo@mybucket/mykey.txt'
        self.assertRaises(ValueError, smart_open_lib._parse_uri, as_string)

    def test_leading_slash_local_file(self):
        path = "/home/misha/hello.txt"
        uri = smart_open_lib._parse_uri(path)
        self.assertEqual(uri.scheme, "file")
        self.assertEqual(uri.uri_path, path)

        uri = smart_open_lib._parse_uri('//' + path)
        self.assertEqual(uri.scheme, "file")
        self.assertEqual(uri.uri_path, '//' + path)

    def test_ssh(self):
        as_string = 'ssh://user@host:1234/path/to/file'
        uri = smart_open_lib._parse_uri(as_string)
        self.assertEqual(uri.scheme, 'ssh')
        self.assertEqual(uri.uri_path, '/path/to/file')
        self.assertEqual(uri.user, 'user')
        self.assertEqual(uri.host, 'host')
        self.assertEqual(uri.port, 1234)
        self.assertEqual(uri.password, None)

    def test_ssh_with_pass(self):
        as_string = 'ssh://user:pass@host:1234/path/to/file'
        uri = smart_open_lib._parse_uri(as_string)
        self.assertEqual(uri.scheme, 'ssh')
        self.assertEqual(uri.uri_path, '/path/to/file')
        self.assertEqual(uri.user, 'user')
        self.assertEqual(uri.host, 'host')
        self.assertEqual(uri.port, 1234)
        self.assertEqual(uri.password, 'pass')

    def test_scp(self):
        as_string = 'scp://user@host:/path/to/file'
        uri = smart_open_lib._parse_uri(as_string)
        self.assertEqual(uri.scheme, 'scp')
        self.assertEqual(uri.uri_path, '/path/to/file')
        self.assertEqual(uri.user, 'user')
        self.assertEqual(uri.host, 'host')
        self.assertEqual(uri.port, 22)
        self.assertEqual(uri.password, None)

    def test_scp_with_pass(self):
        as_string = 'scp://user:pass@host:/path/to/file'
        uri = smart_open_lib._parse_uri(as_string)
        self.assertEqual(uri.scheme, 'scp')
        self.assertEqual(uri.uri_path, '/path/to/file')
        self.assertEqual(uri.user, 'user')
        self.assertEqual(uri.host, 'host')
        self.assertEqual(uri.port, 22)
        self.assertEqual(uri.password, 'pass')

    def test_sftp(self):
        as_string = 'sftp://host/path/to/file'
        uri = smart_open_lib._parse_uri(as_string)
        self.assertEqual(uri.scheme, 'sftp')
        self.assertEqual(uri.uri_path, '/path/to/file')
        self.assertEqual(uri.user, None)
        self.assertEqual(uri.host, 'host')
        self.assertEqual(uri.port, 22)
        self.assertEqual(uri.password, None)

    def test_sftp_with_user_and_pass(self):
        as_string = 'sftp://user:pass@host:2222/path/to/file'
        uri = smart_open_lib._parse_uri(as_string)
        self.assertEqual(uri.scheme, 'sftp')
        self.assertEqual(uri.uri_path, '/path/to/file')
        self.assertEqual(uri.user, 'user')
        self.assertEqual(uri.host, 'host')
        self.assertEqual(uri.port, 2222)
        self.assertEqual(uri.password, 'pass')

    def test_ssh_complex_password_with_colon(self):
        as_string = 'sftp://user:some:complex@password$$@host:2222/path/to/file'
        uri = smart_open_lib._parse_uri(as_string)
        self.assertEqual(uri.password, 'some:complex@password$$')

    def test_gs_uri(self):
        """Do GCS URIs parse correctly?"""
        # correct uri without credentials
        parsed_uri = smart_open_lib._parse_uri("gs://mybucket/myblob")
        self.assertEqual(parsed_uri.scheme, "gs")
        self.assertEqual(parsed_uri.bucket_id, "mybucket")
        self.assertEqual(parsed_uri.blob_id, "myblob")

    def test_gs_uri_contains_slash(self):
        parsed_uri = smart_open_lib._parse_uri("gs://mybucket/mydir/myblob")
        self.assertEqual(parsed_uri.scheme, "gs")
        self.assertEqual(parsed_uri.bucket_id, "mybucket")
        self.assertEqual(parsed_uri.blob_id, "mydir/myblob")

    def test_gs_uri_contains_question_mark(self):
        parsed_uri = smart_open_lib._parse_uri("gs://mybucket/mydir/myblob?param")
        self.assertEqual(parsed_uri.scheme, "gs")
        self.assertEqual(parsed_uri.bucket_id, "mybucket")
        self.assertEqual(parsed_uri.blob_id, "mydir/myblob?param")

    def test_azure_blob_uri(self):
        """Do Azure Blob URIs parse correctly?"""
        # correct uri without credentials
        parsed_uri = smart_open_lib._parse_uri("azure://mycontainer/myblob")
        self.assertEqual(parsed_uri.scheme, "azure")
        self.assertEqual(parsed_uri.container_id, "mycontainer")
        self.assertEqual(parsed_uri.blob_id, "myblob")

    def test_azure_blob_uri_root_container(self):
        parsed_uri = smart_open_lib._parse_uri("azure://myblob")
        self.assertEqual(parsed_uri.scheme, "azure")
        self.assertEqual(parsed_uri.container_id, "$root")
        self.assertEqual(parsed_uri.blob_id, "myblob")

    def test_azure_blob_uri_contains_slash(self):
        parsed_uri = smart_open_lib._parse_uri("azure://mycontainer/mydir/myblob")
        self.assertEqual(parsed_uri.scheme, "azure")
        self.assertEqual(parsed_uri.container_id, "mycontainer")
        self.assertEqual(parsed_uri.blob_id, "mydir/myblob")

    def test_pathlib_monkeypatch(self):
        from smart_open.smart_open_lib import pathlib

        assert pathlib.Path.open != smart_open.open

        with patch_pathlib():
            assert pathlib.Path.open == smart_open.open

        assert pathlib.Path.open != smart_open.open

        obj = patch_pathlib()
        assert pathlib.Path.open == smart_open.open

        _patch_pathlib(obj.old_impl)
        assert pathlib.Path.open != smart_open.open

    def test_pathlib_monkeypath_read_gz(self):
        from smart_open.smart_open_lib import pathlib

        path = pathlib.Path(CURR_DIR) / 'test_data' / 'crime-and-punishment.txt.gz'

        # Check that standard implementation can't work with gzip
        with path.open("r") as infile:
            with self.assertRaises(Exception):
                lines = infile.readlines()

        # Check that our implementation works with gzip
        obj = patch_pathlib()
        try:
            with path.open("r") as infile:
                lines = infile.readlines()
            self.assertEqual(len(lines), 3)
        finally:
            _patch_pathlib(obj.old_impl)


class SmartOpenHttpTest(unittest.TestCase):
    """
    Test reading from HTTP connections in various ways.

    """
    @mock.patch('smart_open.ssh.open')
    def test_read_ssh(self, mock_open):
        """Is SSH line iterator called correctly?"""
        obj = smart_open.smart_open(
            "ssh://ubuntu:pass@ip_address:1022/some/path/lines.txt",
            hello='world',
        )
        obj.__iter__()
        mock_open.assert_called_with(
            '/some/path/lines.txt',
            'rb',
            host='ip_address',
            user='ubuntu',
            password='pass',
            port=1022,
            transport_params={'hello': 'world'},
        )

    @responses.activate
    def test_http_read(self):
        """Does http read method work correctly"""
        responses.add(responses.GET, "http://127.0.0.1/index.html",
                      body='line1\nline2', stream=True)
        smart_open_object = smart_open.smart_open("http://127.0.0.1/index.html")
        self.assertEqual(smart_open_object.read().decode("utf-8"), "line1\nline2")

    @responses.activate
    def test_https_readline(self):
        """Does https readline method work correctly"""
        responses.add(responses.GET, "https://127.0.0.1/index.html",
                      body='line1\nline2', stream=True)
        smart_open_object = smart_open.smart_open("https://127.0.0.1/index.html")
        self.assertEqual(smart_open_object.readline().decode("utf-8"), "line1\n")

    @responses.activate
    def test_http_pass(self):
        """Does http authentication work correctly"""
        responses.add(responses.GET, "http://127.0.0.1/index.html",
                      body='line1\nline2', stream=True)
        _ = smart_open.smart_open("http://127.0.0.1/index.html", user='me', password='pass')
        self.assertEqual(len(responses.calls), 1)
        actual_request = responses.calls[0].request
        self.assertTrue('Authorization' in actual_request.headers)
        self.assertTrue(actual_request.headers['Authorization'].startswith('Basic '))

    @responses.activate
    def _test_compressed_http(self, suffix, query):
        """Can open <suffix> via http?"""
        raw_data = b'Hello World Compressed.' * 10000
        buf = make_buffer(name='data' + suffix)
        with smart_open.smart_open(buf, 'wb') as outfile:
            outfile.write(raw_data)
        compressed_data = buf.getvalue()
        # check that the string was actually compressed
        self.assertNotEqual(compressed_data, raw_data)

        responses.add(responses.GET, 'http://127.0.0.1/data' + suffix, body=compressed_data, stream=True)
        smart_open_object = smart_open.smart_open(
            'http://127.0.0.1/data%s%s' % (suffix, '?some_param=some_val' if query else ''))

        # decompress the file and get the same md5 hash
        self.assertEqual(smart_open_object.read(), raw_data)

    def test_http_gz(self):
        """Can open gzip via http?"""
        self._test_compressed_http(".gz", False)

    def test_http_bz2(self):
        """Can open bzip2 via http?"""
        self._test_compressed_http(".bz2", False)

    def test_http_gz_query(self):
        """Can open gzip via http with a query appended to URI?"""
        self._test_compressed_http(".gz", True)

    def test_http_bz2_query(self):
        """Can open bzip2 via http with a query appended to URI?"""
        self._test_compressed_http(".bz2", True)


def make_buffer(cls=io.BytesIO, initial_value=None, name=None, noclose=False):
    """
    Construct a new in-memory file object aka "buf".

    :param cls: Class of the file object. Meaningful values are BytesIO and StringIO.
    :param initial_value: Passed directly to the constructor, this is the content of the returned buffer.
    :param name: Associated file path. Not assigned if is None (default).
    :param noclose: If True, disables the .close function.
    :return: Instance of `cls`.
    """
    buf = cls(initial_value) if initial_value else cls()
    if name is not None:
        buf.name = name
    if noclose:
        buf.close = lambda: None
    return buf


class RealFileSystemTests(unittest.TestCase):
    """Tests that touch the file system via temporary files."""

    def setUp(self):
        with named_temporary_file(prefix='test', delete=False) as fout:
            fout.write(SAMPLE_BYTES)
            self.temp_file = fout.name

    def tearDown(self):
        os.unlink(self.temp_file)

    def test_rt(self):
        with smart_open.smart_open(self.temp_file, 'rt') as fin:
            data = fin.read()
        self.assertEqual(data, SAMPLE_TEXT)

    def test_wt(self):
        #
        # The file already contains SAMPLE_TEXT, so write something different.
        #
        text = 'nippon budokan'
        with smart_open.smart_open(self.temp_file, 'wt') as fout:
            fout.write(text)

        with smart_open.smart_open(self.temp_file, 'rt') as fin:
            data = fin.read()
        self.assertEqual(data, text)

    def test_ab(self):
        with smart_open.smart_open(self.temp_file, 'ab') as fout:
            fout.write(SAMPLE_BYTES)
        with smart_open.smart_open(self.temp_file, 'rb') as fin:
            data = fin.read()
        self.assertEqual(data, SAMPLE_BYTES * 2)

    def test_aplus(self):
        with smart_open.smart_open(self.temp_file, 'a+') as fout:
            fout.write(SAMPLE_TEXT)
        with smart_open.smart_open(self.temp_file, 'rt') as fin:
            text = fin.read()
        self.assertEqual(text, SAMPLE_TEXT * 2)

    def test_at(self):
        with smart_open.smart_open(self.temp_file, 'at') as fout:
            fout.write(SAMPLE_TEXT)
        with smart_open.smart_open(self.temp_file, 'rt') as fin:
            text = fin.read()
        self.assertEqual(text, SAMPLE_TEXT * 2)

    def test_atplus(self):
        with smart_open.smart_open(self.temp_file, 'at+') as fout:
            fout.write(SAMPLE_TEXT)
        with smart_open.smart_open(self.temp_file, 'rt') as fin:
            text = fin.read()
        self.assertEqual(text, SAMPLE_TEXT * 2)


class SmartOpenFileObjTest(unittest.TestCase):
    """
    Test passing raw file objects.
    """

    def test_read_bytes(self):
        """Can we read bytes from a byte stream?"""
        buf = make_buffer(initial_value=SAMPLE_BYTES)
        with smart_open.smart_open(buf, 'rb') as sf:
            data = sf.read()
        self.assertEqual(data, SAMPLE_BYTES)

    def test_write_bytes(self):
        """Can we write bytes to a byte stream?"""
        buf = make_buffer()
        with smart_open.smart_open(buf, 'wb') as sf:
            sf.write(SAMPLE_BYTES)
            self.assertEqual(buf.getvalue(), SAMPLE_BYTES)

    def test_read_text_stream_fails(self):
        """Attempts to read directly from a text stream should fail.

        This is because smart_open.open expects a byte stream as input.
        If you have a text stream, there's no point passing it to smart_open:
        you can read from it directly.
        """
        buf = make_buffer(io.StringIO, initial_value=SAMPLE_TEXT)
        with smart_open.smart_open(buf, 'r') as sf:
            self.assertRaises(TypeError, sf.read)  # we expect binary mode

    def test_write_text_stream_fails(self):
        """Attempts to write directly to a text stream should fail."""
        buf = make_buffer(io.StringIO)
        with smart_open.smart_open(buf, 'w') as sf:
            self.assertRaises(TypeError, sf.write, SAMPLE_TEXT)  # we expect binary mode

    def test_read_text_from_bytestream(self):
        buf = make_buffer(initial_value=SAMPLE_BYTES)
        with smart_open.smart_open(buf, 'r') as sf:
            data = sf.read()
        self.assertEqual(data, SAMPLE_TEXT)

    def test_read_text_from_bytestream_rt(self):
        buf = make_buffer(initial_value=SAMPLE_BYTES)
        with smart_open.smart_open(buf, 'rt') as sf:
            data = sf.read()
        self.assertEqual(data, SAMPLE_TEXT)

    def test_read_text_from_bytestream_rtplus(self):
        buf = make_buffer(initial_value=SAMPLE_BYTES)
        with smart_open.smart_open(buf, 'rt+') as sf:
            data = sf.read()
        self.assertEqual(data, SAMPLE_TEXT)

    def test_write_text_to_bytestream(self):
        """Can we write strings to a byte stream?"""
        buf = make_buffer(noclose=True)
        with smart_open.smart_open(buf, 'w') as sf:
            sf.write(SAMPLE_TEXT)

        self.assertEqual(buf.getvalue(), SAMPLE_BYTES)

    def test_write_text_to_bytestream_wt(self):
        """Can we write strings to a byte stream?"""
        buf = make_buffer(noclose=True)
        with smart_open.smart_open(buf, 'wt') as sf:
            sf.write(SAMPLE_TEXT)

        self.assertEqual(buf.getvalue(), SAMPLE_BYTES)

    def test_write_text_to_bytestream_wtplus(self):
        """Can we write strings to a byte stream?"""
        buf = make_buffer(noclose=True)
        with smart_open.smart_open(buf, 'wt+') as sf:
            sf.write(SAMPLE_TEXT)

        self.assertEqual(buf.getvalue(), SAMPLE_BYTES)

    def test_name_read(self):
        """Can we use the "name" attribute to decompress on the fly?"""
        data = SAMPLE_BYTES * 1000
        buf = make_buffer(initial_value=bz2.compress(data), name='data.bz2')
        with smart_open.smart_open(buf, 'rb') as sf:
            data = sf.read()
        self.assertEqual(data, data)

    def test_name_write(self):
        """Can we use the "name" attribute to compress on the fly?"""
        data = SAMPLE_BYTES * 1000
        buf = make_buffer(name='data.bz2')
        with smart_open.smart_open(buf, 'wb') as sf:
            sf.write(data)
        self.assertEqual(bz2.decompress(buf.getvalue()), data)

    def test_open_side_effect(self):
        """
        Does our detection of the `name` attribute work with wrapped open()-ed streams?

        We `open()` a file with ".bz2" extension, pass the file object to `smart_open()` and check that
        we read decompressed data. This behavior is driven by detecting the `name` attribute in
        `_open_binary_stream()`.
        """
        data = SAMPLE_BYTES * 1000
        with named_temporary_file(prefix='smart_open_tests_', suffix=".bz2", delete=False) as tmpf:
            tmpf.write(bz2.compress(data))
        try:
            with open(tmpf.name, 'rb') as openf:
                with smart_open.smart_open(openf) as smartf:
                    smart_data = smartf.read()
            self.assertEqual(data, smart_data)
        finally:
            os.unlink(tmpf.name)


#
# What exactly to patch here differs on _how_ we're opening the file.
# See the _shortcut_open function for details.
#
_IO_OPEN = 'io.open'
_BUILTIN_OPEN = 'smart_open.smart_open_lib._builtin_open'


class SmartOpenReadTest(unittest.TestCase):
    """
    Test reading from files under various schemes.

    """

    def test_shortcut(self):
        fpath = os.path.join(CURR_DIR, 'test_data/crime-and-punishment.txt')
        with mock.patch('smart_open.smart_open_lib._builtin_open') as mock_open:
            smart_open.smart_open(fpath, 'r').read()
        mock_open.assert_called_with(fpath, 'r', buffering=-1)

    def test_open_with_keywords(self):
        """This test captures Issue #142."""
        fpath = os.path.join(CURR_DIR, 'test_data/cp852.tsv.txt')
        with open(fpath, 'rb') as fin:
            expected = fin.read().decode('cp852')
        with smart_open.smart_open(fpath, encoding='cp852') as fin:
            actual = fin.read()
        self.assertEqual(expected, actual)

    def test_open_with_keywords_explicit_r(self):
        fpath = os.path.join(CURR_DIR, 'test_data/cp852.tsv.txt')
        with open(fpath, 'rb') as fin:
            expected = fin.read().decode('cp852')
        with smart_open.smart_open(fpath, mode='r', encoding='cp852') as fin:
            actual = fin.read()
        self.assertEqual(expected, actual)

    def test_open_and_read_pathlib_path(self):
        """If ``pathlib.Path`` is available we should be able to open and read."""
        from smart_open.smart_open_lib import pathlib

        fpath = os.path.join(CURR_DIR, 'test_data/cp852.tsv.txt')
        with open(fpath, 'rb') as fin:
            expected = fin.read().decode('cp852')
        with smart_open.smart_open(pathlib.Path(fpath), mode='r', encoding='cp852') as fin:
            actual = fin.read()
        self.assertEqual(expected, actual)

    @mock_s3
    def test_read_never_returns_none(self):
        """read should never return None."""
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='mybucket')

        test_string = u"ветер по морю гуляет..."
        with smart_open.smart_open("s3://mybucket/mykey", "wb") as fout:
            fout.write(test_string.encode('utf8'))

        r = smart_open.smart_open("s3://mybucket/mykey", "rb")
        self.assertEqual(r.read(), test_string.encode("utf-8"))
        self.assertEqual(r.read(), b"")
        self.assertEqual(r.read(), b"")

    @mock_s3
    def test_readline(self):
        """Does readline() return the correct file content?"""
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='mybucket')
        test_string = u"hello žluťoučký world!\nhow are you?".encode('utf8')
        with smart_open.smart_open("s3://mybucket/mykey", "wb") as fout:
            fout.write(test_string)

        reader = smart_open.smart_open("s3://mybucket/mykey", "rb")
        self.assertEqual(reader.readline(), u"hello žluťoučký world!\n".encode("utf-8"))

    @mock_s3
    def test_readline_iter(self):
        """Does __iter__ return the correct file content?"""
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='mybucket')
        lines = [u"всем привет!\n", u"что нового?"]
        with smart_open.smart_open("s3://mybucket/mykey", "wb") as fout:
            fout.write("".join(lines).encode("utf-8"))

        reader = smart_open.smart_open("s3://mybucket/mykey", "rb")

        actual_lines = [line.decode("utf-8") for line in reader]
        self.assertEqual(2, len(actual_lines))
        self.assertEqual(lines[0], actual_lines[0])
        self.assertEqual(lines[1], actual_lines[1])

    @mock_s3
    def test_readline_eof(self):
        """Does readline() return empty string on EOF?"""
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='mybucket')
        with smart_open.smart_open("s3://mybucket/mykey", "wb"):
            pass

        reader = smart_open.smart_open("s3://mybucket/mykey", "rb")

        self.assertEqual(reader.readline(), b"")
        self.assertEqual(reader.readline(), b"")
        self.assertEqual(reader.readline(), b"")

    @mock_s3
    def test_s3_iter_lines(self):
        """Does s3_iter_lines give correct content?"""
        # create fake bucket and fake key
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='mybucket')
        test_string = u"hello žluťoučký world!\nhow are you?".encode('utf8')
        with smart_open.smart_open("s3://mybucket/mykey", "wb") as fin:
            fin.write(test_string)

        # call s3_iter_lines and check output
        reader = smart_open.smart_open("s3://mybucket/mykey", "rb")
        output = list(reader)
        self.assertEqual(b''.join(output), test_string)

    # TODO: add more complex test for file://
    @mock.patch('smart_open.smart_open_lib._builtin_open')
    def test_file(self, mock_smart_open):
        """Is file:// line iterator called correctly?"""
        prefix = "file://"
        full_path = '/tmp/test.txt'
        read_mode = "rb"
        smart_open_object = smart_open.smart_open(prefix+full_path, read_mode)
        smart_open_object.__iter__()
        # called with the correct path?
        mock_smart_open.assert_called_with(full_path, read_mode, buffering=-1)

        full_path = '/tmp/test#hash##more.txt'
        read_mode = "rb"
        smart_open_object = smart_open.smart_open(prefix+full_path, read_mode)
        smart_open_object.__iter__()
        # called with the correct path?
        mock_smart_open.assert_called_with(full_path, read_mode, buffering=-1)

        full_path = 'aa#aa'
        read_mode = "rb"
        smart_open_object = smart_open.smart_open(full_path, read_mode)
        smart_open_object.__iter__()
        # called with the correct path?
        mock_smart_open.assert_called_with(full_path, read_mode, buffering=-1)

        short_path = "~/tmp/test.txt"
        full_path = os.path.expanduser(short_path)

    @mock.patch(_BUILTIN_OPEN)
    def test_file_errors(self, mock_smart_open):
        prefix = "file://"
        full_path = '/tmp/test.txt'
        read_mode = "r"
        short_path = "~/tmp/test.txt"
        full_path = os.path.expanduser(short_path)

        smart_open_object = smart_open.smart_open(prefix+short_path, read_mode, errors='strict')
        smart_open_object.__iter__()
        # called with the correct expanded path?
        mock_smart_open.assert_called_with(full_path, read_mode, buffering=-1, errors='strict')

    @mock.patch(_BUILTIN_OPEN)
    def test_file_buffering(self, mock_smart_open):
        smart_open_object = smart_open.smart_open('/tmp/somefile', 'rb', buffering=0)
        smart_open_object.__iter__()
        # called with the correct expanded path?
        mock_smart_open.assert_called_with('/tmp/somefile', 'rb', buffering=0)

    @unittest.skip('smart_open does not currently accept additional positional args')
    @mock.patch(_BUILTIN_OPEN)
    def test_file_buffering2(self, mock_smart_open):
        smart_open_object = smart_open.smart_open('/tmp/somefile', 'rb', 0)
        smart_open_object.__iter__()
        # called with the correct expanded path?
        mock_smart_open.assert_called_with('/tmp/somefile', 'rb', buffering=0)

    # couldn't find any project for mocking up HDFS data
    # TODO: we want to test also a content of the files, not just fnc call params
    @mock.patch('smart_open.hdfs.subprocess')
    def test_hdfs(self, mock_subprocess):
        """Is HDFS line iterator called correctly?"""
        mock_subprocess.PIPE.return_value = "test"
        smart_open_object = smart_open.smart_open("hdfs:///tmp/test.txt")
        smart_open_object.__iter__()
        # called with the correct params?
        mock_subprocess.Popen.assert_called_with(
            ["hdfs", "dfs", "-cat", "/tmp/test.txt"],
            stdout=mock_subprocess.PIPE,
        )

        # second possibility of schema
        smart_open_object = smart_open.smart_open("hdfs://tmp/test.txt")
        smart_open_object.__iter__()
        mock_subprocess.Popen.assert_called_with(
            ["hdfs", "dfs", "-cat", "/tmp/test.txt"],
            stdout=mock_subprocess.PIPE,
        )

    @responses.activate
    def test_webhdfs(self):
        """Is webhdfs line iterator called correctly"""
        responses.add(responses.GET, "http://127.0.0.1:8440/webhdfs/v1/path/file",
                      body='line1\nline2', stream=True)
        smart_open_object = smart_open.smart_open("webhdfs://127.0.0.1:8440/path/file")
        iterator = iter(smart_open_object)
        self.assertEqual(next(iterator).decode("utf-8"), "line1\n")
        self.assertEqual(next(iterator).decode("utf-8"), "line2")

    @responses.activate
    def test_webhdfs_encoding(self):
        """Is HDFS line iterator called correctly?"""
        input_url = "webhdfs://127.0.0.1:8440/path/file"
        actual_url = 'http://127.0.0.1:8440/webhdfs/v1/path/file'
        text = u'не для меня прийдёт весна, не для меня дон разольётся'
        body = text.encode('utf-8')
        responses.add(responses.GET, actual_url, body=body, stream=True)

        actual = smart_open.smart_open(input_url, encoding='utf-8').read()
        self.assertEqual(text, actual)

    @responses.activate
    def test_webhdfs_read(self):
        """Does webhdfs read method work correctly"""
        responses.add(responses.GET, "http://127.0.0.1:8440/webhdfs/v1/path/file",
                      body='line1\nline2', stream=True)
        smart_open_object = smart_open.smart_open("webhdfs://127.0.0.1:8440/path/file")
        self.assertEqual(smart_open_object.read().decode("utf-8"), "line1\nline2")

    @mock_s3
    def test_s3_iter_moto(self):
        """Are S3 files iterated over correctly?"""
        # a list of strings to test with
        expected = [b"*" * 5 * 1024**2] + [b'0123456789'] * 1024 + [b"test"]

        # create fake bucket and fake key
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='mybucket')

        with smart_open.smart_open("s3://mybucket/mykey", "wb", s3_min_part_size=5 * 1024**2) as fout:
            # write a single huge line (=full multipart upload)
            fout.write(expected[0] + b'\n')

            # write lots of small lines
            for lineno, line in enumerate(expected[1:-1]):
                fout.write(line + b'\n')

            # ...and write the last line too, no newline at the end
            fout.write(expected[-1])

        # connect to fake s3 and read from the fake key we filled above
        smart_open_object = smart_open.smart_open("s3://mybucket/mykey")
        output = [line.rstrip(b'\n') for line in smart_open_object]
        self.assertEqual(output, expected)

        # same thing but using a context manager
        with smart_open.smart_open("s3://mybucket/mykey") as smart_open_object:
            output = [line.rstrip(b'\n') for line in smart_open_object]
            self.assertEqual(output, expected)

    @mock_s3
    def test_s3_read_moto(self):
        """Are S3 files read correctly?"""
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='mybucket')

        # write some bogus key so we can check it below
        content = u"hello wořld\nhow are you?".encode('utf8')
        with smart_open.smart_open("s3://mybucket/mykey", "wb") as fout:
            fout.write(content)

        smart_open_object = smart_open.smart_open("s3://mybucket/mykey")
        self.assertEqual(content[:6], smart_open_object.read(6))
        self.assertEqual(content[6:14], smart_open_object.read(8))  # ř is 2 bytes

        self.assertEqual(content[14:], smart_open_object.read())  # read the rest

    @mock_s3
    def test_s3_seek_moto(self):
        """Does seeking in S3 files work correctly?"""
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='mybucket')

        # write some bogus key so we can check it below
        content = u"hello wořld\nhow are you?".encode('utf8')
        with smart_open.smart_open("s3://mybucket/mykey", "wb") as fout:
            fout.write(content)

        smart_open_object = smart_open.smart_open("s3://mybucket/mykey")
        self.assertEqual(content[:6], smart_open_object.read(6))
        self.assertEqual(content[6:14], smart_open_object.read(8))  # ř is 2 bytes

        smart_open_object.seek(0)
        self.assertEqual(content, smart_open_object.read())  # no size given => read whole file

        smart_open_object.seek(0)
        self.assertEqual(content, smart_open_object.read(-1))  # same thing


class SmartOpenS3KwargsTest(unittest.TestCase):
    @mock.patch('boto3.Session')
    def test_no_kwargs(self, mock_session):
        smart_open.smart_open('s3://mybucket/mykey')
        mock_session.return_value.resource.assert_called_with('s3')

    @mock.patch('boto3.Session')
    def test_credentials(self, mock_session):
        smart_open.smart_open('s3://access_id:access_secret@mybucket/mykey')
        mock_session.assert_called_with(aws_access_key_id='access_id', aws_secret_access_key='access_secret')
        mock_session.return_value.resource.assert_called_with('s3')

    @mock.patch('boto3.Session')
    def test_host(self, mock_session):
        transport_params = {'resource_kwargs': {'endpoint_url': 'http://aa.domain.com'}}
        smart_open.open("s3://access_id:access_secret@mybucket/mykey", transport_params=transport_params)
        mock_session.assert_called_with(
            aws_access_key_id='access_id',
            aws_secret_access_key='access_secret',
        )
        mock_session.return_value.resource.assert_called_with(
            's3',
            endpoint_url='http://aa.domain.com',
        )

    @mock.patch('boto3.Session')
    def test_s3_upload(self, mock_session):
        smart_open.open(
            "s3://bucket/key", 'wb', transport_params={
                'multipart_upload_kwargs': {
                    'ServerSideEncryption': 'AES256',
                    'ContentType': 'application/json',
                }
            }
        )

        # Locate the s3.Object instance (mock)
        s3_resource = mock_session.return_value.resource.return_value
        s3_object = s3_resource.Object.return_value

        # Check that `initiate_multipart_upload` was called
        # with the desired args
        s3_object.initiate_multipart_upload.assert_called_with(
            ServerSideEncryption='AES256',
            ContentType='application/json'
        )

    def test_session_read_mode(self):
        """
        Read stream should use a custom boto3.Session
        """
        session = boto3.Session()
        session.resource = mock.MagicMock()

        smart_open.open('s3://bucket/key', transport_params={'session': session})
        session.resource.assert_called_with('s3')

    def test_session_write_mode(self):
        """
        Write stream should use a custom boto3.Session
        """
        session = boto3.Session()
        session.resource = mock.MagicMock()

        smart_open.open('s3://bucket/key', 'wb', transport_params={'session': session})
        session.resource.assert_called_with('s3')


class SmartOpenTest(unittest.TestCase):
    """
    Test reading and writing from/into files.

    """
    def setUp(self):
        self.as_text = u'куда идём мы с пятачком - большой большой секрет'
        self.as_bytes = self.as_text.encode('utf-8')
        self.stringio = io.StringIO(self.as_text)
        self.bytesio = io.BytesIO(self.as_bytes)

    def test_file_mode_mock(self):
        """Are file:// open modes passed correctly?"""
        # correct read modes
        #
        # We always open files in binary mode first, but engage
        # encoders/decoders as necessary.  Instead of checking how the file
        # _initially_ got opened, we now also check the end result: if the
        # contents got decoded correctly.
        #

    def test_text(self):
        with mock.patch(_BUILTIN_OPEN, mock.Mock(return_value=self.stringio)) as mock_open:
            with smart_open.smart_open("blah", "r", encoding='utf-8') as fin:
                self.assertEqual(fin.read(), self.as_text)
                mock_open.assert_called_with("blah", "r", buffering=-1, encoding='utf-8')

    def test_binary(self):
        with mock.patch(_BUILTIN_OPEN, mock.Mock(return_value=self.bytesio)) as mock_open:
            with smart_open.smart_open("blah", "rb") as fin:
                self.assertEqual(fin.read(), self.as_bytes)
                mock_open.assert_called_with("blah", "rb", buffering=-1)

    def test_expanded_path(self):
        short_path = "~/blah"
        full_path = os.path.expanduser(short_path)
        with mock.patch(_BUILTIN_OPEN, mock.Mock(return_value=self.stringio)) as mock_open:
            with smart_open.smart_open(short_path, "rb"):
                mock_open.assert_called_with(full_path, "rb", buffering=-1)

    def test_incorrect(self):
        # incorrect file mode
        self.assertRaises(NotImplementedError, smart_open.smart_open, "s3://bucket/key", "x")

        # correct write modes, incorrect scheme
        self.assertRaises(NotImplementedError, smart_open.smart_open, "hdfs:///blah.txt", "wb+")
        self.assertRaises(NotImplementedError, smart_open.smart_open, "http:///blah.txt", "w")
        self.assertRaises(NotImplementedError, smart_open.smart_open, "s3://bucket/key", "wb+")

    def test_write_utf8(self):
        # correct write mode, correct file:// URI
        with mock.patch(_BUILTIN_OPEN, mock.Mock(return_value=self.stringio)) as mock_open:
            with smart_open.smart_open("blah", "w", encoding='utf-8') as fout:
                mock_open.assert_called_with("blah", "w", buffering=-1, encoding='utf-8')
                fout.write(self.as_text)

    def test_write_utf8_absolute_path(self):
        with mock.patch(_BUILTIN_OPEN, mock.Mock(return_value=self.stringio)) as mock_open:
            with smart_open.smart_open("/some/file.txt", "w", encoding='utf-8') as fout:
                mock_open.assert_called_with("/some/file.txt", "w", buffering=-1, encoding='utf-8')
                fout.write(self.as_text)

    def test_append_utf8(self):
        with mock.patch(_BUILTIN_OPEN, mock.Mock(return_value=self.stringio)) as mock_open:
            with smart_open.smart_open("/some/file.txt", "w+", encoding='utf-8') as fout:
                mock_open.assert_called_with("/some/file.txt", "w+", buffering=-1, encoding='utf-8')
                fout.write(self.as_text)

    def test_append_binary_absolute_path(self):
        with mock.patch(_BUILTIN_OPEN, mock.Mock(return_value=self.bytesio)) as mock_open:
            with smart_open.smart_open("/some/file.txt", "wb+") as fout:
                mock_open.assert_called_with("/some/file.txt", "wb+", buffering=-1)
                fout.write(self.as_bytes)

    def test_newline(self):
        with mock.patch(_BUILTIN_OPEN, mock.Mock(return_value=self.bytesio)) as mock_open:
            smart_open.smart_open("/some/file.txt", "wb+", newline='\n')
            mock_open.assert_called_with("/some/file.txt", "wb+", buffering=-1, newline='\n')

    def test_newline_csv(self):
        #
        # See https://github.com/RaRe-Technologies/smart_open/issues/477
        #
        rows = [{'name': 'alice', 'color': 'aqua'}, {'name': 'bob', 'color': 'blue'}]
        expected = 'name,color\nalice,aqua\nbob,blue\n'

        with named_temporary_file(mode='w') as tmp:
            with smart_open.open(tmp.name, 'w+', newline='\n') as fout:
                out = csv.DictWriter(fout, fieldnames=['name', 'color'])
                out.writeheader()
                out.writerows(rows)

            with open(tmp.name, 'r') as fin:
                content = fin.read()

        assert content == expected

    @mock.patch('boto3.Session')
    def test_s3_mode_mock(self, mock_session):
        """Are s3:// open modes passed correctly?"""

        # correct write mode, correct s3 URI
        transport_params = {'resource_kwargs': {'endpoint_url': 'http://s3.amazonaws.com'}}
        smart_open.open("s3://mybucket/mykey", "w", transport_params=transport_params)
        mock_session.return_value.resource.assert_called_with(
            's3', endpoint_url='http://s3.amazonaws.com'
        )

    @mock.patch('smart_open.hdfs.subprocess')
    def test_hdfs(self, mock_subprocess):
        """Is HDFS write called correctly"""
        smart_open_object = smart_open.smart_open("hdfs:///tmp/test.txt", 'wb')
        smart_open_object.write("test")
        # called with the correct params?
        mock_subprocess.Popen.assert_called_with(
            ["hdfs", "dfs", "-put", "-f", "-", "/tmp/test.txt"], stdin=mock_subprocess.PIPE
        )

        # second possibility of schema
        smart_open_object = smart_open.smart_open("hdfs://tmp/test.txt", 'wb')
        smart_open_object.write("test")
        mock_subprocess.Popen.assert_called_with(
            ["hdfs", "dfs", "-put", "-f", "-", "/tmp/test.txt"], stdin=mock_subprocess.PIPE
        )

    @mock_s3
    def test_s3_modes_moto(self):
        """Do s3:// open modes work correctly?"""
        # fake bucket and key
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='mybucket')
        raw_data = b"second test"

        # correct write mode, correct s3 URI
        with smart_open.smart_open("s3://mybucket/newkey", "wb") as fout:
            logger.debug('fout: %r', fout)
            fout.write(raw_data)

        logger.debug("write successfully completed")

        output = list(smart_open.smart_open("s3://mybucket/newkey", "rb"))

        self.assertEqual(output, [raw_data])

    @mock_s3
    def test_s3_metadata_write(self):
        # Read local file fixture
        path = os.path.join(CURR_DIR, 'test_data/crime-and-punishment.txt.gz')
        data = ""
        with smart_open.smart_open(path, 'rb') as fd:
            data = fd.read()

        # Create a test bucket
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='mybucket')

        # Write data, with multipart_upload options
        write_stream = smart_open.open(
            's3://mybucket/crime-and-punishment.txt.gz', 'wb',
            transport_params={
                'multipart_upload_kwargs': {
                    'ContentType': 'text/plain',
                    'ContentEncoding': 'gzip',
                }
            }
        )
        with write_stream as fout:
            fout.write(data)

        key = s3.Object('mybucket', 'crime-and-punishment.txt.gz')
        self.assertIn('text/plain', key.content_type)
        self.assertEqual(key.content_encoding, 'gzip')

    @mock_s3
    def test_write_bad_encoding_strict(self):
        """Should abort on encoding error."""
        text = u'欲しい気持ちが成長しすぎて'

        with self.assertRaises(UnicodeEncodeError):
            with named_temporary_file('wb', delete=True) as infile:
                with smart_open.smart_open(infile.name, 'w', encoding='koi8-r',
                                           errors='strict') as fout:
                    fout.write(text)

    @mock_s3
    def test_write_bad_encoding_replace(self):
        """Should replace characters that failed to encode."""
        text = u'欲しい気持ちが成長しすぎて'
        expected = u'?' * len(text)

        with named_temporary_file('wb', delete=True) as infile:
            with smart_open.smart_open(infile.name, 'w', encoding='koi8-r',
                                       errors='replace') as fout:
                fout.write(text)
            with smart_open.smart_open(infile.name, 'r', encoding='koi8-r') as fin:
                actual = fin.read()

        self.assertEqual(expected, actual)


class WebHdfsWriteTest(unittest.TestCase):
    """
    Test writing into webhdfs files.

    """

    @responses.activate
    def test_initialize_write(self):
        def request_callback(_):
            resp_body = ""
            headers = {'location': 'http://127.0.0.1:8440/file'}
            return 307, headers, resp_body

        responses.add_callback(
            responses.PUT,
            "http://127.0.0.1:8440/webhdfs/v1/path/file",
            callback=request_callback,
        )
        responses.add(
            responses.PUT,
            "http://127.0.0.1:8440/file",
            status=201,
        )
        smart_open.smart_open("webhdfs://127.0.0.1:8440/path/file", 'wb')

        assert len(responses.calls) == 2
        path, params = responses.calls[0].request.url.split("?")
        assert path == "http://127.0.0.1:8440/webhdfs/v1/path/file"
        assert params == "overwrite=True&op=CREATE" or params == "op=CREATE&overwrite=True"
        assert responses.calls[1].request.url == "http://127.0.0.1:8440/file"

    @responses.activate
    def test_write(self):
        def request_callback(_):
            resp_body = ""
            headers = {'location': 'http://127.0.0.1:8440/file'}
            return 307, headers, resp_body

        responses.add_callback(
            responses.PUT,
            "http://127.0.0.1:8440/webhdfs/v1/path/file",
            callback=request_callback,
        )
        responses.add(responses.PUT, "http://127.0.0.1:8440/file", status=201)
        smart_open_object = smart_open.smart_open("webhdfs://127.0.0.1:8440/path/file", 'wb')

        def write_callback(request):
            assert request.body == u"žluťoučký koníček".encode('utf8')
            headers = {}
            return 200, headers, ""

        test_string = u"žluťoučký koníček".encode('utf8')
        responses.add_callback(
            responses.POST,
            "http://127.0.0.1:8440/webhdfs/v1/path/file",
            callback=request_callback,
        )
        responses.add_callback(
            responses.POST,
            "http://127.0.0.1:8440/file",
            callback=write_callback,
        )
        smart_open_object.write(test_string)
        smart_open_object.close()

        assert len(responses.calls) == 4
        assert responses.calls[2].request.url == "http://127.0.0.1:8440/webhdfs/v1/path/file?op=APPEND"  # noqa
        assert responses.calls[3].request.url == "http://127.0.0.1:8440/file"


class CompressionFormatTest(unittest.TestCase):
    """Test transparent (de)compression."""

    def write_read_assertion(self, suffix):
        test_file = make_buffer(name='file' + suffix)
        with smart_open.smart_open(test_file, 'wb') as fout:
            fout.write(SAMPLE_BYTES)
        self.assertNotEqual(SAMPLE_BYTES, test_file.getvalue())
        # we have to recreate the buffer because it is closed
        test_file = make_buffer(initial_value=test_file.getvalue(), name=test_file.name)
        with smart_open.smart_open(test_file, 'rb') as fin:
            self.assertEqual(fin.read(), SAMPLE_BYTES)

    def test_open_gz(self):
        """Can open gzip?"""
        fpath = os.path.join(CURR_DIR, 'test_data/crlf_at_1k_boundary.warc.gz')
        with smart_open.smart_open(fpath) as infile:
            data = infile.read()
        m = hashlib.md5(data)
        assert m.hexdigest() == '18473e60f8c7c98d29d65bf805736a0d', \
            'Failed to read gzip'

    def test_write_read_gz(self):
        """Can write and read gzip?"""
        self.write_read_assertion('.gz')

    def test_write_read_bz2(self):
        """Can write and read bz2?"""
        self.write_read_assertion('.bz2')


class MultistreamsBZ2Test(unittest.TestCase):
    """
    Test that multistream bzip2 compressed files can be read.

    """

    # note: these tests are derived from the Python 3.x tip bz2 tests.

    TEXT_LINES = [
        b'root:x:0:0:root:/root:/bin/bash\n',
        b'bin:x:1:1:bin:/bin:\n',
        b'daemon:x:2:2:daemon:/sbin:\n',
        b'adm:x:3:4:adm:/var/adm:\n',
        b'lp:x:4:7:lp:/var/spool/lpd:\n',
        b'sync:x:5:0:sync:/sbin:/bin/sync\n',
        b'shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown\n',
        b'halt:x:7:0:halt:/sbin:/sbin/halt\n',
        b'mail:x:8:12:mail:/var/spool/mail:\n',
        b'news:x:9:13:news:/var/spool/news:\n',
        b'uucp:x:10:14:uucp:/var/spool/uucp:\n',
        b'operator:x:11:0:operator:/root:\n',
        b'games:x:12:100:games:/usr/games:\n',
        b'gopher:x:13:30:gopher:/usr/lib/gopher-data:\n',
        b'ftp:x:14:50:FTP User:/var/ftp:/bin/bash\n',
        b'nobody:x:65534:65534:Nobody:/home:\n',
        b'postfix:x:100:101:postfix:/var/spool/postfix:\n',
        b'niemeyer:x:500:500::/home/niemeyer:/bin/bash\n',
        b'postgres:x:101:102:PostgreSQL Server:/var/lib/pgsql:/bin/bash\n',
        b'mysql:x:102:103:MySQL server:/var/lib/mysql:/bin/bash\n',
        b'www:x:103:104::/var/www:/bin/false\n',
    ]

    TEXT = b''.join(TEXT_LINES)

    DATA = (
        b'BZh91AY&SY.\xc8N\x18\x00\x01>_\x80\x00\x10@\x02\xff\xf0\x01\x07n\x00?\xe7\xff\xe00\x01\x99\xaa\x00'
        b'\xc0\x03F\x86\x8c#&\x83F\x9a\x03\x06\xa6\xd0\xa6\x93M\x0fQ\xa7\xa8\x06\x804hh\x12$\x11\xa4i4\xf14S'
        b'\xd2<Q\xb5\x0fH\xd3\xd4\xdd\xd5\x87\xbb\xf8\x94\r\x8f\xafI\x12\xe1\xc9\xf8/E\x00pu\x89\x12]\xc9'
        b'\xbbDL\nQ\x0e\t1\x12\xdf\xa0\xc0\x97\xac2O9\x89\x13\x94\x0e\x1c7\x0ed\x95I\x0c\xaaJ\xa4\x18L\x10'
        b'\x05#\x9c\xaf\xba\xbc/\x97\x8a#C\xc8\xe1\x8cW\xf9\xe2\xd0\xd6M\xa7\x8bXa<e\x84t\xcbL\xb3\xa7\xd9'
        b'\xcd\xd1\xcb\x84.\xaf\xb3\xab\xab\xad`n}\xa0lh\tE,\x8eZ\x15\x17VH>\x88\xe5\xcd9gd6\x0b\n\xe9\x9b'
        b'\xd5\x8a\x99\xf7\x08.K\x8ev\xfb\xf7xw\xbb\xdf\xa1\x92\xf1\xdd|/";\xa2\xba\x9f\xd5\xb1#A\xb6\xf6'
        b'\xb3o\xc9\xc5y\\\xebO\xe7\x85\x9a\xbc\xb6f8\x952\xd5\xd7"%\x89>V,\xf7\xa6z\xe2\x9f\xa3\xdf\x11'
        b'\x11"\xd6E)I\xa9\x13^\xca\xf3r\xd0\x03U\x922\xf26\xec\xb6\xed\x8b\xc3U\x13\x9d\xc5\x170\xa4\xfa^'
        b'\x92\xacDF\x8a\x97\xd6\x19\xfe\xdd\xb8\xbd\x1a\x9a\x19\xa3\x80ankR\x8b\xe5\xd83]\xa9\xc6\x08'
        b'\x82f\xf6\xb9"6l$\xb8j@\xc0\x8a\xb0l1..\xbak\x83ls\x15\xbc\xf4\xc1\x13\xbe\xf8E\xb8\x9d\r\xa8\x9dk'
        b'\x84\xd3n\xfa\xacQ\x07\xb1%y\xaav\xb4\x08\xe0z\x1b\x16\xf5\x04\xe9\xcc\xb9\x08z\x1en7.G\xfc]\xc9'
        b'\x14\xe1B@\xbb!8`'
    )

    def create_temp_bz2(self, streams=1):
        with named_temporary_file('wb', suffix='.bz2', delete=False) as f:
            f.write(self.DATA * streams)
        return f.name

    def cleanup_temp_bz2(self, test_file):
        if os.path.isfile(test_file):
            os.unlink(test_file)

    def test_can_read_multistream_bz2(self):
        from bz2 import BZ2File

        test_file = self.create_temp_bz2(streams=5)
        with BZ2File(test_file) as bz2f:
            self.assertEqual(bz2f.read(), self.TEXT * 5)
        self.cleanup_temp_bz2(test_file)

    def test_file_smart_open_can_read_multistream_bz2(self):
        test_file = self.create_temp_bz2(streams=5)
        with smart_open_lib.smart_open(test_file) as bz2f:
            self.assertEqual(bz2f.read(), self.TEXT * 5)
        self.cleanup_temp_bz2(test_file)


class S3OpenTest(unittest.TestCase):

    @mock_s3
    def test_r(self):
        """Reading a UTF string should work."""
        text = u"физкульт-привет!"

        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='bucket')
        key = s3.Object('bucket', 'key')
        key.put(Body=text.encode('utf-8'))

        with smart_open.smart_open('s3://bucket/key', "rb") as fin:
            self.assertEqual(fin.read(), text.encode('utf-8'))

        with smart_open.smart_open('s3://bucket/key', "r", encoding='utf-8') as fin:
            self.assertEqual(fin.read(), text)

    def test_bad_mode(self):
        """Bad mode should raise and exception."""
        uri = smart_open_lib._parse_uri("s3://bucket/key")
        self.assertRaises(NotImplementedError, smart_open.smart_open, uri, "x")

    @mock_s3
    def test_rw_encoding(self):
        """Should read and write text, respecting encodings, etc."""
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='bucket')

        key = "s3://bucket/key"
        text = u"расцветали яблони и груши"

        with smart_open.smart_open(key, "w", encoding="koi8-r") as fout:
            fout.write(text)

        with smart_open.smart_open(key, "r", encoding="koi8-r") as fin:
            self.assertEqual(text, fin.read())

        with smart_open.smart_open(key, "rb") as fin:
            self.assertEqual(text.encode("koi8-r"), fin.read())

        with smart_open.smart_open(key, "r", encoding="euc-jp") as fin:
            self.assertRaises(UnicodeDecodeError, fin.read)

        with smart_open.smart_open(key, "r", encoding="euc-jp", errors="replace") as fin:
            fin.read()

    @mock_s3
    def test_rw_gzip(self):
        """Should read/write gzip files, implicitly and explicitly."""
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='bucket')
        key = "s3://bucket/key.gz"

        text = u"не слышны в саду даже шорохи"
        with smart_open.smart_open(key, "wb") as fout:
            fout.write(text.encode("utf-8"))

        #
        # Check that what we've created is a gzip.
        #
        with smart_open.smart_open(key, "rb", ignore_extension=True) as fin:
            gz = gzip.GzipFile(fileobj=fin)
            self.assertEqual(gz.read().decode("utf-8"), text)

        #
        # We should be able to read it back as well.
        #
        with smart_open.smart_open(key, "rb") as fin:
            self.assertEqual(fin.read().decode("utf-8"), text)

    @mock_s3
    @mock.patch('smart_open.smart_open_lib._inspect_kwargs', mock.Mock(return_value={}))
    def test_gzip_write_mode(self):
        """Should always open in binary mode when writing through a codec."""
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='bucket')

        with mock.patch('smart_open.s3.open') as mock_open:
            smart_open.smart_open("s3://bucket/key.gz", "wb")
            mock_open.assert_called_with('bucket', 'key.gz', 'wb')

    @mock_s3
    @mock.patch('smart_open.smart_open_lib._inspect_kwargs', mock.Mock(return_value={}))
    def test_gzip_read_mode(self):
        """Should always open in binary mode when reading through a codec."""
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='bucket')
        key = "s3://bucket/key.gz"

        text = u"если-б я был султан и имел трёх жён, то тройной красотой был бы окружён"
        with smart_open.smart_open(key, "wb") as fout:
            fout.write(text.encode("utf-8"))

        with mock.patch('smart_open.s3.open') as mock_open:
            smart_open.smart_open(key, "r")
            mock_open.assert_called_with('bucket', 'key.gz', 'rb')

    @mock_s3
    def test_read_encoding(self):
        """Should open the file with the correct encoding, explicit text read."""
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='bucket')
        key = "s3://bucket/key.txt"
        text = u'это знала ева, это знал адам, колеса любви едут прямо по нам'
        with smart_open.smart_open(key, 'wb') as fout:
            fout.write(text.encode('koi8-r'))
        with smart_open.smart_open(key, 'r', encoding='koi8-r') as fin:
            actual = fin.read()
        self.assertEqual(text, actual)

    @mock_s3
    def test_read_encoding_implicit_text(self):
        """Should open the file with the correct encoding, implicit text read."""
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='bucket')
        key = "s3://bucket/key.txt"
        text = u'это знала ева, это знал адам, колеса любви едут прямо по нам'
        with smart_open.smart_open(key, 'wb') as fout:
            fout.write(text.encode('koi8-r'))
        with smart_open.smart_open(key, encoding='koi8-r') as fin:
            actual = fin.read()
        self.assertEqual(text, actual)

    @mock_s3
    def test_write_encoding(self):
        """Should open the file for writing with the correct encoding."""
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='bucket')
        key = "s3://bucket/key.txt"
        text = u'какая боль, какая боль, аргентина - ямайка, 5-0'

        with smart_open.smart_open(key, 'w', encoding='koi8-r') as fout:
            fout.write(text)
        with smart_open.smart_open(key, encoding='koi8-r') as fin:
            actual = fin.read()
        self.assertEqual(text, actual)

    @mock_s3
    def test_write_bad_encoding_strict(self):
        """Should open the file for writing with the correct encoding."""
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='bucket')
        key = "s3://bucket/key.txt"
        text = u'欲しい気持ちが成長しすぎて'

        with self.assertRaises(UnicodeEncodeError):
            with smart_open.smart_open(key, 'w', encoding='koi8-r', errors='strict') as fout:
                fout.write(text)

    @mock_s3
    def test_write_bad_encoding_replace(self):
        """Should open the file for writing with the correct encoding."""
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='bucket')
        key = "s3://bucket/key.txt"
        text = u'欲しい気持ちが成長しすぎて'
        expected = u'?' * len(text)

        with smart_open.smart_open(key, 'w', encoding='koi8-r', errors='replace') as fout:
            fout.write(text)
        with smart_open.smart_open(key, encoding='koi8-r') as fin:
            actual = fin.read()
        self.assertEqual(expected, actual)

    @mock_s3
    def test_write_text_gzip(self):
        """Should open the file for writing with the correct encoding."""
        s3 = boto3.resource('s3')
        s3.create_bucket(Bucket='bucket')
        key = "s3://bucket/key.txt.gz"
        text = u'какая боль, какая боль, аргентина - ямайка, 5-0'

        with smart_open.smart_open(key, 'w', encoding='utf-8') as fout:
            fout.write(text)
        with smart_open.smart_open(key, 'r', encoding='utf-8') as fin:
            actual = fin.read()
        self.assertEqual(text, actual)

    @mock.patch('smart_open.s3.Reader')
    def test_transport_params_is_not_mutable(self, mock_open):
        smart_open.open('s3://access_key:secret_key@host@bucket/key')
        smart_open.open('s3://bucket/key')

        #
        # The first call should have a non-null session, because the session
        # keys were explicitly specified in the URL.  The second call should
        # _not_ have a session.
        #
        self.assertIsNone(mock_open.call_args_list[1][1]['session'])
        self.assertIsNotNone(mock_open.call_args_list[0][1]['session'])

    @mock.patch('smart_open.s3.Reader')
    def test_respects_endpoint_url_read(self, mock_open):
        url = 's3://key_id:secret_key@play.min.io:9000@smart-open-test/README.rst'
        smart_open.open(url)

        expected = {'endpoint_url': 'https://play.min.io:9000'}
        self.assertEqual(mock_open.call_args[1]['resource_kwargs'], expected)

    @mock.patch('smart_open.s3.MultipartWriter')
    def test_respects_endpoint_url_write(self, mock_open):
        url = 's3://key_id:secret_key@play.min.io:9000@smart-open-test/README.rst'
        smart_open.open(url, 'wb')

        expected = {'endpoint_url': 'https://play.min.io:9000'}
        self.assertEqual(mock_open.call_args[1]['resource_kwargs'], expected)


def function(a, b, c, foo='bar', baz='boz'):
    pass


class CheckKwargsTest(unittest.TestCase):
    def test(self):
        kwargs = {'foo': 123, 'bad': False}
        expected = {'foo': 123}
        actual = smart_open.smart_open_lib._check_kwargs(function, kwargs)
        self.assertEqual(expected, actual)


if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s', level=logging.DEBUG)
    unittest.main()
