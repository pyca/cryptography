# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 Radim Rehurek <me@radimrehurek.com>
#
# This code is distributed under the terms and conditions
# from the MIT License (MIT).
#
import gzip
import inspect
import io
import logging
import os
import time
import uuid
import unittest
try:
    from unittest import mock
except ImportError:
    import mock
import warnings
from collections import OrderedDict

import google.cloud
import google.api_core.exceptions

import smart_open
import smart_open.constants

BUCKET_NAME = 'test-smartopen-{}'.format(uuid.uuid4().hex)
BLOB_NAME = 'test-blob'
WRITE_BLOB_NAME = 'test-write-blob'
DISABLE_MOCKS = os.environ.get('SO_DISABLE_GCS_MOCKS') == "1"

RESUMABLE_SESSION_URI_TEMPLATE = (
    'https://www.googleapis.com/upload/storage/v1/b/'
    '%(bucket)s'
    '/o?uploadType=resumable&upload_id='
    '%(upload_id)s'
)

logger = logging.getLogger(__name__)


def ignore_resource_warnings():
    warnings.filterwarnings("ignore", category=ResourceWarning, message="unclosed.*<ssl.SSLSocket.*>")  # noqa


class FakeBucket(object):
    def __init__(self, client, name=None):
        self.client = client  # type: FakeClient
        self.name = name
        self.blobs = OrderedDict()
        self._exists = True

        #
        # This is simpler than creating a backend and metaclass to store the state of every bucket created
        #
        self.client.register_bucket(self)

    def blob(self, blob_id):
        return self.blobs.get(blob_id, FakeBlob(blob_id, self))

    def delete(self):
        self.client.delete_bucket(self)
        self._exists = False
        for blob in list(self.blobs.values()):
            blob.delete()

    def exists(self):
        return self._exists

    def get_blob(self, blob_id):
        try:
            return self.blobs[blob_id]
        except KeyError as e:
            raise google.cloud.exceptions.NotFound('Blob {} not found'.format(blob_id)) from e

    def list_blobs(self):
        return list(self.blobs.values())

    def delete_blob(self, blob):
        del self.blobs[blob.name]

    def register_blob(self, blob):
        if blob.name not in self.blobs.keys():
            self.blobs[blob.name] = blob

    def register_upload(self, upload):
        self.client.register_upload(upload)


class FakeBucketTest(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()
        self.bucket = FakeBucket(self.client, 'test-bucket')

    def test_blob_registers_with_bucket(self):
        blob_id = 'blob.txt'
        expected = FakeBlob(blob_id, self.bucket)
        actual = self.bucket.blob(blob_id)
        self.assertEqual(actual, expected)

    def test_blob_alternate_constuctor(self):
        blob_id = 'blob.txt'
        expected = self.bucket.blob(blob_id)
        actual = self.bucket.list_blobs()[0]
        self.assertEqual(actual, expected)

    def test_delete(self):
        blob_id = 'blob.txt'
        blob = FakeBlob(blob_id, self.bucket)
        self.bucket.delete()
        self.assertFalse(self.bucket.exists())
        self.assertFalse(blob.exists())

    def test_get_multiple_blobs(self):
        blob_one_id = 'blob_one.avro'
        blob_two_id = 'blob_two.parquet'
        blob_one = self.bucket.blob(blob_one_id)
        blob_two = self.bucket.blob(blob_two_id)
        actual_first_blob = self.bucket.get_blob(blob_one_id)
        actual_second_blob = self.bucket.get_blob(blob_two_id)
        self.assertEqual(actual_first_blob, blob_one)
        self.assertEqual(actual_second_blob, blob_two)

    def test_get_nonexistent_blob(self):
        with self.assertRaises(google.cloud.exceptions.NotFound):
            self.bucket.get_blob('test-blob')

    def test_list_blobs(self):
        blob_one = self.bucket.blob('blob_one.avro')
        blob_two = self.bucket.blob('blob_two.parquet')
        actual = self.bucket.list_blobs()
        expected = [blob_one, blob_two]
        self.assertEqual(actual, expected)


class FakeBlob(object):
    def __init__(self, name, bucket):
        self.name = name
        self._bucket = bucket  # type: FakeBucket
        self._exists = False
        self.__contents = io.BytesIO()

        self._create_if_not_exists()

    def create_resumable_upload_session(self):
        resumeable_upload_url = RESUMABLE_SESSION_URI_TEMPLATE % dict(
            bucket=self._bucket.name,
            upload_id=str(uuid.uuid4()),
        )
        upload = FakeBlobUpload(resumeable_upload_url, self)
        self._bucket.register_upload(upload)
        return resumeable_upload_url

    def delete(self):
        self._bucket.delete_blob(self)
        self._exists = False

    def download_as_string(self, start=0, end=None):
        # mimics Google's API by returning bytes, despite the method name
        # https://google-cloud-python.readthedocs.io/en/0.32.0/storage/blobs.html#google.cloud.storage.blob.Blob.download_as_string
        if end is None:
            end = self.__contents.tell()
        self.__contents.seek(start)
        return self.__contents.read(end - start)

    def exists(self, client=None):
        return self._exists

    def upload_from_string(self, data):
        # mimics Google's API by accepting bytes or str, despite the method name
        # https://google-cloud-python.readthedocs.io/en/0.32.0/storage/blobs.html#google.cloud.storage.blob.Blob.upload_from_string
        if isinstance(data, str):
            data = bytes(data, 'utf8')
        self.__contents = io.BytesIO(data)
        self.__contents.seek(0, io.SEEK_END)

    def write(self, data):
        self.upload_from_string(data)

    @property
    def bucket(self):
        return self._bucket

    @property
    def size(self):
        if self.__contents.tell() == 0:
            return None
        return self.__contents.tell()

    def _create_if_not_exists(self):
        self._bucket.register_blob(self)
        self._exists = True


class FakeBlobTest(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()
        self.bucket = FakeBucket(self.client, 'test-bucket')

    def test_create_resumable_upload_session(self):
        blob = FakeBlob('fake-blob', self.bucket)
        resumable_upload_url = blob.create_resumable_upload_session()
        self.assertTrue(resumable_upload_url in self.client.uploads)

    def test_delete(self):
        blob = FakeBlob('fake-blob', self.bucket)
        blob.delete()
        self.assertFalse(blob.exists())
        self.assertEqual(self.bucket.list_blobs(), [])

    def test_upload_download(self):
        blob = FakeBlob('fake-blob', self.bucket)
        contents = b'test'
        blob.upload_from_string(contents)
        self.assertEqual(blob.download_as_string(), b'test')
        self.assertEqual(blob.download_as_string(start=2), b'st')
        self.assertEqual(blob.download_as_string(end=2), b'te')
        self.assertEqual(blob.download_as_string(start=2, end=3), b's')

    def test_size(self):
        blob = FakeBlob('fake-blob', self.bucket)
        self.assertEqual(blob.size, None)
        blob.upload_from_string(b'test')
        self.assertEqual(blob.size, 4)


class FakeCredentials(object):
    def __init__(self, client):
        self.client = client  # type: FakeClient

    def before_request(self, *args, **kwargs):
        pass


class FakeClient(object):
    def __init__(self, credentials=None):
        if credentials is None:
            credentials = FakeCredentials(self)
        self._credentials = credentials  # type: FakeCredentials
        self.uploads = OrderedDict()
        self.__buckets = OrderedDict()

    def bucket(self, bucket_id):
        try:
            return self.__buckets[bucket_id]
        except KeyError as e:
            raise google.cloud.exceptions.NotFound('Bucket %s not found' % bucket_id) from e

    def create_bucket(self, bucket_id):
        bucket = FakeBucket(self, bucket_id)
        return bucket

    def get_bucket(self, bucket_id):
        return self.bucket(bucket_id)

    def register_bucket(self, bucket):
        if bucket.name in self.__buckets:
            raise google.cloud.exceptions.Conflict('Bucket %s already exists' % bucket.name)
        self.__buckets[bucket.name] = bucket

    def delete_bucket(self, bucket):
        del self.__buckets[bucket.name]

    def register_upload(self, upload):
        self.uploads[upload.url] = upload


class FakeClientTest(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()

    def test_nonexistent_bucket(self):
        with self.assertRaises(google.cloud.exceptions.NotFound):
            self.client.bucket('test-bucket')

    def test_bucket(self):
        bucket_id = 'test-bucket'
        bucket = FakeBucket(self.client, bucket_id)
        actual = self.client.bucket(bucket_id)
        self.assertEqual(actual, bucket)

    def test_duplicate_bucket(self):
        bucket_id = 'test-bucket'
        FakeBucket(self.client, bucket_id)
        with self.assertRaises(google.cloud.exceptions.Conflict):
            FakeBucket(self.client, bucket_id)

    def test_create_bucket(self):
        bucket_id = 'test-bucket'
        bucket = self.client.create_bucket(bucket_id)
        actual = self.client.get_bucket(bucket_id)
        self.assertEqual(actual, bucket)


class FakeBlobUpload(object):
    def __init__(self, url, blob):
        self.url = url
        self.blob = blob  # type: FakeBlob
        self._finished = False
        self.__contents = io.BytesIO()

    def write(self, data):
        self.__contents.write(data)

    def finish(self):
        if not self._finished:
            self.__contents.seek(0)
            data = self.__contents.read()
            self.blob.upload_from_string(data)
            self._finished = True

    def terminate(self):
        self.blob.delete()
        self.__contents = None


class FakeResponse(object):
    def __init__(self, status_code=200, text=None):
        self.status_code = status_code
        self.text = text


class FakeAuthorizedSession(object):
    def __init__(self, credentials):
        self._credentials = credentials  # type: FakeCredentials

    def delete(self, upload_url):
        upload = self._credentials.client.uploads.pop(upload_url)
        upload.terminate()

    def put(self, url, data=None, headers=None):
        upload = self._credentials.client.uploads[url]

        if data is not None:
            if hasattr(data, 'read'):
                upload.write(data.read())
            else:
                upload.write(data)
        if not headers.get('Content-Range', '').endswith(smart_open.gcs._UNKNOWN):
            upload.finish()
            return FakeResponse(200)
        return FakeResponse(smart_open.gcs._UPLOAD_INCOMPLETE_STATUS_CODES[0])

    @staticmethod
    def _blob_with_url(url, client):
        # type: (str, FakeClient) -> FakeBlobUpload
        return client.uploads.get(url)


class FakeAuthorizedSessionTest(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()
        self.credentials = FakeCredentials(self.client)
        self.session = FakeAuthorizedSession(self.credentials)
        self.bucket = FakeBucket(self.client, 'test-bucket')
        self.blob = FakeBlob('test-blob', self.bucket)
        self.upload_url = self.blob.create_resumable_upload_session()

    def test_delete(self):
        self.session.delete(self.upload_url)
        self.assertFalse(self.blob.exists())
        self.assertDictEqual(self.client.uploads, {})

    def test_unfinished_put_does_not_write_to_blob(self):
        data = io.BytesIO(b'test')
        headers = {
            'Content-Range': 'bytes 0-3/*',
            'Content-Length': str(4),
        }
        response = self.session.put(self.upload_url, data, headers=headers)
        self.assertIn(response.status_code, smart_open.gcs._UPLOAD_INCOMPLETE_STATUS_CODES)
        self.session._blob_with_url(self.upload_url, self.client)
        blob_contents = self.blob.download_as_string()
        self.assertEqual(blob_contents, b'')

    def test_finished_put_writes_to_blob(self):
        data = io.BytesIO(b'test')
        headers = {
            'Content-Range': 'bytes 0-3/4',
            'Content-Length': str(4),
        }
        response = self.session.put(self.upload_url, data, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.session._blob_with_url(self.upload_url, self.client)
        blob_contents = self.blob.download_as_string()
        data.seek(0)
        self.assertEqual(blob_contents, data.read())


if DISABLE_MOCKS:
    storage_client = google.cloud.storage.Client()
else:
    storage_client = FakeClient()


def get_bucket():
    return storage_client.bucket(BUCKET_NAME)


def get_blob():
    bucket = get_bucket()
    return bucket.blob(BLOB_NAME)


def cleanup_bucket():
    bucket = get_bucket()

    blobs = bucket.list_blobs()
    for blob in blobs:
        blob.delete()


def put_to_bucket(contents, num_attempts=12, sleep_time=5):
    logger.debug('%r', locals())

    #
    # In real life, it can take a few seconds for the bucket to become ready.
    # If we try to write to the key while the bucket while it isn't ready, we
    # will get a StorageError: NotFound.
    #
    for attempt in range(num_attempts):
        try:
            blob = get_blob()
            blob.upload_from_string(contents)
            return
        except google.cloud.exceptions.NotFound as err:
            logger.error('caught %r, retrying', err)
            time.sleep(sleep_time)

    assert False, 'failed to create bucket %s after %d attempts' % (BUCKET_NAME, num_attempts)


def mock_gcs(class_or_func):
    """Mock all methods of a class or a function."""
    if inspect.isclass(class_or_func):
        for attr in class_or_func.__dict__:
            if callable(getattr(class_or_func, attr)):
                setattr(class_or_func, attr, mock_gcs_func(getattr(class_or_func, attr)))
        return class_or_func
    else:
        return mock_gcs_func(class_or_func)


def mock_gcs_func(func):
    """Mock the function and provide additional required arguments."""
    assert callable(func), '%r is not a callable function' % func

    def inner(*args, **kwargs):
        #
        # Is it a function or a method? The latter requires a self parameter.
        #
        signature = inspect.signature(func)

        fake_session = FakeAuthorizedSession(storage_client._credentials)
        patched_client = mock.patch(
            'google.cloud.storage.Client',
            return_value=storage_client,
        )
        patched_session = mock.patch(
            'google.auth.transport.requests.AuthorizedSession',
            return_value=fake_session,
        )

        with patched_client, patched_session:
            if not hasattr(signature, 'self'):
                return func(*args, **kwargs)
            else:
                return func(signature.self, *args, **kwargs)

    return inner


def maybe_mock_gcs(func):
    if DISABLE_MOCKS:
        return func
    else:
        return mock_gcs(func)


@maybe_mock_gcs
def setUpModule():  # noqa
    """Called once by unittest when initializing this module.  Set up the
    test GCS bucket.
    """
    storage_client.create_bucket(BUCKET_NAME)


@maybe_mock_gcs
def tearDownModule():  # noqa
    """Called once by unittest when tearing down this module.  Empty and
    removes the test GCS bucket.
    """
    try:
        bucket = get_bucket()
        bucket.delete()
    except google.cloud.exceptions.NotFound:
        pass


@maybe_mock_gcs
class ReaderTest(unittest.TestCase):
    def setUp(self):
        # lower the multipart upload size, to speed up these tests
        self.old_min_buffer_size = smart_open.gcs.DEFAULT_BUFFER_SIZE
        smart_open.gcs.DEFAULT_BUFFER_SIZE = 5 * 1024**2

        ignore_resource_warnings()

    def tearDown(self):
        cleanup_bucket()

    def test_iter(self):
        """Are GCS files iterated over correctly?"""
        expected = u"hello wořld\nhow are you?".encode('utf8')
        put_to_bucket(contents=expected)

        # connect to fake GCS and read from the fake key we filled above
        fin = smart_open.gcs.Reader(BUCKET_NAME, BLOB_NAME)
        output = [line.rstrip(b'\n') for line in fin]
        self.assertEqual(output, expected.split(b'\n'))

    def test_iter_context_manager(self):
        # same thing but using a context manager
        expected = u"hello wořld\nhow are you?".encode('utf8')
        put_to_bucket(contents=expected)
        with smart_open.gcs.Reader(BUCKET_NAME, BLOB_NAME) as fin:
            output = [line.rstrip(b'\n') for line in fin]
            self.assertEqual(output, expected.split(b'\n'))

    def test_read(self):
        """Are GCS files read correctly?"""
        content = u"hello wořld\nhow are you?".encode('utf8')
        put_to_bucket(contents=content)
        logger.debug('content: %r len: %r', content, len(content))

        fin = smart_open.gcs.Reader(BUCKET_NAME, BLOB_NAME)
        self.assertEqual(content[:6], fin.read(6))
        self.assertEqual(content[6:14], fin.read(8))  # ř is 2 bytes
        self.assertEqual(content[14:], fin.read())  # read the rest

    def test_seek_beginning(self):
        """Does seeking to the beginning of GCS files work correctly?"""
        content = u"hello wořld\nhow are you?".encode('utf8')
        put_to_bucket(contents=content)

        fin = smart_open.gcs.Reader(BUCKET_NAME, BLOB_NAME)
        self.assertEqual(content[:6], fin.read(6))
        self.assertEqual(content[6:14], fin.read(8))  # ř is 2 bytes

        fin.seek(0)
        self.assertEqual(content, fin.read())  # no size given => read whole file

        fin.seek(0)
        self.assertEqual(content, fin.read(-1))  # same thing

    def test_seek_start(self):
        """Does seeking from the start of GCS files work correctly?"""
        content = u"hello wořld\nhow are you?".encode('utf8')
        put_to_bucket(contents=content)

        fin = smart_open.gcs.Reader(BUCKET_NAME, BLOB_NAME)
        seek = fin.seek(6)
        self.assertEqual(seek, 6)
        self.assertEqual(fin.tell(), 6)
        self.assertEqual(fin.read(6), u'wořld'.encode('utf-8'))

    def test_seek_current(self):
        """Does seeking from the middle of GCS files work correctly?"""
        content = u"hello wořld\nhow are you?".encode('utf8')
        put_to_bucket(contents=content)

        fin = smart_open.gcs.Reader(BUCKET_NAME, BLOB_NAME)
        self.assertEqual(fin.read(5), b'hello')
        seek = fin.seek(1, whence=smart_open.constants.WHENCE_CURRENT)
        self.assertEqual(seek, 6)
        self.assertEqual(fin.read(6), u'wořld'.encode('utf-8'))

    def test_seek_end(self):
        """Does seeking from the end of GCS files work correctly?"""
        content = u"hello wořld\nhow are you?".encode('utf8')
        put_to_bucket(contents=content)

        fin = smart_open.gcs.Reader(BUCKET_NAME, BLOB_NAME)
        seek = fin.seek(-4, whence=smart_open.constants.WHENCE_END)
        self.assertEqual(seek, len(content) - 4)
        self.assertEqual(fin.read(), b'you?')

    def test_detect_eof(self):
        content = u"hello wořld\nhow are you?".encode('utf8')
        put_to_bucket(contents=content)

        fin = smart_open.gcs.Reader(BUCKET_NAME, BLOB_NAME)
        fin.read()
        eof = fin.tell()
        self.assertEqual(eof, len(content))
        fin.seek(0, whence=smart_open.constants.WHENCE_END)
        self.assertEqual(eof, fin.tell())

    def test_read_gzip(self):
        expected = u'раcцветали яблони и груши, поплыли туманы над рекой...'.encode('utf-8')
        buf = io.BytesIO()
        buf.close = lambda: None  # keep buffer open so that we can .getvalue()
        with gzip.GzipFile(fileobj=buf, mode='w') as zipfile:
            zipfile.write(expected)
        put_to_bucket(contents=buf.getvalue())

        #
        # Make sure we're reading things correctly.
        #
        with smart_open.gcs.Reader(BUCKET_NAME, BLOB_NAME) as fin:
            self.assertEqual(fin.read(), buf.getvalue())

        #
        # Make sure the buffer we wrote is legitimate gzip.
        #
        sanity_buf = io.BytesIO(buf.getvalue())
        with gzip.GzipFile(fileobj=sanity_buf) as zipfile:
            self.assertEqual(zipfile.read(), expected)

        logger.debug('starting actual test')
        with smart_open.gcs.Reader(BUCKET_NAME, BLOB_NAME) as fin:
            with gzip.GzipFile(fileobj=fin) as zipfile:
                actual = zipfile.read()

        self.assertEqual(expected, actual)

    def test_readline(self):
        content = b'englishman\nin\nnew\nyork\n'
        put_to_bucket(contents=content)

        with smart_open.gcs.Reader(BUCKET_NAME, BLOB_NAME) as fin:
            fin.readline()
            self.assertEqual(fin.tell(), content.index(b'\n')+1)

            fin.seek(0)
            actual = list(fin)
            self.assertEqual(fin.tell(), len(content))

        expected = [b'englishman\n', b'in\n', b'new\n', b'york\n']
        self.assertEqual(expected, actual)

    def test_readline_tiny_buffer(self):
        content = b'englishman\nin\nnew\nyork\n'
        put_to_bucket(contents=content)

        with smart_open.gcs.Reader(BUCKET_NAME, BLOB_NAME, buffer_size=8) as fin:
            actual = list(fin)

        expected = [b'englishman\n', b'in\n', b'new\n', b'york\n']
        self.assertEqual(expected, actual)

    def test_read0_does_not_return_data(self):
        content = b'englishman\nin\nnew\nyork\n'
        put_to_bucket(contents=content)

        with smart_open.gcs.Reader(BUCKET_NAME, BLOB_NAME) as fin:
            data = fin.read(0)

        self.assertEqual(data, b'')

    def test_read_past_end(self):
        content = b'englishman\nin\nnew\nyork\n'
        put_to_bucket(contents=content)

        with smart_open.gcs.Reader(BUCKET_NAME, BLOB_NAME) as fin:
            data = fin.read(100)

        self.assertEqual(data, content)


@maybe_mock_gcs
class WriterTest(unittest.TestCase):
    """
    Test writing into GCS files.

    """
    def setUp(self):
        ignore_resource_warnings()

    def tearDown(self):
        cleanup_bucket()

    def test_write_01(self):
        """Does writing into GCS work correctly?"""
        test_string = u"žluťoučký koníček".encode('utf8')

        with smart_open.gcs.Writer(BUCKET_NAME, WRITE_BLOB_NAME) as fout:
            fout.write(test_string)

        with smart_open.open("gs://{}/{}".format(BUCKET_NAME, WRITE_BLOB_NAME), "rb") as fin:
            output = list(fin)

        self.assertEqual(output, [test_string])

    def test_incorrect_input(self):
        """Does gcs write fail on incorrect input?"""
        try:
            with smart_open.gcs.Writer(BUCKET_NAME, WRITE_BLOB_NAME) as fin:
                fin.write(None)
        except TypeError:
            pass
        else:
            self.fail()

    def test_write_02(self):
        """Does gcs write unicode-utf8 conversion work?"""
        smart_open_write = smart_open.gcs.Writer(BUCKET_NAME, WRITE_BLOB_NAME)
        smart_open_write.tell()
        logger.info("smart_open_write: %r", smart_open_write)
        with smart_open_write as fout:
            fout.write(u"testžížáč".encode("utf-8"))
            self.assertEqual(fout.tell(), 14)

    def test_write_03(self):
        """Do multiple writes less than the min_part_size work correctly?"""
        # write
        min_part_size = 256 * 1024
        smart_open_write = smart_open.gcs.Writer(
            BUCKET_NAME, WRITE_BLOB_NAME, min_part_size=min_part_size
        )
        local_write = io.BytesIO()

        with smart_open_write as fout:
            first_part = b"t" * 262141
            fout.write(first_part)
            local_write.write(first_part)
            self.assertEqual(fout._current_part.tell(), 262141)

            second_part = b"t\n"
            fout.write(second_part)
            local_write.write(second_part)
            self.assertEqual(fout._current_part.tell(), 262143)
            self.assertEqual(fout._total_parts, 0)

            third_part = b"t"
            fout.write(third_part)
            local_write.write(third_part)
            self.assertEqual(fout._current_part.tell(), 262144)
            self.assertEqual(fout._total_parts, 0)

            fourth_part = b"t" * 1
            fout.write(fourth_part)
            local_write.write(fourth_part)
            self.assertEqual(fout._current_part.tell(), 1)
            self.assertEqual(fout._total_parts, 1)

        # read back the same key and check its content
        output = list(smart_open.open("gs://{}/{}".format(BUCKET_NAME, WRITE_BLOB_NAME)))
        local_write.seek(0)
        actual = [line.decode("utf-8") for line in list(local_write)]
        self.assertEqual(output, actual)

    def test_write_03a(self):
        """Do multiple writes greater than the min_part_size work correctly?"""
        min_part_size = 256 * 1024
        smart_open_write = smart_open.gcs.Writer(
            BUCKET_NAME, WRITE_BLOB_NAME, min_part_size=min_part_size
        )
        local_write = io.BytesIO()

        with smart_open_write as fout:
            for i in range(1, 4):
                part = b"t" * (min_part_size + 1)
                fout.write(part)
                local_write.write(part)
                self.assertEqual(fout._current_part.tell(), i)
                self.assertEqual(fout._total_parts, i)

        # read back the same key and check its content
        output = list(smart_open.open("gs://{}/{}".format(BUCKET_NAME, WRITE_BLOB_NAME)))
        local_write.seek(0)
        actual = [line.decode("utf-8") for line in list(local_write)]
        self.assertEqual(output, actual)

    def test_write_03b(self):
        """Does writing a last chunk size equal to a multiple of the min_part_size work?"""
        min_part_size = 256 * 1024
        smart_open_write = smart_open.gcs.Writer(
            BUCKET_NAME, WRITE_BLOB_NAME, min_part_size=min_part_size
        )
        expected = b"t" * min_part_size * 2

        with smart_open_write as fout:
            fout.write(expected)
            self.assertEqual(fout._current_part.tell(), 262144)
            self.assertEqual(fout._total_parts, 1)

        # read back the same key and check its content
        with smart_open.open("gs://{}/{}".format(BUCKET_NAME, WRITE_BLOB_NAME)) as fin:
            output = fin.read().encode('utf-8')

        self.assertEqual(output, expected)

    def test_write_04(self):
        """Does writing no data cause key with an empty value to be created?"""
        smart_open_write = smart_open.gcs.Writer(BUCKET_NAME, WRITE_BLOB_NAME)
        with smart_open_write as fout:  # noqa
            pass

        # read back the same key and check its content
        output = list(smart_open.open("gs://{}/{}".format(BUCKET_NAME, WRITE_BLOB_NAME)))

        self.assertEqual(output, [])

    def test_gzip(self):
        expected = u'а не спеть ли мне песню... о любви'.encode('utf-8')
        with smart_open.gcs.Writer(BUCKET_NAME, WRITE_BLOB_NAME) as fout:
            with gzip.GzipFile(fileobj=fout, mode='w') as zipfile:
                zipfile.write(expected)

        with smart_open.gcs.Reader(BUCKET_NAME, WRITE_BLOB_NAME) as fin:
            with gzip.GzipFile(fileobj=fin) as zipfile:
                actual = zipfile.read()

        self.assertEqual(expected, actual)

    def test_buffered_writer_wrapper_works(self):
        """
        Ensure that we can wrap a smart_open gcs stream in a BufferedWriter, which
        passes a memoryview object to the underlying stream in python >= 2.7
        """
        expected = u'не думай о секундах свысока'

        with smart_open.gcs.Writer(BUCKET_NAME, WRITE_BLOB_NAME) as fout:
            with io.BufferedWriter(fout) as sub_out:
                sub_out.write(expected.encode('utf-8'))

        with smart_open.open("gs://{}/{}".format(BUCKET_NAME, WRITE_BLOB_NAME), 'rb') as fin:
            with io.TextIOWrapper(fin, encoding='utf-8') as text:
                actual = text.read()

        self.assertEqual(expected, actual)

    def test_binary_iterator(self):
        expected = u"выйду ночью в поле с конём".encode('utf-8').split(b' ')
        put_to_bucket(contents=b"\n".join(expected))
        with smart_open.gcs.open(BUCKET_NAME, BLOB_NAME, 'rb') as fin:
            actual = [line.rstrip() for line in fin]
        self.assertEqual(expected, actual)

    def test_nonexisting_bucket(self):
        expected = u"выйду ночью в поле с конём".encode('utf-8')
        with self.assertRaises(google.api_core.exceptions.NotFound):
            with smart_open.gcs.open('thisbucketdoesntexist', 'mykey', 'wb') as fout:
                fout.write(expected)

    def test_read_nonexisting_key(self):
        with self.assertRaises(google.api_core.exceptions.NotFound):
            with smart_open.gcs.open(BUCKET_NAME, 'my_nonexisting_key', 'rb') as fin:
                fin.read()

    def test_double_close(self):
        text = u'там за туманами, вечными, пьяными'.encode('utf-8')
        fout = smart_open.gcs.open(BUCKET_NAME, 'key', 'wb')
        fout.write(text)
        fout.close()
        fout.close()

    def test_flush_close(self):
        text = u'там за туманами, вечными, пьяными'.encode('utf-8')
        fout = smart_open.gcs.open(BUCKET_NAME, 'key', 'wb')
        fout.write(text)
        fout.flush()
        fout.close()

    def test_terminate(self):
        text = u'там за туманами, вечными, пьяными'.encode('utf-8')
        fout = smart_open.gcs.open(BUCKET_NAME, 'key', 'wb')
        fout.write(text)
        fout.terminate()

        with self.assertRaises(google.api_core.exceptions.NotFound):
            with smart_open.gcs.open(BUCKET_NAME, 'key', 'rb') as fin:
                fin.read()


@maybe_mock_gcs
class OpenTest(unittest.TestCase):
    def setUp(self):
        ignore_resource_warnings()

    def tearDown(self):
        cleanup_bucket()

    def test_read_never_returns_none(self):
        """read should never return None."""
        test_string = u"ветер по морю гуляет..."
        with smart_open.gcs.open(BUCKET_NAME, BLOB_NAME, "wb") as fout:
            self.assertEqual(fout.name, BLOB_NAME)
            fout.write(test_string.encode('utf8'))

        r = smart_open.gcs.open(BUCKET_NAME, BLOB_NAME, "rb")
        self.assertEqual(r.name, BLOB_NAME)
        self.assertEqual(r.read(), test_string.encode("utf-8"))
        self.assertEqual(r.read(), b"")
        self.assertEqual(r.read(), b"")

    def test_round_trip(self):
        test_string = u"ветер по морю гуляет..."
        url = 'gs://%s/%s' % (BUCKET_NAME, BLOB_NAME)
        with smart_open.open(url, "w") as fout:
            fout.write(test_string)

        with smart_open.open(url) as fin:
            actual = fin.read()

        self.assertEqual(test_string, actual)


class MakeRangeStringTest(unittest.TestCase):
    def test_no_stop(self):
        start, stop = 1, None
        self.assertEqual(smart_open.gcs._make_range_string(start, stop), 'bytes 1-/*')

    def test_stop(self):
        start, stop = 1, 2
        self.assertEqual(smart_open.gcs._make_range_string(start, stop), 'bytes 1-2/*')


if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s', level=logging.INFO)
    unittest.main()
