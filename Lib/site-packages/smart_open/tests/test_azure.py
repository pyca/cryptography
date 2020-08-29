# -*- coding: utf-8 -*-
#
# Copyright (C) 2020 Radim Rehurek <radim@rare-technologies.com>
# Copyright (C) 2020 Nicolas Mitchell <ncls.mitchell@gmail.com>
#
# This code is distributed under the terms and conditions
# from the MIT License (MIT).
#
import gzip
import io
import logging
import os
import time
import uuid
import unittest
from collections import OrderedDict

import smart_open
import smart_open.constants

import azure.storage.blob
import azure.common
import azure.core.exceptions

CONTAINER_NAME = 'test-smartopen-{}'.format(uuid.uuid4().hex)
BLOB_NAME = 'test-blob'
DISABLE_MOCKS = os.environ.get('SO_DISABLE_AZURE_MOCKS') == "1"

"""If mocks are disabled, allow to use the Azurite local Azure Storage API
https://github.com/Azure/Azurite
To use locally:
docker run -p 10000:10000 -p 10001:10001 mcr.microsoft.com/azure-storage/azurite
"""
_AZURITE_DEFAULT_CONNECT_STR = 'DefaultEndpointsProtocol=http;' \
    'AccountName=devstoreaccount1;' \
    'AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/' \
    'K1SZFPTOtr/KBHBeksoGMGw==;' \
    'BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;'
CONNECT_STR = os.environ.get('SO_AZURE_CONNECTION_STRING', _AZURITE_DEFAULT_CONNECT_STR)

logger = logging.getLogger(__name__)


class FakeBlobClient(object):
    # From Azure's BlobClient API
    # https://azuresdkdocs.blob.core.windows.net/$web/python/azure-storage-blob/12.0.0/azure.storage.blob.html#azure.storage.blob.BlobClient
    def __init__(self, container_client, name):
        self._container_client = container_client  # type: FakeContainerClient
        self.blob_name = name
        self.metadata = dict(size=0)
        self.__contents = io.BytesIO()
        self._staged_contents = {}

    def commit_block_list(self, block_list):
        data = b''.join([self._staged_contents[block_blob['id']] for block_blob in block_list])
        self.__contents = io.BytesIO(data)
        self.set_blob_metadata(dict(size=len(data)))
        self._container_client.register_blob_client(self)

    def delete_blob(self):
        self._container_client.delete_blob(self)

    def download_blob(self, offset=None, length=None):
        if offset is None:
            return self.__contents
        self.__contents.seek(offset)
        return io.BytesIO(self.__contents.read(length))

    def get_blob_properties(self):
        return self.metadata

    def set_blob_metadata(self, metadata):
        self.metadata = metadata

    def stage_block(self, block_id, data):
        self._staged_contents[block_id] = data

    def upload_blob(self, data, length=None, metadata=None):
        if metadata is not None:
            self.set_blob_metadata(metadata)
        self.__contents = io.BytesIO(data[:length])
        self.set_blob_metadata(dict(size=len(data[:length])))
        self._container_client.register_blob_client(self)


class FakeBlobClientTest(unittest.TestCase):
    def setUp(self):
        self.blob_service_client = FakeBlobServiceClient.from_connection_string(CONNECT_STR)
        self.container_client = FakeContainerClient(self.blob_service_client, 'test-container')
        self.blob_client = FakeBlobClient(self.container_client, 'test-blob.txt')

    def test_delete_blob(self):
        data = b'Lorem ipsum'
        self.blob_client.upload_blob(data)
        self.assertEqual(self.container_client.list_blobs(), [self.blob_client.blob_name])
        self.blob_client.delete_blob()
        self.assertEqual(self.container_client.list_blobs(), [])

    def test_upload_blob(self):
        data = b'Lorem ipsum'
        self.blob_client.upload_blob(data)
        actual = self.blob_client.download_blob().read()
        self.assertEqual(actual, data)


class FakeContainerClient(object):
    # From Azure's ContainerClient API
    # https://docs.microsoft.com/fr-fr/python/api/azure-storage-blob/azure.storage.blob.containerclient?view=azure-python
    def __init__(self, blob_service_client, name):
        self.blob_service_client = blob_service_client  # type: FakeBlobServiceClient
        self.container_name = name
        self.metadata = {}
        self.__blob_clients = OrderedDict()

    def create_container(self, metadata):
        self.metadata = metadata

    def delete_blob(self, blob):
        del self.__blob_clients[blob.blob_name]

    def delete_blobs(self):
        self.__blob_clients = OrderedDict()

    def delete_container(self):
        self.blob_service_client.delete_container(self.container_name)

    def download_blob(self, blob):
        if blob.blob_name not in list(self.__blob_clients.keys()):
            raise azure.core.exceptions.ResourceNotFoundError('The specified blob does not exist.')
        blob_client = self.__blob_clients[blob.blob_name]
        blob_content = blob_client.download_blob()
        return blob_content

    def get_blob_client(self, blob_name):
        return self.__blob_clients.get(blob_name, FakeBlobClient(self, blob_name))

    def get_container_properties(self):
        return self.metadata

    def list_blobs(self):
        return list(self.__blob_clients.keys())

    def upload_blob(self, blob_name, data):
        blob_client = FakeBlobClient(self, blob_name)
        blob_client.upload_blob(data)
        self.__blob_clients[blob_name] = blob_client

    def register_blob_client(self, blob_client):
        self.__blob_clients[blob_client.blob_name] = blob_client


class FakeContainerClientTest(unittest.TestCase):
    def setUp(self):
        self.blob_service_client = FakeBlobServiceClient.from_connection_string(CONNECT_STR)
        self.container_client = FakeContainerClient(self.blob_service_client, 'test-container')

    def test_nonexistent_blob(self):
        blob_client = self.container_client.get_blob_client('test-blob.txt')
        with self.assertRaises(azure.core.exceptions.ResourceNotFoundError):
            self.container_client.download_blob(blob_client)

    def test_delete_blob(self):
        blob_name = 'test-blob.txt'
        data = b'Lorem ipsum'
        self.container_client.upload_blob(blob_name, data)
        self.assertEqual(self.container_client.list_blobs(), [blob_name])
        blob_client = FakeBlobClient(self.container_client, 'test-blob.txt')
        self.container_client.delete_blob(blob_client)
        self.assertEqual(self.container_client.list_blobs(), [])

    def test_delete_blobs(self):
        blob_name_1 = 'test-blob-1.txt'
        blob_name_2 = 'test-blob-2.txt'
        data = b'Lorem ipsum'
        self.container_client.upload_blob(blob_name_1, data)
        self.container_client.upload_blob(blob_name_2, data)
        self.assertEqual(self.container_client.list_blobs(), [blob_name_1, blob_name_2])

    def test_delete_container(self):
        container_name = 'test-container'
        container_client = self.blob_service_client.create_container(container_name)
        self.assertEqual(self.blob_service_client.get_container_client(container_name).container_name,
                         container_name)
        container_client.delete_container()
        with self.assertRaises(azure.core.exceptions.ResourceNotFoundError):
            self.blob_service_client.get_container_client(container_name)

    def test_list_blobs(self):
        blob_name_1 = 'test-blob-1.txt'
        blob_name_2 = 'test-blob-2.txt'
        data = b'Lorem ipsum'
        self.container_client.upload_blob(blob_name_1, data)
        self.container_client.upload_blob(blob_name_2, data)
        self.assertEqual(self.container_client.list_blobs(), [blob_name_1, blob_name_2])
        self.container_client.delete_blobs()
        self.assertEqual(self.container_client.list_blobs(), [])

    def test_upload_blob(self):
        blob_name = 'test-blob.txt'
        data = b'Lorem ipsum'
        self.container_client.upload_blob(blob_name, data)
        blob_client = self.container_client.get_blob_client(blob_name)
        actual = self.container_client.download_blob(blob_client).read()
        self.assertEqual(actual, data)


class FakeBlobServiceClient(object):
    # From Azure's BlobServiceClient API
    # https://docs.microsoft.com/fr-fr/python/api/azure-storage-blob/azure.storage.blob.blobserviceclient?view=azure-python
    def __init__(self, account_url, credential=None, **kwargs):
        self._account_url = account_url
        self._credential = credential

        self.__container_clients = OrderedDict()

    @classmethod
    def from_connection_string(cls, conn_str, credential=None, **kwargs):
        account_url, secondary, credential = \
            azure.storage.blob._shared.base_client.parse_connection_str(conn_str, credential, 'blob')
        if 'secondary_hostname' not in kwargs:
            kwargs['secondary_hostname'] = secondary
        return cls(account_url, credential=credential, **kwargs)

    def create_container(self, container_name, metadata=None):
        if container_name in self.__container_clients:
            raise azure.core.exceptions.ResourceExistsError('The specified container already exists.')
        container_client = FakeContainerClient(self, container_name)
        if metadata is not None:
            container_client.create_container(metadata)
        self.__container_clients[container_name] = container_client
        return container_client

    def delete_container(self, container_name):
        del self.__container_clients[container_name]

    def get_blob_client(self, container, blob):
        container = self.__container_clients[container]
        blob_client = container.get_blob_client(blob)
        return blob_client

    def get_container_client(self, container):
        if container not in self.__container_clients:
            raise azure.core.exceptions.ResourceNotFoundError('The specified container does not exist.')
        return self.__container_clients[container]


class FakeBlobServiceClientTest(unittest.TestCase):
    def setUp(self):
        self.blob_service_client = FakeBlobServiceClient.from_connection_string(CONNECT_STR)

    def test_nonexistent_container(self):
        with self.assertRaises(azure.core.exceptions.ResourceNotFoundError):
            self.blob_service_client.get_container_client('test-container')

    def test_create_container(self):
        container_name = 'test_container'
        expected = self.blob_service_client.create_container(container_name)
        actual = self.blob_service_client.get_container_client(container_name)
        self.assertEqual(actual, expected)

    def test_duplicate_container(self):
        container_name = 'test-container'
        self.blob_service_client.create_container(container_name)
        with self.assertRaises(azure.core.exceptions.ResourceExistsError):
            self.blob_service_client.create_container(container_name)

    def test_delete_container(self):
        container_name = 'test_container'
        self.blob_service_client.create_container(container_name)
        self.blob_service_client.delete_container(container_name)
        with self.assertRaises(azure.core.exceptions.ResourceNotFoundError):
            self.blob_service_client.get_container_client(container_name)

    def test_get_blob_client(self):
        container_name = 'test_container'
        blob_name = 'test-blob.txt'
        self.blob_service_client.create_container(container_name)
        blob_client = self.blob_service_client.get_blob_client(container_name, blob_name)
        self.assertEqual(blob_client.blob_name, blob_name)


if DISABLE_MOCKS:
    CLIENT = azure.storage.blob.BlobServiceClient.from_connection_string(CONNECT_STR)
else:
    CLIENT = FakeBlobServiceClient.from_connection_string(CONNECT_STR)


def get_container_client():
    return CLIENT.get_container_client(container=CONTAINER_NAME)


def cleanup_container():
    container_client = get_container_client()
    container_client.delete_blobs()


def put_to_container(blob_name, contents, num_attempts=12, sleep_time=5):
    logger.debug('%r', locals())

    #
    # In real life, it can take a few seconds for the container to become ready.
    # If we try to write to the key while the container while it isn't ready, we
    # will get a StorageError: NotFound.
    #
    for attempt in range(num_attempts):
        try:
            container_client = get_container_client()
            container_client.upload_blob(blob_name, contents)
            return
        except azure.common.AzureHttpError as err:
            logger.error('caught %r, retrying', err)
            time.sleep(sleep_time)

    assert False, 'failed to create container %s after %d attempts' % (CONTAINER_NAME, num_attempts)


def setUpModule():  # noqa
    """Called once by unittest when initializing this module.  Set up the
    test Azure container.
    """
    CLIENT.create_container(CONTAINER_NAME)


def tearDownModule():  # noqa
    """Called once by unittest when tearing down this module.  Empty and
    removes the test Azure container.
    """
    try:
        container_client = get_container_client()
        container_client.delete_container()
    except azure.common.AzureHttpError:
        pass


class ReaderTest(unittest.TestCase):

    def tearDown(self):
        cleanup_container()

    def test_iter(self):
        """Are Azure Blob Storage files iterated over correctly?"""
        expected = u"hello wořld\nhow are you?".encode('utf8')
        blob_name = "test_iter_%s" % BLOB_NAME
        put_to_container(blob_name, contents=expected)

        # connect to fake Azure Blob Storage and read from the fake key we filled above
        fin = smart_open.azure.Reader(CONTAINER_NAME, blob_name, CLIENT)
        output = [line.rstrip(b'\n') for line in fin]
        self.assertEqual(output, expected.split(b'\n'))

    def test_iter_context_manager(self):
        # same thing but using a context manager
        expected = u"hello wořld\nhow are you?".encode('utf8')
        blob_name = "test_iter_context_manager_%s" % BLOB_NAME
        put_to_container(blob_name, contents=expected)

        with smart_open.azure.Reader(CONTAINER_NAME, blob_name, CLIENT) as fin:
            output = [line.rstrip(b'\n') for line in fin]
            self.assertEqual(output, expected.split(b'\n'))

    def test_read(self):
        """Are Azure Blob Storage files read correctly?"""
        content = u"hello wořld\nhow are you?".encode('utf8')
        blob_name = "test_read_%s" % BLOB_NAME
        put_to_container(blob_name, contents=content)
        logger.debug('content: %r len: %r', content, len(content))

        fin = smart_open.azure.Reader(CONTAINER_NAME, blob_name, CLIENT)
        self.assertEqual(content[:6], fin.read(6))
        self.assertEqual(content[6:14], fin.read(8))  # ř is 2 bytes
        self.assertEqual(content[14:], fin.read())  # read the rest

    def test_seek_beginning(self):
        """Does seeking to the beginning of Azure Blob Storage files work correctly?"""
        content = u"hello wořld\nhow are you?".encode('utf8')
        blob_name = "test_seek_beginning_%s" % BLOB_NAME
        put_to_container(blob_name, contents=content)

        fin = smart_open.azure.Reader(CONTAINER_NAME, blob_name, CLIENT)
        self.assertEqual(content[:6], fin.read(6))
        self.assertEqual(content[6:14], fin.read(8))  # ř is 2 bytes

        fin.seek(0)
        self.assertEqual(content, fin.read())  # no size given => read whole file

        fin.seek(0)
        self.assertEqual(content, fin.read(-1))  # same thing

    def test_seek_start(self):
        """Does seeking from the start of Azure Blob Storage files work correctly?"""
        content = u"hello wořld\nhow are you?".encode('utf8')
        blob_name = "test_seek_start_%s" % BLOB_NAME
        put_to_container(blob_name, contents=content)

        fin = smart_open.azure.Reader(CONTAINER_NAME, blob_name, CLIENT)
        seek = fin.seek(6)
        self.assertEqual(seek, 6)
        self.assertEqual(fin.tell(), 6)
        self.assertEqual(fin.read(6), u'wořld'.encode('utf-8'))

    def test_seek_current(self):
        """Does seeking from the middle of Azure Blob Storage files work correctly?"""
        content = u"hello wořld\nhow are you?".encode('utf8')
        blob_name = "test_seek_current_%s" % BLOB_NAME
        put_to_container(blob_name, contents=content)

        fin = smart_open.azure.Reader(CONTAINER_NAME, blob_name, CLIENT)
        self.assertEqual(fin.read(5), b'hello')
        seek = fin.seek(1, whence=smart_open.constants.WHENCE_CURRENT)
        self.assertEqual(seek, 6)
        self.assertEqual(fin.read(6), u'wořld'.encode('utf-8'))

    def test_seek_end(self):
        """Does seeking from the end of Azure Blob Storage files work correctly?"""
        content = u"hello wořld\nhow are you?".encode('utf8')
        blob_name = "test_seek_end_%s" % BLOB_NAME
        put_to_container(blob_name, contents=content)

        fin = smart_open.azure.Reader(CONTAINER_NAME, blob_name, CLIENT)
        seek = fin.seek(-4, whence=smart_open.constants.WHENCE_END)
        self.assertEqual(seek, len(content) - 4)
        self.assertEqual(fin.read(), b'you?')

    def test_detect_eof(self):
        content = u"hello wořld\nhow are you?".encode('utf8')
        blob_name = "test_detect_eof_%s" % BLOB_NAME
        put_to_container(blob_name, contents=content)

        fin = smart_open.azure.Reader(CONTAINER_NAME, blob_name, CLIENT)
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
        blob_name = "test_read_gzip_%s" % BLOB_NAME
        put_to_container(blob_name, contents=buf.getvalue())

        #
        # Make sure we're reading things correctly.
        #
        with smart_open.azure.Reader(CONTAINER_NAME, blob_name, CLIENT) as fin:
            self.assertEqual(fin.read(), buf.getvalue())

        #
        # Make sure the buffer we wrote is legitimate gzip.
        #
        sanity_buf = io.BytesIO(buf.getvalue())
        with gzip.GzipFile(fileobj=sanity_buf) as zipfile:
            self.assertEqual(zipfile.read(), expected)

        logger.debug('starting actual test')
        with smart_open.azure.Reader(CONTAINER_NAME, blob_name, CLIENT) as fin:
            with gzip.GzipFile(fileobj=fin) as zipfile:
                actual = zipfile.read()

        self.assertEqual(expected, actual)

    def test_readline(self):
        content = b'englishman\nin\nnew\nyork\n'
        blob_name = "test_readline_%s" % BLOB_NAME
        put_to_container(blob_name, contents=content)

        with smart_open.azure.Reader(CONTAINER_NAME, blob_name, CLIENT) as fin:
            fin.readline()
            self.assertEqual(fin.tell(), content.index(b'\n')+1)

            fin.seek(0)
            actual = list(fin)
            self.assertEqual(fin.tell(), len(content))

        expected = [b'englishman\n', b'in\n', b'new\n', b'york\n']
        self.assertEqual(expected, actual)

    def test_readline_tiny_buffer(self):
        content = b'englishman\nin\nnew\nyork\n'
        blob_name = "test_readline_tiny_buffer_%s" % BLOB_NAME
        put_to_container(blob_name, contents=content)

        with smart_open.azure.Reader(
                CONTAINER_NAME,
                blob_name,
                CLIENT,
                buffer_size=8
        ) as fin:
            actual = list(fin)

        expected = [b'englishman\n', b'in\n', b'new\n', b'york\n']
        self.assertEqual(expected, actual)

    def test_read0_does_not_return_data(self):
        content = b'englishman\nin\nnew\nyork\n'
        blob_name = "test_read0_does_not_return_data_%s" % BLOB_NAME
        put_to_container(blob_name, contents=content)

        with smart_open.azure.Reader(CONTAINER_NAME, blob_name, CLIENT) as fin:
            data = fin.read(0)

        self.assertEqual(data, b'')

    def test_read_past_end(self):
        content = b'englishman\nin\nnew\nyork\n'
        blob_name = "test_read_past_end_%s" % BLOB_NAME
        put_to_container(blob_name, contents=content)

        with smart_open.azure.Reader(CONTAINER_NAME, blob_name, CLIENT) as fin:
            data = fin.read(100)

        self.assertEqual(data, content)


class WriterTest(unittest.TestCase):
    """Test writing into Azure Blob files."""

    def tearDown(self):
        cleanup_container()

    def test_write_01(self):
        """Does writing into Azure Blob Storage work correctly?"""
        test_string = u"žluťoučký koníček".encode('utf8')
        blob_name = "test_write_01_%s" % BLOB_NAME

        with smart_open.azure.Writer(CONTAINER_NAME, blob_name, CLIENT) as fout:
            fout.write(test_string)

        output = list(smart_open.open(
            "azure://%s/%s" % (CONTAINER_NAME, blob_name),
            "rb",
            transport_params=dict(client=CLIENT),
        ))
        self.assertEqual(output, [test_string])

    def test_incorrect_input(self):
        """Does azure write fail on incorrect input?"""
        blob_name = "test_incorrect_input_%s" % BLOB_NAME
        try:
            with smart_open.azure.Writer(CONTAINER_NAME, blob_name, CLIENT) as fin:
                fin.write(None)
        except TypeError:
            pass
        else:
            self.fail()

    def test_write_02(self):
        """Does Azure Blob Storage write unicode-utf8 conversion work?"""
        blob_name = "test_write_02_%s" % BLOB_NAME
        smart_open_write = smart_open.azure.Writer(CONTAINER_NAME, blob_name, CLIENT)
        smart_open_write.tell()
        logger.info("smart_open_write: %r", smart_open_write)
        with smart_open_write as fout:
            fout.write(u"testžížáč".encode("utf-8"))
            self.assertEqual(fout.tell(), 14)

    def test_write_03(self):
        """Do multiple writes less than the min_part_size work correctly?"""
        # write
        blob_name = "test_write_03_%s" % BLOB_NAME
        min_part_size = 256 * 1024
        smart_open_write = smart_open.azure.Writer(
            CONTAINER_NAME, blob_name, CLIENT, min_part_size=min_part_size
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
            self.assertEqual(fout._current_part.tell(), 0)
            self.assertEqual(fout._total_parts, 1)

            fourth_part = b"t" * 1
            fout.write(fourth_part)
            local_write.write(fourth_part)
            self.assertEqual(fout._current_part.tell(), 1)
            self.assertEqual(fout._total_parts, 1)

        # read back the same key and check its content
        uri = "azure://%s/%s" % (CONTAINER_NAME, blob_name)
        output = list(smart_open.open(uri, transport_params=dict(client=CLIENT)))
        local_write.seek(0)
        actual = [line.decode("utf-8") for line in list(local_write)]
        self.assertEqual(output, actual)

    def test_write_03a(self):
        """Do multiple writes greater than or equal to the min_part_size work correctly?"""
        min_part_size = 256 * 1024
        blob_name = "test_write_03_%s" % BLOB_NAME
        smart_open_write = smart_open.azure.Writer(
            CONTAINER_NAME, blob_name, CLIENT, min_part_size=min_part_size
        )
        local_write = io.BytesIO()

        with smart_open_write as fout:
            for i in range(1, 4):
                part = b"t" * min_part_size
                fout.write(part)
                local_write.write(part)
                self.assertEqual(fout._current_part.tell(), 0)
                self.assertEqual(fout._total_parts, i)

        # read back the same key and check its content
        uri = "azure://%s/%s" % (CONTAINER_NAME, blob_name)
        output = list(smart_open.open(uri, transport_params=dict(client=CLIENT)))
        local_write.seek(0)
        actual = [line.decode("utf-8") for line in list(local_write)]
        self.assertEqual(output, actual)

    def test_write_04(self):
        """Does writing no data cause key with an empty value to be created?"""
        blob_name = "test_write_04_%s" % BLOB_NAME
        smart_open_write = smart_open.azure.Writer(CONTAINER_NAME, blob_name, CLIENT)
        with smart_open_write as fout:  # noqa
            pass

        # read back the same key and check its content
        output = list(smart_open.open(
            "azure://%s/%s" % (CONTAINER_NAME, blob_name),
            transport_params=dict(client=CLIENT))
        )
        self.assertEqual(output, [])

    def test_gzip(self):
        expected = u'а не спеть ли мне песню... о любви'.encode('utf-8')
        blob_name = "test_gzip_%s" % BLOB_NAME
        with smart_open.azure.Writer(CONTAINER_NAME, blob_name, CLIENT) as fout:
            with gzip.GzipFile(fileobj=fout, mode='w') as zipfile:
                zipfile.write(expected)

        with smart_open.azure.Reader(CONTAINER_NAME, blob_name, CLIENT) as fin:
            with gzip.GzipFile(fileobj=fin) as zipfile:
                actual = zipfile.read()

        self.assertEqual(expected, actual)

    def test_buffered_writer_wrapper_works(self):
        """
        Ensure that we can wrap a smart_open azure stream in a BufferedWriter, which
        passes a memoryview object to the underlying stream in python >= 2.7
        """
        expected = u'не думай о секундах свысока'
        blob_name = "test_buffered_writer_wrapper_works_%s" % BLOB_NAME

        with smart_open.azure.Writer(CONTAINER_NAME, blob_name, CLIENT) as fout:
            with io.BufferedWriter(fout) as sub_out:
                sub_out.write(expected.encode('utf-8'))

        with smart_open.open(
                "azure://%s/%s" % (CONTAINER_NAME, blob_name),
                'rb',
                transport_params=dict(client=CLIENT)
        ) as fin:
            with io.TextIOWrapper(fin, encoding='utf-8') as text:
                actual = text.read()

        self.assertEqual(expected, actual)

    def test_binary_iterator(self):
        expected = u"выйду ночью в поле с конём".encode('utf-8').split(b' ')
        blob_name = "test_binary_iterator_%s" % BLOB_NAME
        put_to_container(blob_name=blob_name, contents=b"\n".join(expected))
        with smart_open.azure.open(CONTAINER_NAME, blob_name, 'rb', CLIENT) as fin:
            actual = [line.rstrip() for line in fin]
        self.assertEqual(expected, actual)

    def test_nonexisting_container(self):
        expected = u"выйду ночью в поле с конём".encode('utf-8')
        with self.assertRaises(azure.core.exceptions.ResourceNotFoundError):
            with smart_open.azure.open(
                    'thiscontainerdoesntexist',
                    'mykey',
                    'wb',
                    CLIENT
            ) as fout:
                fout.write(expected)

    def test_double_close(self):
        text = u'там за туманами, вечными, пьяными'.encode('utf-8')
        fout = smart_open.azure.open(CONTAINER_NAME, 'key', 'wb', CLIENT)
        fout.write(text)
        fout.close()
        fout.close()

    def test_flush_close(self):
        text = u'там за туманами, вечными, пьяными'.encode('utf-8')
        fout = smart_open.azure.open(CONTAINER_NAME, 'key', 'wb', CLIENT)
        fout.write(text)
        fout.flush()
        fout.close()
