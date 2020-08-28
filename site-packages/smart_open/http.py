# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 Radim Rehurek <me@radimrehurek.com>
#
# This code is distributed under the terms and conditions
# from the MIT License (MIT).
#
"""Implements file-like objects for reading from http."""

import io
import logging
import os.path
import urllib.parse

import requests

from smart_open import bytebuffer, constants
import smart_open.utils

DEFAULT_BUFFER_SIZE = 128 * 1024
SCHEMES = ('http', 'https')

logger = logging.getLogger(__name__)


_HEADERS = {'Accept-Encoding': 'identity'}
"""The headers we send to the server with every HTTP request.

For now, we ask the server to send us the files as they are.
Sometimes, servers compress the file for more efficient transfer, in which case
the client (us) has to decompress them with the appropriate algorithm.
"""


def parse_uri(uri_as_string):
    split_uri = urllib.parse.urlsplit(uri_as_string)
    assert split_uri.scheme in SCHEMES

    uri_path = split_uri.netloc + split_uri.path
    uri_path = "/" + uri_path.lstrip("/")
    return dict(scheme=split_uri.scheme, uri_path=uri_path)


def open_uri(uri, mode, transport_params):
    kwargs = smart_open.utils.check_kwargs(open, transport_params)
    return open(uri, mode, **kwargs)


def open(uri, mode, kerberos=False, user=None, password=None, headers=None):
    """Implement streamed reader from a web site.

    Supports Kerberos and Basic HTTP authentication.

    Parameters
    ----------
    url: str
        The URL to open.
    mode: str
        The mode to open using.
    kerberos: boolean, optional
        If True, will attempt to use the local Kerberos credentials
    user: str, optional
        The username for authenticating over HTTP
    password: str, optional
        The password for authenticating over HTTP
    headers: dict, optional
        Any headers to send in the request. If ``None``, the default headers are sent:
        ``{'Accept-Encoding': 'identity'}``. To use no headers at all,
        set this variable to an empty dict, ``{}``.

    Note
    ----
    If neither kerberos or (user, password) are set, will connect
    unauthenticated, unless set separately in headers.

    """
    if mode == constants.READ_BINARY:
        fobj = SeekableBufferedInputBase(
            uri, mode, kerberos=kerberos,
            user=user, password=password, headers=headers
        )
        fobj.name = os.path.basename(urllib.parse.urlparse(uri).path)
        return fobj
    else:
        raise NotImplementedError('http support for mode %r not implemented' % mode)


class BufferedInputBase(io.BufferedIOBase):
    def __init__(self, url, mode='r', buffer_size=DEFAULT_BUFFER_SIZE,
                 kerberos=False, user=None, password=None, headers=None):
        if kerberos:
            import requests_kerberos
            auth = requests_kerberos.HTTPKerberosAuth()
        elif user is not None and password is not None:
            auth = (user, password)
        else:
            auth = None

        self.buffer_size = buffer_size
        self.mode = mode

        if headers is None:
            self.headers = _HEADERS.copy()
        else:
            self.headers = headers

        self.response = requests.get(url, auth=auth, stream=True, headers=self.headers)

        if not self.response.ok:
            self.response.raise_for_status()

        self._read_iter = self.response.iter_content(self.buffer_size)
        self._read_buffer = bytebuffer.ByteBuffer(buffer_size)
        self._current_pos = 0

        #
        # This member is part of the io.BufferedIOBase interface.
        #
        self.raw = None

    #
    # Override some methods from io.IOBase.
    #
    def close(self):
        """Flush and close this stream."""
        logger.debug("close: called")
        self.response = None
        self._read_iter = None

    def readable(self):
        """Return True if the stream can be read from."""
        return True

    def seekable(self):
        return False

    #
    # io.BufferedIOBase methods.
    #
    def detach(self):
        """Unsupported."""
        raise io.UnsupportedOperation

    def read(self, size=-1):
        """
        Mimics the read call to a filehandle object.
        """
        logger.debug("reading with size: %d", size)
        if self.response is None:
            return b''

        if size == 0:
            return b''
        elif size < 0 and len(self._read_buffer) == 0:
            retval = self.response.raw.read()
        elif size < 0:
            retval = self._read_buffer.read() + self.response.raw.read()
        else:
            while len(self._read_buffer) < size:
                logger.debug(
                    "http reading more content at current_pos: %d with size: %d",
                    self._current_pos, size,
                )
                bytes_read = self._read_buffer.fill(self._read_iter)
                if bytes_read == 0:
                    # Oops, ran out of data early.
                    retval = self._read_buffer.read()
                    self._current_pos += len(retval)

                    return retval

            # If we got here, it means we have enough data in the buffer
            # to return to the caller.
            retval = self._read_buffer.read(size)

        self._current_pos += len(retval)
        return retval

    def read1(self, size=-1):
        """This is the same as read()."""
        return self.read(size=size)

    def readinto(self, b):
        """Read up to len(b) bytes into b, and return the number of bytes
        read."""
        data = self.read(len(b))
        if not data:
            return 0
        b[:len(data)] = data
        return len(data)


class SeekableBufferedInputBase(BufferedInputBase):
    """
    Implement seekable streamed reader from a web site.
    Supports Kerberos and Basic HTTP authentication.
    """

    def __init__(self, url, mode='r', buffer_size=DEFAULT_BUFFER_SIZE,
                 kerberos=False, user=None, password=None, headers=None):
        """
        If Kerberos is True, will attempt to use the local Kerberos credentials.
        Otherwise, will try to use "basic" HTTP authentication via username/password.

        If none of those are set, will connect unauthenticated.
        """
        self.url = url

        if kerberos:
            import requests_kerberos
            self.auth = requests_kerberos.HTTPKerberosAuth()
        elif user is not None and password is not None:
            self.auth = (user, password)
        else:
            self.auth = None

        if headers is None:
            self.headers = _HEADERS.copy()
        else:
            self.headers = headers

        self.buffer_size = buffer_size
        self.mode = mode
        self.response = self._partial_request()

        if not self.response.ok:
            self.response.raise_for_status()

        logger.debug('self.response: %r, raw: %r', self.response, self.response.raw)

        self._seekable = True

        self.content_length = int(self.response.headers.get("Content-Length", -1))
        if self.content_length < 0:
            self._seekable = False
        if self.response.headers.get("Accept-Ranges", "none").lower() != "bytes":
            self._seekable = False

        self._read_iter = self.response.iter_content(self.buffer_size)
        self._read_buffer = bytebuffer.ByteBuffer(buffer_size)
        self._current_pos = 0

        #
        # This member is part of the io.BufferedIOBase interface.
        #
        self.raw = None

    def seek(self, offset, whence=0):
        """Seek to the specified position.

        :param int offset: The offset in bytes.
        :param int whence: Where the offset is from.

        Returns the position after seeking."""
        logger.debug('seeking to offset: %r whence: %r', offset, whence)
        if whence not in constants.WHENCE_CHOICES:
            raise ValueError('invalid whence, expected one of %r' % constants.WHENCE_CHOICES)

        if not self.seekable():
            raise OSError

        if whence == constants.WHENCE_START:
            new_pos = offset
        elif whence == constants.WHENCE_CURRENT:
            new_pos = self._current_pos + offset
        elif whence == constants.WHENCE_END:
            new_pos = self.content_length + offset

        new_pos = smart_open.utils.clamp(new_pos, 0, self.content_length)

        if self._current_pos == new_pos:
            return self._current_pos

        logger.debug("http seeking from current_pos: %d to new_pos: %d", self._current_pos, new_pos)

        self._current_pos = new_pos

        if new_pos == self.content_length:
            self.response = None
            self._read_iter = None
            self._read_buffer.empty()
        else:
            response = self._partial_request(new_pos)
            if response.ok:
                self.response = response
                self._read_iter = self.response.iter_content(self.buffer_size)
                self._read_buffer.empty()
            else:
                self.response = None

        return self._current_pos

    def tell(self):
        return self._current_pos

    def seekable(self, *args, **kwargs):
        return self._seekable

    def truncate(self, size=None):
        """Unsupported."""
        raise io.UnsupportedOperation

    def _partial_request(self, start_pos=None):
        if start_pos is not None:
            self.headers.update({"range": smart_open.utils.make_range_string(start_pos)})

        response = requests.get(self.url, auth=self.auth, stream=True, headers=self.headers)
        return response
