"""Base implementation of test utilities."""

import asyncio
import functools
import unittest
import urllib.parse

import httptools

from . import exceptions
from . import message
from . import protocols


class _HTTPResponseParser(httptools.HttpResponseParser):
    """HTTP response parser class used by TestClient."""

    def __init__(self, callback):
        super().__init__(self)
        self._callback = callback
        self._headers = []
        self._data = None

    def feed_data(self, data):
        try:
            super().feed_data(data)
        except:
            raise exceptions.MessageParseError

    def on_header(self, name, value):
        self._headers.append((name.decode(), value.decode()))

    def on_body(self, data):
        if self._data is None:
            self._data = b''
        self._data += data

    def on_message_complete(self):
        try:
            status_code = super().get_status_code()
            version = super().get_http_version()
            self._callback(self._data, status_code, self._headers, version)
        finally:
            self._cleanup()

    def _cleanup(self):
        self._headers = []
        self._data = None


class TestClient:
    """Client side implementation for tests."""

    __slots__ = ('_loop', '_reader', '_transport', '_response_waiter')

    # Default class used for representing HTTP request messages
    request_class = message.HTTPRequestMessage

    # Default class used for representing HTTP response messages
    response_class = message.HTTPResponseMessage

    # Default host and port values used to create the connection
    # if they were not explicitly specified
    host, port = '127.0.0.1', 5000

    def __init__(self, loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop
        self._reader = None
        self._transport = None
        self._response_waiter = None

    def get_response(self, data, status_code, headers, version):
        """Get the parsed response message.

        This is a callback function called by the message parser when
        raw message data bytes have been parsed completely.
        """
        assert self._response_waiter is not None
        resp = self.response_class(data, status_code, headers, version)
        self._response_waiter.set_result(resp)

    async def create_connection(self, host, port, **kwargs):
        """Create a streaming transport connection to host and port."""
        protocol_factory = functools.partial(
            protocols._StreamProtocol,
            loop=self._loop,
            reader=self._reader
        )
        transport, protocol = await self._loop.create_connection(
            protocol_factory,
            host=host,
            port=port,
            **kwargs
        )
        self._transport = transport
        return protocol

    async def request(self, url, method, max_redirections=10, *args, **kwargs):
        """Send a request message."""
        version = kwargs.pop('version', None)
        scheme = kwargs.pop('scheme', None)
        headers = kwargs.pop('headers', None)
        data = kwargs.pop('data', None)

        redirections = {}
        try:
            while True:
                # Generate request object
                req = self.request_class(
                    url, method,
                    version=version,
                    scheme=scheme,
                    headers=headers,
                    data=data
                )
                # Create a parser for each request
                self._reader = _HTTPResponseParser(callback=self.get_response)

                # Create a Future object to wait for parsed response message
                self._response_waiter = self._loop.create_future()

                # Create connection
                host, port = req.host, req.port
                host = host if host else self.host
                port = port if port else self.port
                conn = await self.create_connection(host, port)

                # Send request start-line
                conn.send('{} {} {}\r\n'.format(
                    req.method,
                    req.path,
                    req.version_string).encode('iso-8859-1'))

                # Send request headers
                conn.send(str(req.headers).encode('iso-8859-1'))

                # Send request body
                if req.data is not None:
                    conn.send(req.data)

                # Flush the write buffer and close the write end
                await conn.flush()
                conn.send_eof()

                # Wait for response
                resp = await self._response_waiter

                # Handle redirection
                redirection_status_codes = (301, 302, 303, 307)
                if (resp.status_code not in redirection_status_codes or
                        # Set max_redirections to 0 or negative integer
                        # to disallow redirection
                        max_redirections < 1 or
                        # Reached maximum redirections
                        len(redirections) == max_redirections):
                    break

                new_url = resp.headers.get('Location')
                if not new_url:
                    new_url = resp.headers.get('URI')
                    if not new_url:
                        break

                new_url = urllib.parse.urlparse(new_url)
                assert new_url.scheme in ('http', 'https', ''), \
                    'Only allow redirection to http and https'

                url = urllib.parse.urlunparse(
                    (new_url.scheme or req.scheme,
                     new_url.netloc or req.netloc,
                     new_url.path,
                     new_url.params,
                     new_url.query,
                     new_url.fragment)
                )
                if url in redirections:
                    break  # Break out of redirection loop
                else:
                    redirections[url] = resp
                continue
        except:
            self.close()
            raise
        return resp

    async def delete(self, url, *args, **kwargs):
        """Send a DELETE request."""
        return await self.request(url, 'DELETE', *args, *kwargs)

    async def get(self, url, *args, **kwargs):
        """Send a GET request."""
        return await self.request(url, 'GET', *args, *kwargs)

    async def head(self, url, *args, **kwargs):
        """Send a HEAD request."""
        return await self.request(url, 'HEAD', *args, *kwargs)

    async def options(self, url, *args, **kwargs):
        """Send a OPTIONS request."""
        return await self.request(url, 'OPTIONS', *args, *kwargs)

    async def patch(self, url, *args, **kwargs):
        """Send a PATCH request."""
        return await self.request(url, 'PATCH', *args, *kwargs)

    async def post(self, url, *args, **kwargs):
        """Send a POST request."""
        return await self.request(url, 'POST', *args, *kwargs)

    async def put(self, url, *args, **kwargs):
        """Send a PUT request."""
        return await self.request(url, 'PUT', *args, *kwargs)

    def close(self):
        self._transport.close()
        self._transport = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self.close()


class TestCase(unittest.TestCase):
    """
    TODO
    """