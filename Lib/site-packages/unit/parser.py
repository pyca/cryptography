"""A parser of HTTP request messages."""

__all__ = ['HTTPRequestParser']

import asyncio
import httptools

from . import exceptions


class HTTPRequestParser(httptools.HttpRequestParser):
    """Parser of HTTP request messages."""

    __slots__ = ('_callback', '_loop', 'content_length', 'environ')

    max_content_length = 1024 * 1024

    def __init__(self, callback=None, loop=None):
        super().__init__(self)
        self._callback = callback
        if loop is None:
            self._loop = asyncio.get_event_loop()
        else:
            self._loop = loop
        self.content_length = 0
        self.environ = {'headers': [], 'data': None}

    def feed_data(self, data: bytes):
        """Feed data to the parser.

        :param data: The incoming data in bytes.
        """
        try:
            super().feed_data(data)
        except:
            raise exceptions.MessageParseError

    def on_url(self, url: bytes):
        """Called when the URL of a request message has been parsed
        successfully.

        :param url: URL of the request message.
        """
        self.environ['url'] = url.decode()

    def on_header(self, name: bytes, value: bytes):
        """Add a header to the headers buffer.

        :param name: The name of a header field.
        :param value: The value of a header field.
        """
        name, value = name.decode(), value.decode()
        self.environ['headers'].append((name, value))

    def on_body(self, data: bytes):
        """Append data to the data buffer.

        :param data: Payload data of the request message.
        """
        self.content_length += len(data)
        if self.content_length > self.max_content_length:
            raise exceptions.RequestEntityTooLarge

        if self.environ['data'] is None:
            self.environ['data'] = b''
        self.environ['data'] += data

    def on_message_complete(self):
        """Called when parsing is completed."""
        try:
            self.environ['method'] = super().get_method()
            self.environ['version'] = super().get_http_version()
            if self._callback is not None:
                self._loop.create_task(self._callback(self.environ))
        finally:
            self.cleanup()

    def cleanup(self):
        """Clean up data associated with the current request message."""
        self.content_length = 0
        self.environ = {'headers': [], 'data': None}
