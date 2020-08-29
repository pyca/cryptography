"""Protocol classes."""

__all__ = ['HTTPProtocol']

import asyncio
import html
import http.server
import inspect
import sys
import time
import wsgiref.handlers

from http import HTTPStatus

from . import exceptions
from . import message
from . import parser

__version__ = "0.2.2"


class _StreamProtocol(asyncio.streams.FlowControlMixin, asyncio.Protocol):
    """Implements the interface for stream protocol."""

    __slots__ = ('_reader', '_writer', '_over_ssl')

    def __init__(self, reader=None, loop=None):
        super().__init__(loop=loop)
        self._reader = reader
        self._writer = None
        self._over_ssl = False

    def connection_made(self, transport):
        """Called when a connection is made."""
        self._over_ssl = transport.get_extra_info('sslcontext') is not None
        self._writer = asyncio.StreamWriter(transport, self, None, self._loop)

    def connection_lost(self, exc):
        """Called when the connection is lost or closed."""
        super().connection_lost(exc)
        self._reader = None
        self._writer = None

    def data_received(self, data):
        """Called when some data is received."""
        self._reader.feed_data(data)

    def eof_received(self):
        if self._over_ssl:
            # Prevent a warning in SSLProtocol.eof_received:
            # "returning true from eof_received()
            # has no effect when using ssl"
            return False
        return True


class HTTPProtocol(_StreamProtocol):
    """HTTP Protocol class."""

    __slots__ = ('_router', '_view_handlers', '_exception_handlers',
                 '_request_timeout', '_keepalive_timeout', '_debug',
                 '_request', '_response', '_last_request_time',
                 '_last_response_time', '_request_timeout_handle',
                 '_keepalive_timeout_handle', '_close_connection', '_closed')

    # The server software version
    server_version = "Unit/" + __version__

    # The Python system version
    sys_version = "Python/" + sys.version.split()[0]

    # Supported protocol versions
    supported_protocol_versions = ['1.0', '1.1']

    # Default request timeout value
    request_timeout = 60.0

    # Default keep-alive timeout value
    keepalive_timeout = 5.0

    # Default class used for representing HTTP request messages
    request_class = message.HTTPRequestMessage

    # Default class used for representing HTTP response messages
    response_class = message.HTTPResponseMessage

    # Default error message template
    error_message_format = http.server.DEFAULT_ERROR_MESSAGE

    # Set to True to inspect response messages before sending
    do_response_inspection = True

    def __init__(self, loop=None, router=None, view_handlers=None,
                 exception_handlers=None, request_timeout=None,
                 keepalive_timeout=None, debug=None):

        loop = asyncio.get_event_loop() if loop is None else loop
        reader = parser.HTTPRequestParser(self.get_request, loop)
        super().__init__(reader, loop)

        self._router = router
        self._view_handlers = view_handlers
        self._exception_handlers = exception_handlers

        if request_timeout is None:
            self._request_timeout = self.request_timeout
        else:
            self._request_timeout = float(request_timeout)

        if keepalive_timeout is None:
            self._keepalive_timeout = self.keepalive_timeout
        else:
            self._keepalive_timeout = float(keepalive_timeout)

        self._debug = debug

        self._request = None
        self._response = None
        self._last_request_time = None
        self._last_response_time = None
        self._request_timeout_handle = None
        self._keepalive_timeout_handle = None
        self._close_connection = True
        self._closed = False

    def data_received(self, data):
        """Called when some data is received."""
        try:
            self._loop.run_in_executor(None, self._reader.feed_data, data)
        except exceptions.MessageParseError:
            self._loop.create_task(self._send_error(exceptions.BadRequest))

    async def get_request(self, environ):
        """Get the parsed request message and schedule the handling process.

        This is a callback function called by the message parser when
        raw message data bytes have been parsed completely.

        :param environ: A dict containing all information about the request.
        """
        scheme = 'https' if self._over_ssl else 'http'
        try:
            request = self.request_class(
                url=environ['url'],
                method=environ['method'],
                headers=environ.get('headers'),
                data=environ.get('data'),
                version=environ.get('version'),
                scheme=scheme)
        except:
            if self._debug:
                raise
            return await self._send_error(exceptions.BadRequest)

        # Set request timeout handle
        if self._request_timeout_handle is None:
            self._request_timeout_handle = self._loop.call_later(
                self._request_timeout, self.handle_request_timeout)

        self._request = request
        self._last_request_time = self._loop.time()
        await self.process_request()

    async def process_request(self):
        """Start processing a request."""
        request = self._request
        assert request is not None

        # Check protocol version
        if request.version not in self.supported_protocol_versions:
            return await self._send_error(exceptions.HTTPVersionNotSupported)

        # Check "Connection" header field
        conn = request.headers.get('Connection', '')
        conn = conn.strip().lower()
        if conn == 'close':
            self._close_connection = True
        elif conn == 'keep-alive' and request.version >= '1.0':
            self._close_connection = False
        elif request.version >= '1.1':
            self._close_connection = False
        else:
            self._close_connection = True

        try:
            # Check "Expect: 100-continue" header field
            expect = request.headers.get('Expect')
            if (expect and
                    expect.lower() == '100-continue' and
                    request.version >= '1.1'):
                return await self.handle_expect_100()

            # Match request
            match_result = await self.match_request()
            if self._closed:
                # An error response has been sent, just exit
                return
            if self._response is None:
                assert match_result is not None
                self._response = await self.make_response(match_result)
            await self.send_response()
        finally:
            if self._close_connection:
                self.close()
            else:
                # Set keepalive timeout handle
                if self._keepalive_timeout_handle is None:
                    self._keepalive_timeout_handle = self._loop.call_later(
                        self.keepalive_timeout, self.handle_keepalive_timeout)

                self._last_response_time = self._loop.time()
                self.cleanup()

    async def match_request(self):
        """Match a request and call the handler function."""
        try:
            handler_name, handler_args = await self._router.match(
                self._request.method,
                self._request.url
            )
            handler = self._view_handlers.get(handler_name)
            assert handler is not None

            result = handler(self._request, **handler_args)
            if inspect.isawaitable(result):
                return await result
            else:
                return result
        except exceptions.HTTPException as exc:
            return await self.handle_exception(exc)
        except Exception as exc:
            self._close_connection = True
            if self._debug:
                raise exc
            return await self.handle_exception(exceptions.InternalServerError)

    async def make_response(self, value):
        """Generate an object to represent the response message.

        This inspects the value argument and then converts it to a response
        message object, which should be an instance or subclass instance of
        `message.HTTPResponseMessage` class.

        :param value: The value to be converted to a response message object.
        """
        if isinstance(value, message.HTTPResponseMessage):
            return value

        headers = None
        status_code = None

        if isinstance(value, (str, bytes, bytearray)):
            data = value
        elif isinstance(value, (tuple, list)):
            lv = len(value)
            if lv == 3:
                data, status_code, headers = value
            elif lv == 2:
                data, status_code = value
            elif lv == 1:
                raise TypeError(
                    'The tuple/list returned from handler function has '
                    'only 1 element, expecting 2 or 3'
                )
            else:
                raise TypeError(
                    'Unexpected number of elements returned from handler '
                    'function, expecting 2 or 3, got {}'.format(lv)
                )
        else:
            raise TypeError(
                'Unexpected value returned from handler function: {!r}'
                ''.format(value)
            )
        return self.response_class(data, status_code, headers)

    def inspect_response(self):
        """Inspect the response message before sending."""
        data = self._response.data
        headers = self._response.headers
        status_code = self._response.status_code
        version = self._response.version

        # Message body is omitted for cases described in:
        #  - RFC7230 3.3: 1xx, 204 (No Content), 304 (Not Modified)
        #  - RFC7231 6.3.6: 205 (Reset Content)
        if status_code < 200 or status_code in (204, 205, 304):
            data = None
        else:
            if data is None:
                data = b''

            # RFC7231 section 3.1.1 says a message containing a payload body
            # SHOULD present a `Content-Type` header field to indicate the
            # media type of the enclosed data.
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/octet-stream'

        # Content-Length header field is omitted for cases described in:
        #  - RFC7230 3.3.2: 1xx, 204 (No Content)
        has_length = 'Content-Length' in headers
        if status_code < 200 or status_code == 204:
            if has_length:
                del headers['Content-Length']
        else:
            if data is not None:
                te = [i.lower() for i in headers.get_all('Transfer-Encoding')]
                if 'chunked' in te:
                    if has_length:
                        del headers['Content-Length']
                else:
                    if not has_length:
                        headers['Content-Length'] = str(len(data))

        if 'Connection' not in headers:
            if self._close_connection:
                headers.add_header('Connection', 'close')
            else:
                if version == '1.0':
                    headers.add_header('Connection', 'keep-alive')

        if 'Date' not in headers:
            headers['Date'] = wsgiref.handlers.format_date_time(time.time())

        if 'Server' not in headers:
            headers['Server'] = self.server_version + ' ' + self.sys_version

        # Set the body for a HEAD request at the end so that the header
        # values (e.g. 'Content-Length') are the same as a GET request.
        if self._request is not None:
            if self._request.method == 'HEAD':
                data = None

        self._response._data = data
        self._response._headers = headers

    async def send_response(self):
        """Start sending a response.

        This writes the start-line, headers and body (if the body should
        be sent) of the response message to the transport.
        """
        response = self._response
        assert response is not None

        writer = self._writer

        if self.do_response_inspection:
            self.inspect_response()

        # Send start-line
        start_line = '{} {} {}\r\n'.format(
            response.version_string,
            response.status_code,
            response.status_phrase
        )
        writer.write(start_line.encode('iso-8859-1'))

        # Send header fields
        headers = str(response.headers)
        writer.write(headers.encode('iso-8859-1'))

        # Send payload data
        if response.data is not None:
            writer.write(response.data)

        await writer.drain()

    async def handle_exception(self, exc):
        """Handle an HTTP exception.

        :param exc: The exception object to handle, which should be a subclass
                    of `unit.exceptions.HTTPException` class.
        """
        assert hasattr(exc, 'code')
        code = exc.code
        assert code in message.HTTP_STATUS_CODES

        # Try to find an exception handler
        handler = self._exception_handlers.get(code)
        if handler is not None:
            try:
                result = handler(request=self._request)
                if inspect.isawaitable(result):
                    result = await result
                self._response = await self.make_response(result)
                return
            except:
                if self._debug:
                    raise

        # Handle redirect exception
        if isinstance(exc, exceptions.RedirectException):
            assert exc.new_url is not None
            headers = [('Location', exc.new_url)]
            self._response = await self.make_response((None, code, headers))
            return

        # Generate an error message using default error message template
        if exc.phrase is not None:
            phrase = exc.phrase
        else:
            phrase = HTTPStatus(code).phrase

        if exc.description is not None:
            description = exc.description
        else:
            description = HTTPStatus(code).description

        error_message = self.error_message_format % {
            'code': code,
            # HTML encode to prevent Cross Site Scripting attacks
            'message': html.escape(phrase, quote=False),
            'explain': html.escape(description, quote=False)
        }
        self._response = await self.make_response((error_message, code))

    def handle_request_timeout(self):
        """Handle request timeout."""
        if self._closed:
            return

        now = self._loop.time()
        endtime = self._last_request_time + self._request_timeout
        remaining = endtime - now

        if remaining <= 0:
            # Timed out, send a RequestTimeout (408) error response
            self._close_connection = True
            self._loop.create_task(self._send_error(exceptions.RequestTimeout))
        else:
            # Reschedule the handle
            if self._request_timeout_handle is not None:
                self._request_timeout_handle.cancel()
            self._request_timeout_handle = self._loop.call_later(
                remaining, self.handle_request_timeout)

    def handle_keepalive_timeout(self):
        """Handle keep-alive/persistent connection timeout."""
        if self._closed:
            return

        now = self._loop.time()
        endtime = self._last_response_time + self._keepalive_timeout
        remaining = endtime - now

        if remaining <= 0:
            # Timed out, close the connection
            self._close_connection = True
            self.close()
        else:
            # Reschedule the handle
            if self._keepalive_timeout_handle is not None:
                self._keepalive_timeout_handle.cancel()
            self._keepalive_timeout_handle = self._loop.call_later(
                remaining, self.handle_keepalive_timeout)

    async def handle_expect_100(self):
        """Handle a HTTP/1.1 request with an "Expect: 100-continue" header.

        By default, if a HTTP/1.1 request has an "Expect: 100-continue" header,
        a 100 Continue response is returned.
        """
        await self.handle_exception(exceptions.Continue)
        await self.send_response()

    def close(self):
        """Close the connection gracefully."""
        if self._closed:
            return

        if self._request_timeout_handle is not None:
            self._request_timeout_handle.cancel()
            self._request_timeout_handle = None

        if self._keepalive_timeout_handle is not None:
            self._keepalive_timeout_handle.cancel()
            self._keepalive_timeout_handle = None

        if self._writer.can_write_eof():
            self._writer.write_eof()

        self._writer.close()
        self._closed = True

    def cleanup(self):
        """Clean up data associated with the current request."""
        self._request = None
        self._response = None

    async def _send_error(self, exc, close_connection=True):
        try:
            await self.handle_exception(exc)
            await self.send_response()
        finally:
            if close_connection:
                self.close()
