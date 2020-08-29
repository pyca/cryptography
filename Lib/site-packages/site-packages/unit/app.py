"""Web application class."""

__all__ = ['Application']

import asyncio
import functools
import os

from . import exceptions
from . import message
from . import protocols
from . import router
from . import utils


class Application:
    """The Web application class.
    
    An Web application is created by creating an instance of this class and
    pass the name of the package as the first parameter. For example:
    
        import unit
        app = unit.Application(__name__)
        
    Then the application object `app` can be used to register routes, exception
    handlers, view handlers, etc.
    
    Here is a simple `Hello, World!` example with an exception handler which
    handles `NOT FOUND` (404) exception:
    
        import unit
        
        app = unit.Application(__name__)
        
        @app.route('/')
        def hello_world(request):
            return 'Hello, World!'
            
        @app.exception_handler(404)
        def not_found(request):
            return 'NOT FOUND', 404
        
        if __name__ == '__main__':
            app.run()
    """

    def __init__(self, package_name, static_path='/static'):
        self.package_name = package_name
        self.package_path = utils.get_package_path(package_name)
        self.router = router.Router()
        self.view_handlers = {}
        self.exception_handlers = {}

        self._loop = asyncio.get_event_loop()

        # If static_path argument is specified, add a handler
        # for sending static files.
        if static_path is not None:
            absolute_static_path = os.path.join(
                self.package_path, static_path.strip('/')
            )
            if not os.path.isdir(absolute_static_path):
                raise RuntimeError(
                    'static path {} does not exist'.format(static_path)
                )
            self.static_path = absolute_static_path
            self.add_route('send_static_file', static_path + '/<filename>')
            self.view_handlers['send_static_file'] = self.send_static_file

    def add_route(self, name, path, methods=None):
        """Add a route.

        :param name: Name of the route.
        :param path: Path of the route as string.
        :param methods: A list of request methods that a route is limited to.
                        If not specified, `['HEAD', 'GET']` is set as default.
        """
        if methods is None:
            methods = ['HEAD', 'GET']
        elif not isinstance(methods, (list, tuple)):
            raise TypeError('methods argument must be a list or tuple, '
                            'not {}'.format(type(methods).__name__))
        else:
            methods = [m.upper() for m in methods]
            if 'GET' in methods and 'HEAD' not in methods:
                methods.append('HEAD')

        self.router.add_route(name, path, methods)

    def route(self, path, methods=None):
        """A decorator for setting up a route.

        This registers the decorated function as a view handler and add it
        to `self.view_handlers`. By default, the name of the function is used
        as the name of the route.

        :param path: Path of the route as string.
        :param methods: The request methods a route is limited to, if not
                        specified, 'GET' is set as default'.
        """
        def wrapper(f):
            name = f.__name__
            self.add_route(name, path, methods)
            self.view_handlers[name] = f
            return f
        return wrapper

    def exception_handler(self, status_code):
        """A decorator registers a function as an exception handler.

        :param status_code: Status code of the exception.
        """
        if not isinstance(status_code, int):
            raise TypeError('status_code argument must be an integer, '
                            'not {}'.format(type(status_code).__name__))

        assert status_code in message.HTTP_STATUS_CODES, \
            'Invalid HTTP status code {!r}'.format(status_code)

        def wrapper(f):
            self.exception_handlers[status_code] = f
            return f

        return wrapper

    def get_protocol_factory(self, debug=None):
        """Return a protocol factory object.

        The factory returned is used by the server to create protocol object
        when a request message is received.

        :param debug: Enable debugging if debug is true.
        """
        return functools.partial(protocols.HTTPProtocol,
                                 debug=debug,
                                 loop=self._loop,
                                 router=self.router,
                                 view_handlers=self.view_handlers,
                                 exception_handlers=self.exception_handlers)

    def run(self, host=None, port=None, debug=None):
        """Runs an application on a local server.

        :param host: The hostname the server listens on.
        :param port: The port number the server uses.
        :param debug: Enable debugging if debug is true.
        """

        if host is None:
            host = '127.0.0.1'

        if port is None:
            port = 5000

        loop = self._loop

        # Get a protocol factory object
        protocol_factory = self.get_protocol_factory(debug=debug)

        # Create a local server listening on `host` and `port`
        server = loop.create_server(protocol_factory, host=host, port=port)

        # Schedule and run the server
        loop.run_until_complete(server)

        print('> Running on http://{}:{}/\n'
              '  (Press Ctrl-C to stop.)\n'.format(host, port))

        try:
            loop.run_forever()
        except KeyboardInterrupt:  # Ctrl-C pressed
            pass
        finally:
            loop.close()

    async def send_static_file(self, request, filename):
        """Send a static file from the static file directory.

        :param request: Object that represents the request message.
        :param filename: The name of the staitc file to send.
        """
        file = os.path.join(self.static_path, filename)
        if not os.path.isfile(file):
            raise exceptions.NotFound
        data, content_type = await utils.readfile(
            file,
            loop=self._loop,
            guess_type=True
        )
        headers = [
            ('Content-Type', content_type),
            ('Content-Length', str(len(data)))
        ]
        return message.HTTPResponseMessage(data, headers=headers)
