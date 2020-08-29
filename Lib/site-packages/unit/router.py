"""A handler that handles URL traversal."""

__all__ = ['Router']

import collections
import re
import urllib.parse

from . import exceptions


_Route = collections.namedtuple('Route', 'name path methods path_re path_str')


_path_re = re.compile(r"""
    (?P<static>[^<]*)                           # static part
    <
    (?P<param>[a-zA-Z][a-zA-Z0-9_]*)            # path parameter
    (?:
        \s*                                     # skip leading whitespace
        :                                       # a colon as the delimiter
        \s*                                     # skip trailing whitespace                       
        (?P<param_type>[a-zA-Z][a-zA-Z0-9_]*)   # type of the path parameter
    )?                                         
    >
""", re.VERBOSE)


_path_param_type_patterns = {
    'str': r'[^/]+',        # unicode (default)
    'int': r'\d+'           # integer
}


_path_param_type_formats = {
    'str': 's',
    'int': 'd'
}


class Router:
    """URL traversal handler."""

    __slots__ = ('routes',)

    def __init__(self):
        self.routes = {}

    @staticmethod
    def _compile_path(path):
        """Match a route path and compile its regular expression pattern.

        :param path: The path string to compile.
        """
        pos = 0
        endpos = len(path)
        pattern_cache = []
        string_cache = []
        match = _path_re.match
        while pos < endpos:
            m = match(path, pos)
            if m is None:  # no match
                break

            d = m.groupdict()

            # Does this match have a static part?
            static_part = d['static']
            if static_part:
                pattern_cache.append(re.escape(static_part))
                string_cache.append(static_part)

            # Each match has exactly one dynamic part in the form
            # <param:param_type>, e.g., <user_id:int>. If `param_type`
            # is not specified, e.g., <username>, the unicode pattern
            # 'str' will be used by default.
            param = d['param']
            param_type = d['param_type'] or 'str'
            param_type_pattern = _path_param_type_patterns.get(param_type)
            if param_type_pattern is None:
                raise ValueError(
                    'Unknown path parameter type {!r}'.format(param_type))

            # Save the re pattern for this dynamic parameter.
            # e.g., (?P<user_name>r'[^/]+'), (?P<user_id>r'\d+')
            pattern_cache.append(
                '(?P<{}>{})'.format(param, param_type_pattern))

            # Save the format string for this dynamic parameter.
            # e.g., {user_name:s}, {user_id:d}
            typ = _path_param_type_formats[param_type]
            string_cache.append('{' + '{}:{}'.format(param, typ) + '}')

            pos = m.end()

        if pos < endpos:
            remaining_part = path[pos:]
            # The remaining part has no match, i.e., no dynamic part,
            # so neither '<' nor '>' should exist in it.
            if '<' in remaining_part or '>' in remaining_part:
                raise ValueError('Invalid route path {}'.format(path))

            pattern_cache.append(re.escape(remaining_part))
            string_cache.append(remaining_part)

        path_re = re.compile(r'^%s$' % ''.join(pattern_cache))
        path_str = ''.join(string_cache)
        return path_re, path_str

    def add_route(self, name, path, methods):
        """Generate a route and add it to `self.routes`.

        :param name: Name of the route.
        :param path: Path of the route.
        :param methods: Methods the route is limited to.
        """
        if name in self.routes:
            raise ValueError(
                'A route with name {} already exists'.format(name))
        path_re, path_str = self._compile_path(path)
        self.routes[name] = _Route(name, path, methods, path_re, path_str)

    async def match(self, method, url):
        """Match a request message.

        :param method: Method of the request message.
        :param url: URL of the request message.
        """
        for route in self.routes.values():
            m = route.path_re.match(url)
            if m is None:  # doesn't match
                continue

            if method not in route.methods:
                raise exceptions.MethodNotAllowed  # 405

            return route.name, m.groupdict()
        else:
            raise exceptions.NotFound  # 404

    def build(self, _route_name, **kwargs):
        """Build a path from route name.

        :param _route_name: The name of a route.
        """
        assert '_route_name' not in kwargs
        route = self.routes.get(_route_name)
        if route is None:
            raise ValueError('No route named {}'.format(_route_name))

        try:
            path = route.path_str.format(**kwargs)
        except KeyError:
            raise KeyError('Invalid argument(s) for route '
                           '{}: {}'.format(_route_name, kwargs))
        except ValueError:
            raise TypeError('Invalid argument type for route '
                            '{}: {}'.format(_route_name, kwargs))

        return urllib.parse.quote(path)

    def redirect(self, target, **kwargs):
        """Redirect to a new target from a route-name or a URL.

        :param target: The name of a Route, or a URL.
        """
        if '/' in target:  # url
            new_url = target
        else:  # route name
            new_url = self.build(target, **kwargs)
        exc = exceptions.Found
        exc.new_url = new_url
        raise exc
