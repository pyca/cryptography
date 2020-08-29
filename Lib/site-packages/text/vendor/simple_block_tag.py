"""
https://github.com/piha/django-simple-block-tag

The MIT License (MIT)

Copyright (c) 2013 Ilya Tikhonov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

from django.template.base import Node

from inspect import getargspec
from functools import partial

from .parse_bits import parse_bits


def simple_block_tag(register, takes_context=None, name=None):
    def dec(func):
        params, varargs, varkw, defaults = getargspec(func)

        class SimpleNode(Node):
            def __init__(self, nodelist, takes_context, args, kwargs):
                self.nodelist = nodelist
                self.takes_context = takes_context
                self.args = args
                self.kwargs = kwargs

            def get_resolved_arguments(self, context):
                resolved_args = [var.resolve(context) for var in self.args]
                resolved_args = [self.nodelist.render(context)] + resolved_args
                if self.takes_context:
                    resolved_args = [context] + resolved_args
                resolved_kwargs = dict((k, v.resolve(context))
                                       for k, v in self.kwargs.items())
                return resolved_args, resolved_kwargs

            def render(self, context):
                resolved_args, resolved_kwargs = self.get_resolved_arguments(context)
                return func(*resolved_args, **resolved_kwargs)

        def tag_compiler(parser, token, params, varargs, varkw, defaults,
                         name, takes_context, function_name):
            bits = token.split_contents()[1:]
            bits = [''] + bits  # add placeholder for content arg
            args, kwargs = parse_bits(parser, bits, params, varargs, varkw,
                                      defaults, takes_context, name)
            args = args[1:]  # remove content placeholder
            nodelist = parser.parse(('end{}'.format(function_name),))
            parser.delete_first_token()
            return SimpleNode(nodelist, takes_context, args, kwargs)

        function_name = (name or
                         getattr(func, '_decorated_function', func).__name__)
        compile_func = partial(tag_compiler,
                               params=params, varargs=varargs, varkw=varkw,
                               defaults=defaults, name=function_name,
                               takes_context=takes_context, function_name=function_name)
        compile_func.__doc__ = func.__doc__

        register.tag(function_name, compile_func)
        return func

    return dec
