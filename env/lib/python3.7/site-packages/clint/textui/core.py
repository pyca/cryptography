# -*- coding: utf-8 -*-

"""
clint.textui.core
~~~~~~~~~~~~~~~~~

Core TextUI functionality for Puts/Indent/Writer.

"""


from __future__ import absolute_import

import sys

from contextlib import contextmanager

from .formatters import max_width, min_width
from .cols import columns
from ..utils import tsplit


__all__ = ('puts', 'puts_err', 'indent', 'dedent', 'columns', 'max_width',
    'min_width', 'STDOUT', 'STDERR')


STDOUT = sys.stdout.write
STDERR = sys.stderr.write

NEWLINES = ('\n', '\r', '\r\n')

INDENT_STRINGS = []

# Private

def _indent(indent=0, quote='', indent_char=' '):
    """Indent util function, compute new indent_string"""
    if indent > 0:
        indent_string = ''.join((
            str(quote),
            (indent_char * (indent - len(quote)))
        ))
    else:
        indent_string = ''.join((
            ('\x08' * (-1 * (indent - len(quote)))),
            str(quote))
        )

    if len(indent_string):
        INDENT_STRINGS.append(indent_string)

# Public

def puts(s='', newline=True, stream=STDOUT):
    """Prints given string to stdout."""
    if newline:
        s = tsplit(s, NEWLINES)
        s = map(str, s)
        indent = ''.join(INDENT_STRINGS)

        s = (str('\n' + indent)).join(s)

    _str = ''.join((
        ''.join(INDENT_STRINGS),
        str(s),
        '\n' if newline else ''
    ))
    stream(_str)

def puts_err(s='', newline=True, stream=STDERR):
    """Prints given string to stderr."""
    puts(s, newline, stream)

def dedent():
    """Dedent next strings, use only if you use indent otherwise than as a
    context."""
    INDENT_STRINGS.pop()

@contextmanager
def _indent_context():
    """Indentation context manager."""
    try:
        yield
    finally:
        dedent()

def indent(indent=4, quote=''):
    """Indentation manager, return an indentation context manager."""
    _indent(indent, quote)
    return _indent_context()
