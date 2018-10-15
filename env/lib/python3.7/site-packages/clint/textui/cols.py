# -*- coding: utf-8 -*-

"""
clint.textui.columns
~~~~~~~~~~~~~~~~~~~~

Core TextUI functionality for column formatting.

"""

from __future__ import absolute_import

from .formatters import max_width, min_width
from ..utils import tsplit

import sys


NEWLINES = ('\n', '\r', '\r\n')



def _find_unix_console_width():
    import termios, fcntl, struct, sys

    # fcntl.ioctl will fail if stdout is not a tty
    if not sys.stdout.isatty():
        return None

    s = struct.pack("HHHH", 0, 0, 0, 0)
    fd_stdout = sys.stdout.fileno()
    size = fcntl.ioctl(fd_stdout, termios.TIOCGWINSZ, s)
    height, width = struct.unpack("HHHH", size)[:2]
    return width


def _find_windows_console_width():
    # http://code.activestate.com/recipes/440694/
    from ctypes import windll, create_string_buffer
    STDIN, STDOUT, STDERR = -10, -11, -12

    h = windll.kernel32.GetStdHandle(STDERR)
    csbi = create_string_buffer(22)
    res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)

    if res:
        import struct
        (bufx, bufy, curx, cury, wattr,
         left, top, right, bottom,
         maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)
        sizex = right - left + 1
        sizey = bottom - top + 1
        return sizex


def console_width(kwargs):
    """"Determine console_width."""

    if sys.platform.startswith('win'):
        console_width = _find_windows_console_width()
    else:
        console_width = _find_unix_console_width()

    _width = kwargs.get('width', None)
    if _width:
        console_width = _width
    else:
        if not console_width:
            console_width = 80

    return console_width



def columns(*cols, **kwargs):

    columns = list(cols)

    cwidth = console_width(kwargs)

    _big_col = None
    _total_cols = 0


    for i, (string, width) in enumerate(cols):

        if width is not None:
            _total_cols += (width + 1)
            cols[i][0] = max_width(string, width).split('\n')
        else:
            _big_col = i

    if _big_col:
        cols[_big_col][1] = (cwidth - _total_cols) - len(cols)
        cols[_big_col][0] = max_width(cols[_big_col][0], cols[_big_col][1]).split('\n')

    height = len(max([c[0] for c in cols], key=len))
    
    for i, (strings, width) in enumerate(cols):

        for _ in range(height - len(strings)):
            cols[i][0].append('')

        for j, string in enumerate(strings):
            cols[i][0][j] = min_width(string, width)

    stack =  [c[0] for c in cols]
    _out = []

    for i in range(height):
        _row = ''

        for col in stack:
            _row += col[i]
            _row += ' '

        _out.append(_row)
#            try:
#                pass
#            except:
#                pass




    return '\n'.join(_out)


#        string = max_width(string, width)
#        string = min_width(string, width)
#        pass
#        columns.append()



###########################

a = 'this is text that goes into a small column\n cool?'
b = 'this is other text\nothertext\nothertext'

#columns((a, 10), (b, 20), (b, None))
