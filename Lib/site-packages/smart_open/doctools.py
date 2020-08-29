# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 Radim Rehurek <me@radimrehurek.com>
#
# This code is distributed under the terms and conditions
# from the MIT License (MIT).
#

"""Common functions for working with docstrings.

For internal use only.
"""

import contextlib
import inspect
import io
import os.path
import re

from . import compression
from . import transport

PLACEHOLDER = '    smart_open/doctools.py magic goes here'


def extract_kwargs(docstring):
    """Extract keyword argument documentation from a function's docstring.

    Parameters
    ----------
    docstring: str
        The docstring to extract keyword arguments from.

    Returns
    -------
    list of (str, str, list str)

    str
        The name of the keyword argument.
    str
        Its type.
    str
        Its documentation as a list of lines.

    Notes
    -----
    The implementation is rather fragile.  It expects the following:

    1. The parameters are under an underlined Parameters section
    2. Keyword parameters have the literal ", optional" after the type
    3. Names and types are not indented
    4. Descriptions are indented with 4 spaces
    5. The Parameters section ends with an empty line.

    Examples
    --------

    >>> docstring = '''The foo function.
    ... Parameters
    ... ----------
    ... bar: str, optional
    ...     This parameter is the bar.
    ... baz: int, optional
    ...     This parameter is the baz.
    ...
    ... '''
    >>> kwargs = extract_kwargs(docstring)
    >>> kwargs[0]
    ('bar', 'str, optional', ['This parameter is the bar.'])

    """
    if not docstring:
        return []

    lines = inspect.cleandoc(docstring).split('\n')
    retval = []

    #
    # 1. Find the underlined 'Parameters' section
    # 2. Once there, continue parsing parameters until we hit an empty line
    #
    while lines and lines[0] != 'Parameters':
        lines.pop(0)

    if not lines:
        return []

    lines.pop(0)
    lines.pop(0)

    while lines and lines[0]:
        name, type_ = lines.pop(0).split(':', 1)
        description = []
        while lines and lines[0].startswith('    '):
            description.append(lines.pop(0).strip())
        if 'optional' in type_:
            retval.append((name.strip(), type_.strip(), description))

    return retval


def to_docstring(kwargs, lpad=''):
    """Reconstruct a docstring from keyword argument info.

    Basically reverses :func:`extract_kwargs`.

    Parameters
    ----------
    kwargs: list
        Output from the extract_kwargs function
    lpad: str, optional
        Padding string (from the left).

    Returns
    -------
    str
        The docstring snippet documenting the keyword arguments.

    Examples
    --------

    >>> kwargs = [
    ...     ('bar', 'str, optional', ['This parameter is the bar.']),
    ...     ('baz', 'int, optional', ['This parameter is the baz.']),
    ... ]
    >>> print(to_docstring(kwargs), end='')
    bar: str, optional
        This parameter is the bar.
    baz: int, optional
        This parameter is the baz.

    """
    buf = io.StringIO()
    for name, type_, description in kwargs:
        buf.write('%s%s: %s\n' % (lpad, name, type_))
        for line in description:
            buf.write('%s    %s\n' % (lpad, line))
    return buf.getvalue()


def extract_examples_from_readme_rst(indent='    '):
    """Extract examples from this project's README.rst file.

    Parameters
    ----------
    indent: str
        Prepend each line with this string.  Should contain some number of spaces.

    Returns
    -------
    str
        The examples.

    Notes
    -----
    Quite fragile, depends on named labels inside the README.rst file.
    """
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    readme_path = os.path.join(curr_dir, '..', 'README.rst')
    try:
        with open(readme_path) as fin:
            lines = list(fin)
        start = lines.index('.. _doctools_before_examples:\n')
        end = lines.index(".. _doctools_after_examples:\n")
        lines = lines[start+4:end-2]
        return ''.join([indent + re.sub('^  ', '', line) for line in lines])
    except Exception:
        return indent + 'See README.rst'


def tweak_open_docstring(f):
    buf = io.StringIO()
    seen = set()

    root_path = os.path.dirname(os.path.dirname(__file__))

    with contextlib.redirect_stdout(buf):
        print('    smart_open supports the following transport mechanisms:')
        print()
        for scheme, submodule in sorted(transport._REGISTRY.items()):
            if scheme == transport.NO_SCHEME or submodule in seen:
                continue
            seen.add(submodule)

            relpath = os.path.relpath(submodule.__file__, start=root_path)
            heading = '%s (%s)' % (scheme, relpath)
            print('    %s' % heading)
            print('    %s' % ('~' * len(heading)))
            print('    %s' % submodule.__doc__.split('\n')[0])
            print()

            kwargs = extract_kwargs(submodule.open.__doc__)
            if kwargs:
                print(to_docstring(kwargs, lpad=u'    '))

        print('    Examples')
        print('    --------')
        print()
        print(extract_examples_from_readme_rst())

        print('    This function also supports transparent compression and decompression ')
        print('    using the following codecs:')
        print()
        for extension in compression.get_supported_extensions():
            print('    * %s' % extension)
        print()
        print('    The function depends on the file extension to determine the appropriate codec.')

    #
    # The docstring can be None if -OO was passed to the interpreter.
    #
    if f.__doc__:
        f.__doc__ = f.__doc__.replace(PLACEHOLDER, buf.getvalue())


def tweak_parse_uri_docstring(f):
    buf = io.StringIO()
    seen = set()
    schemes = []
    examples = []

    for scheme, submodule in sorted(transport._REGISTRY.items()):
        if scheme == transport.NO_SCHEME or submodule in seen:
            continue
        schemes.append(scheme)
        seen.add(submodule)

        try:
            examples.extend(submodule.URI_EXAMPLES)
        except AttributeError:
            pass

    with contextlib.redirect_stdout(buf):
        print('    Supported URI schemes are:')
        print()
        for scheme in schemes:
            print('    * %s' % scheme)
        print()
        print('    Valid URI examples::')
        print()
        for example in examples:
            print('    * %s' % example)

    if f.__doc__:
        f.__doc__ = f.__doc__.replace(PLACEHOLDER, buf.getvalue())
