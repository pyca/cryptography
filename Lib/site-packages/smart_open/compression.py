# -*- coding: utf-8 -*-
#
# Copyright (C) 2020 Radim Rehurek <me@radimrehurek.com>
#
# This code is distributed under the terms and conditions
# from the MIT License (MIT).
#
"""Implements the compression layer of the ``smart_open`` library."""
import logging
import os.path

logger = logging.getLogger(__name__)


_COMPRESSOR_REGISTRY = {}


def get_supported_extensions():
    """Return the list of file extensions for which we have registered compressors."""
    return sorted(_COMPRESSOR_REGISTRY.keys())


def register_compressor(ext, callback):
    """Register a callback for transparently decompressing files with a specific extension.

    Parameters
    ----------
    ext: str
        The extension.  Must include the leading period, e.g. ``.gz``.
    callback: callable
        The callback.  It must accept two position arguments, file_obj and mode.
        This function will be called when ``smart_open`` is opening a file with
        the specified extension.

    Examples
    --------

    Instruct smart_open to use the `lzma` module whenever opening a file
    with a .xz extension (see README.rst for the complete example showing I/O):

    >>> def _handle_xz(file_obj, mode):
    ...     import lzma
    ...     return lzma.LZMAFile(filename=file_obj, mode=mode, format=lzma.FORMAT_XZ)
    >>>
    >>> register_compressor('.xz', _handle_xz)

    """
    if not (ext and ext[0] == '.'):
        raise ValueError('ext must be a string starting with ., not %r' % ext)
    if ext in _COMPRESSOR_REGISTRY:
        logger.warning('overriding existing compression handler for %r', ext)
    _COMPRESSOR_REGISTRY[ext] = callback


def _handle_bz2(file_obj, mode):
    from bz2 import BZ2File
    return BZ2File(file_obj, mode)


def _handle_gzip(file_obj, mode):
    import gzip
    return gzip.GzipFile(fileobj=file_obj, mode=mode)


def compression_wrapper(file_obj, mode, filename=None):
    """
    This function will wrap the file_obj with an appropriate
    [de]compression mechanism based on the extension of the filename.

    file_obj must either be a filehandle object, or a class which behaves
    like one. It must have a .name attribute unless ``filename`` is given.

    If the filename extension isn't recognized, will simply return the original
    file_obj.

    """
    try:
        if filename is None:
            filename = file_obj.name
        _, ext = os.path.splitext(filename)
    except (AttributeError, TypeError):
        logger.warning(
            'unable to transparently decompress %r because it '
            'seems to lack a string-like .name', file_obj
        )
        return file_obj

    if ext in _COMPRESSOR_REGISTRY and mode.endswith('+'):
        raise ValueError('transparent (de)compression unsupported for mode %r' % mode)

    try:
        callback = _COMPRESSOR_REGISTRY[ext]
    except KeyError:
        return file_obj
    else:
        return callback(file_obj, mode)


#
# NB. avoid using lambda here to make stack traces more readable.
#
register_compressor('.bz2', _handle_bz2)
register_compressor('.gz', _handle_gzip)
