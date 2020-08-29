__version__ = '0.4'

from contextlib import contextmanager
from functools import partial
import os
from shutil import copyfileobj
import tempfile

from six import text_type, PY2, reraise, StringIO, BytesIO, Iterator, wraps


def enable_unicode(enabled):
    def wrapper(f):
        @wraps(f)
        def _(self, *args, **kwargs):
            rv = f(self, *args, **kwargs)
            if enabled and not isinstance(rv, text_type):
                return rv.decode(self.encoding)
            elif not enabled and isinstance(rv, text_type):
                return rv.encode(self.encoding)
            return rv
        return _
    return wrapper


class Data(Iterator):
    """Dynamically converts between various forms of passed in input data.

    Exactly one of ``arg``, ``data`` or ``file`` must be not-``None``.

    :param arg: Dynamic argument. If a bytestring, will be interpreted as raw
                bytes. A unicode string will be interpreted as text and any
                object that has a ``read()`` method as a file-like.
                Any instance of ``Data`` will be passed through and rendered
                unusable.
    :param encoding: The data's encoding. Will be used for every conversion
                     from bytestrings to text (unicode) if necessary and the
                     other way around.
    :param data: Buffer argument. If unicode string, will be interpreted as
                 text, otherwise as bytestring.
    :param file: File argument. Any object with a ``read()`` method will be
                 treated as file-like. Everything else is considered a
                 filename."""
    data = None
    text = None
    file = None
    filename = None

    def __init__(self, arg=None, encoding=None, data=None, file=None):
        self.orig_args = (arg, data, file, encoding)
        if [arg, data, file].count(None) != 2:
            raise ValueError('Must supply exactly one of data or file')

        # when given a positional argument, try to be smart
        if arg is not None:
            if isinstance(arg, self.__class__):
                # copy attributes
                data = arg.data or arg.text
                file = arg.file or arg.filename
                encoding = arg.encoding
                arg.data = arg.text = arg.file = arg.filename = None
            elif hasattr(arg, 'read'):
                file = arg
            else:
                data = arg

        if data is not None:
            if isinstance(data, text_type):
                self.text = data
            else:
                self.data = data
        elif file is not None:
            if hasattr(file, 'read'):
                self.file = file
                if getattr(file, 'encoding', None):
                    encoding = file.encoding
            else:
                self.filename = file

        self.encoding = encoding or 'utf8'

    def __bytes__(self):
        """Returns the data as bytes (on Python3) or string (on Python2)."""
        if self.data is not None:
            return self.data

        if self.text is not None:
            return self.text.encode(self.encoding)

        if self.file is not None:
            return self.readb()

        if self.filename is not None:
            with open(self.filename, 'rb') as f:
                return f.read()

        raise ValueError('Broken Data, all None.')

    def __enter__(self):
        """Context manager support. If data is a file-like, will close it upon
        exiting the context manager."""
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.close()

    def __iter__(self):
        """Iterator support. Returns lines (similar to file objects) using
        :meth:`~data.Data.readline`."""
        return self

    def __next__(self):
        chunk = self.readline()
        if not chunk:
            raise StopIteration
        return chunk

    def __str__(self):
        """Returns the data as unicode (on Python3) or string (on Python2)."""
        if PY2:
            return self.__bytes__()
        return self.__unicode__()

    def __unicode__(self):
        """Returns the data as unicode."""
        if self.text is not None:
            return self.text

        if self.file is not None:
            return self.read()

        return self.__bytes__().decode(self.encoding)

    def __repr__(self):
        def head(buf):
            if len(buf) < 20:
                return repr(buf)

            return repr(buf[:20]) + '...'

        cname = self.__class__.__name__

        if self.data is not None:
            return '{}(data={}, encoding={!r})'.format(
                cname, head(self.data), self.encoding,
            )

        if self.text is not None:
            return '{}(data={}, encoding={!r})'.format(
                cname, head(self.text), self.encoding,
            )

        return '{}(file={!r}, encoding={!r})'.format(
            cname, self.file or self.filename, self.encoding,
        )

    def close(self):
        """Closes input if based on open filelike. Otherwise does nothing."""
        # only close if we have something to close
        if getattr(self, '_stream', None) is None and self.file is None:
            return

        self.stream.close()

    @property
    def stream(self):
        """Returns a stream object (:func:`file`, :class:`~io.BytesIO` or
        :class:`~StringIO.StringIO`) on the data."""

        if not hasattr(self, '_stream'):
            if self.file is not None:
                self._stream = self.file
            elif self.filename is not None:
                self._stream = open(self.filename, 'rb')
            elif self.text is not None:
                self._stream = StringIO(self.text)
            elif self.data is not None:
                self._stream = BytesIO(self.data)
            else:
                raise ValueError('Broken Data, all None.')
        return self._stream

    @enable_unicode(True)
    def read(self, *args, **kwargs):
        """Read method, implements same interface as :func:`file.read`. Always
        returns ``unicode``."""
        return self.stream.read(*args, **kwargs)

    @enable_unicode(False)
    def readb(self, *args, **kwargs):
        """Like :meth:`~data.Data.read`, but returns bytestrings instead."""
        return self.stream.read(*args, **kwargs)

    @enable_unicode(True)
    def readline(self, *args, **kwargs):
        """Return one line from stream. Always returns unicode."""
        return self.stream.readline(*args)

    def readlines(self, *args, **kwargs):
        """Return list of all lines. Always returns list of unicode."""
        return list(iter(partial(self.readline, *args, **kwargs), u''))

    def save_to(self, file):
        """Save data to file.

        Will copy by either writing out the data or using
        :func:`shutil.copyfileobj`.

        :param file: A file-like object (with a ``write`` method) or a
                     filename."""
        dest = file

        if hasattr(dest, 'write'):
            # writing to a file-like
            # only works when no unicode conversion is done
            if self.file is not None and\
                    getattr(self.file, 'encoding', None) is None:
                copyfileobj(self.file, dest)
            elif self.filename is not None:
                with open(self.filename, 'rb') as inp:
                    copyfileobj(inp, dest)
            else:
                dest.write(self.__bytes__())
        else:
            # we do not use filesystem io to make sure we have the same
            # permissions all around
            # copyfileobj() should be efficient enough

            # destination is a filename
            with open(dest, 'wb') as out:
                return self.save_to(out)

    @contextmanager
    def temp_saved(self, suffix='', prefix='tmp', dir=None):
        """Saves data to temporary file and returns the relevant instance of
        :func:`~tempfile.NamedTemporaryFile`. The resulting file is not
        deleted upon closing, but when the context manager exits.

        Other arguments are passed on to :func:`~tempfile.NamedTemporaryFile`.
        """
        tmp = tempfile.NamedTemporaryFile(
            suffix=suffix,
            prefix=prefix,
            dir=dir,
            delete=False,
        )

        try:
            self.save_to(tmp)
            tmp.flush()
            tmp.seek(0)
            yield tmp
        finally:
            try:
                os.unlink(tmp.name)
            except OSError as e:
                if e.errno != 2:
                    reraise(e)
