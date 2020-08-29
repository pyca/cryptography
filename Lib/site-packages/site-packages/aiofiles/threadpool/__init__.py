"""Handle files using a thread pool executor."""
import asyncio
from types import coroutine

from io import (
    FileIO,
    TextIOBase,
    BufferedReader,
    BufferedWriter,
    BufferedRandom,
)
from functools import partial, singledispatch

from .binary import AsyncBufferedIOBase, AsyncBufferedReader, AsyncFileIO
from .text import AsyncTextIOWrapper
from ..base import AiofilesContextManager

sync_open = open

__all__ = ("open",)


def open(
    file,
    mode="r",
    buffering=-1,
    encoding=None,
    errors=None,
    newline=None,
    closefd=True,
    opener=None,
    *,
    loop=None,
    executor=None
):
    return AiofilesContextManager(
        _open(
            file,
            mode=mode,
            buffering=buffering,
            encoding=encoding,
            errors=errors,
            newline=newline,
            closefd=closefd,
            opener=opener,
            loop=loop,
            executor=executor,
        )
    )


@coroutine
def _open(
    file,
    mode="r",
    buffering=-1,
    encoding=None,
    errors=None,
    newline=None,
    closefd=True,
    opener=None,
    *,
    loop=None,
    executor=None
):
    """Open an asyncio file."""
    if loop is None:
        loop = asyncio.get_event_loop()
    cb = partial(
        sync_open,
        file,
        mode=mode,
        buffering=buffering,
        encoding=encoding,
        errors=errors,
        newline=newline,
        closefd=closefd,
        opener=opener,
    )
    f = yield from loop.run_in_executor(executor, cb)

    return wrap(f, loop=loop, executor=executor)


@singledispatch
def wrap(file, *, loop=None, executor=None):
    raise TypeError("Unsupported io type: {}.".format(file))


@wrap.register(TextIOBase)
def _(file, *, loop=None, executor=None):
    return AsyncTextIOWrapper(file, loop=loop, executor=executor)


@wrap.register(BufferedWriter)
def _(file, *, loop=None, executor=None):
    return AsyncBufferedIOBase(file, loop=loop, executor=executor)


@wrap.register(BufferedReader)
@wrap.register(BufferedRandom)
def _(file, *, loop=None, executor=None):
    return AsyncBufferedReader(file, loop=loop, executor=executor)


@wrap.register(FileIO)
def _(file, *, loop=None, executor=None):
    return AsyncFileIO(file, loop, executor)
