from ..base import AsyncBase
from .utils import (
    delegate_to_executor,
    proxy_method_directly,
    proxy_property_directly,
)


@delegate_to_executor(
    "close",
    "flush",
    "isatty",
    "read",
    "read1",
    "readinto",
    "readline",
    "readlines",
    "seek",
    "seekable",
    "tell",
    "truncate",
    "writable",
    "write",
    "writelines",
)
@proxy_method_directly("detach", "fileno", "readable")
@proxy_property_directly("closed", "raw")
class AsyncBufferedIOBase(AsyncBase):
    """The asyncio executor version of io.BufferedWriter."""


@delegate_to_executor("peek")
class AsyncBufferedReader(AsyncBufferedIOBase):
    """The asyncio executor version of io.BufferedReader and Random."""


@delegate_to_executor(
    "close",
    "flush",
    "isatty",
    "read",
    "readall",
    "readinto",
    "readline",
    "readlines",
    "seek",
    "seekable",
    "tell",
    "truncate",
    "writable",
    "write",
    "writelines",
)
@proxy_method_directly("fileno", "readable")
@proxy_property_directly("closed")
class AsyncFileIO(AsyncBase):
    """The asyncio executor version of io.FileIO."""
