"""Multidict implementation.

HTTP Headers and URL query string require specific data structure:
multidict. It behaves mostly like a dict but it can have
several values for the same key.
"""

from ._abc import MultiMapping, MutableMultiMapping
from ._compat import USE_CYTHON_EXTENSIONS

__all__ = (
    "MultiMapping",
    "MutableMultiMapping",
    "MultiDictProxy",
    "CIMultiDictProxy",
    "MultiDict",
    "CIMultiDict",
    "upstr",
    "istr",
    "getversion"
)

__version__ = "4.7.6"


try:
    if not USE_CYTHON_EXTENSIONS:
        raise ImportError
    from ._multidict import (
        MultiDictProxy,
        CIMultiDictProxy,
        MultiDict,
        CIMultiDict,
        istr,
        getversion,
    )
except ImportError:  # pragma: no cover
    from ._multidict_py import (
        MultiDictProxy,
        CIMultiDictProxy,
        MultiDict,
        CIMultiDict,
        istr,
        getversion,
    )


upstr = istr
