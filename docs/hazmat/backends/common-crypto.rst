.. hazmat::

CommonCrypto Backend
====================

These are `CFFI`_ bindings to the `CommonCrypto`_ C library provided by Apple
on OS X and iOS.

.. currentmodule:: cryptography.hazmat.backends.commoncrypto.backend

.. data:: cryptography.hazmat.backends.commoncrypto.backend

    This is the exposed API for the CommonCrypto bindings. It has two public
    attributes:

    .. attribute:: ffi

        This is a :class:`cffi.FFI` instance. It can be used to allocate and
        otherwise manipulate CommonCrypto structures.

    .. attribute:: lib

        This is a ``cffi`` library. It can be used to call CommonCrypto
        functions, and access constants.


.. _`CFFI`: https://cffi.readthedocs.org/
.. _`CommonCrypto`: https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man3/Common%20Crypto.3cc.html
