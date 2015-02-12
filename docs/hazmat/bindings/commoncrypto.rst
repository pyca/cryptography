.. hazmat::

CommonCrypto binding
====================

.. currentmodule:: cryptography.hazmat.bindings.commoncrypto.binding

.. versionadded:: 0.2

These are `CFFI`_ bindings to the `CommonCrypto`_ C library. It is only
available on Mac OS X versions 10.8 and above.

.. class:: cryptography.hazmat.bindings.commoncrypto.binding.Binding()

    This is the exposed API for the CommonCrypto bindings. It has two public
    attributes:

    .. attribute:: ffi

        This is a ``cffi.FFI`` instance. It can be used to allocate and
        otherwise manipulate CommonCrypto structures.

    .. attribute:: lib

        This is a ``cffi`` library. It can be used to call CommonCrypto
        functions, and access constants.


.. _`CFFI`: https://cffi.readthedocs.org/
.. _`CommonCrypto`: https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man3/Common%20Crypto.3cc.html
