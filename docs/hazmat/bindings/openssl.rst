.. hazmat::

OpenSSL binding
===============

.. currentmodule:: cryptography.hazmat.bindings.openssl.binding

These are `CFFI`_ bindings to the `OpenSSL`_ C library. Cryptography supports
OpenSSL version 1.0.1 and greater.

.. class:: cryptography.hazmat.bindings.openssl.binding.Binding()

    This is the exposed API for the OpenSSL bindings. It has two public
    attributes:

    .. attribute:: ffi

        This is a ``cffi.FFI`` instance. It can be used to allocate and
        otherwise manipulate OpenSSL structures.

    .. attribute:: lib

        This is a ``cffi`` library. It can be used to call OpenSSL functions,
        and access constants.

    .. classmethod:: init_static_locks

        Enables the best available locking callback for OpenSSL.
        See :ref:`openssl-threading`.

.. _openssl-threading:

Threading
---------

``cryptography`` enables OpenSSLs `thread safety facilities`_ in several
different ways depending on the configuration of your system. For users on
OpenSSL 1.1.0 or newer (including anyone who uses a binary wheel) the OpenSSL
internal locking callbacks are automatically used. Otherwise, we first attempt
to use the callbacks provided by your Python implementation specifically for
OpenSSL. This will work in every case except where ``cryptography`` is linked
against a different version of OpenSSL than the one used by your Python
implementation. For this final case we have a C-based locking callback.

.. _`CFFI`: https://cffi.readthedocs.io
.. _`OpenSSL`: https://www.openssl.org/
.. _`thread safety facilities`: https://www.openssl.org/docs/man1.0.2/man3/CRYPTO_THREADID_set_callback.html
