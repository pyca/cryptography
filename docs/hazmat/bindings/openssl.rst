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

``cryptography`` enables OpenSSLs `thread safety facilities`_ in two different
ways depending on the configuration of your system. Normally the locking
callbacks provided by your Python implementation specifically for OpenSSL will
be used. However, if you have linked ``cryptography`` to a different version of
OpenSSL than that used by your Python implementation we enable an alternative
locking callback. This version is implemented in Python and so may result in
lower performance in some situations. In particular parallelism is reduced
because it has to acquire the GIL whenever any lock operations occur within
OpenSSL.

.. _`CFFI`: https://cffi.readthedocs.io
.. _`OpenSSL`: https://www.openssl.org/
.. _`thread safety facilities`: https://www.openssl.org/docs/man1.0.2/crypto/threads.html
