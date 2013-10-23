OpenSSL
=======

.. warning::

    The OpenSSL API is not easy to use, small mistakes can lead to significant
    security vulnerabilities. We strongly recommend not using this directly,
    and instead using one of the higher level APIs exposed by ``cryptography``.


These are `CFFI`_ bindings to the `OpenSSL`_ C library.

.. data:: cryptography.bindings.openssl.backend

    This is the exposed API for the OpenSSL bindings. It has two public
    attributes:

    .. attribute:: ffi

        This is a :class:`cffi.FFI` instance. It can be used to allocate and
        otherwise manipulate OpenSSL structures.

    .. attribute:: lib

        This is a ``cffi`` library. It can be used to call OpenSSL functions,
        and access constants.


.. _`CFFI`: http://cffi.readthedocs.org/
.. _`OpenSSL`: https://www.openssl.org/
