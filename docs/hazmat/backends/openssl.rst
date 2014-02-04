.. hazmat::

OpenSSL Backend
===============

The `OpenSSL`_ C library.

.. data:: cryptography.hazmat.backends.openssl.backend

    This is the exposed API for the OpenSSL backend.

    It implements the following interfaces:

    * :class:`~cryptography.hazmat.backends.interfaces.CipherBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.HashBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.HMACBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.PBKDF2HMACBackend`

    It has one additional public attribute.

    .. attribute:: name

        The string name of this backend: ``"openssl"``

.. _`OpenSSL`: https://www.openssl.org/
