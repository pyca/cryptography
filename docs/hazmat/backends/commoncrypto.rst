.. hazmat::

CommonCrypto backend
====================

The `CommonCrypto`_ C library provided by Apple on OS X and iOS. The
CommonCrypto backend is only supported on OS X versions 10.8 and above.

.. currentmodule:: cryptography.hazmat.backends.commoncrypto.backend

.. versionadded:: 0.2

.. data:: cryptography.hazmat.backends.commoncrypto.backend

    This is the exposed API for the CommonCrypto backend.

    It implements the following interfaces:

    * :class:`~cryptography.hazmat.backends.interfaces.CipherBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.HashBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.HMACBackend`
    * :class:`~cryptography.hazmat.backends.interfaces.PBKDF2HMACBackend`

    It has one additional public attribute.

    .. attribute:: name

        The string name of this backend: ``"commoncrypto"``

.. _`CommonCrypto`: https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man3/Common%20Crypto.3cc.html
