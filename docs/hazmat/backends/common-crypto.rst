.. hazmat::

CommonCrypto Backend
====================

The `CommonCrypto`_ C library provided by Apple on OS X and iOS.

.. currentmodule:: cryptography.hazmat.backends.commoncrypto.backend

.. versionadded:: 0.2

.. data:: cryptography.hazmat.backends.commoncrypto.backend

    This is the exposed API for the CommonCrypto backend. It has one public attribute.

    .. attribute:: name

        The string name of this backend: ``"commoncrypto"``

.. _`CommonCrypto`: https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man3/Common%20Crypto.3cc.html
