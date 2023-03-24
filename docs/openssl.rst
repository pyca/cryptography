Use of OpenSSL
==============

``cryptography`` depends on the `OpenSSL`_ C library for all cryptographic
operation. OpenSSL is the de facto standard for cryptographic libraries and
provides high performance along with various certifications that may be
relevant to developers.

A list of supported versions can be found in our :doc:`/installation`
documentation.

In general the backend should be considered an internal implementation detail
of the project, but there are some public methods available for debugging
purposes.

.. data:: cryptography.hazmat.backends.openssl.backend

    .. method:: openssl_version_text()

        :return text: The friendly string name of the loaded OpenSSL library.
            This is not necessarily the same version as it was compiled against.

    .. method:: openssl_version_number()

        .. versionadded:: 1.8

        :return int: The integer version of the loaded OpenSSL library. This is
            defined in ``opensslv.h`` as ``OPENSSL_VERSION_NUMBER`` and is
            typically shown in hexadecimal (e.g. ``0x1010003f``). This is
            not necessarily the same version as it was compiled against.

.. _legacy-provider:

Legacy provider in OpenSSL 3.x
------------------------------

.. versionadded:: 39.0.0

Users can set ``CRYPTOGRAPHY_OPENSSL_NO_LEGACY`` environment variable to
disable the legacy provider in OpenSSL 3.x. This will disable legacy
cryptographic algorithms, including ``Blowfish``, ``CAST5``, ``SEED``,
``ARC4``, and ``RC2`` (which is used by some encrypted serialization formats).


.. _`OpenSSL`: https://www.openssl.org/
