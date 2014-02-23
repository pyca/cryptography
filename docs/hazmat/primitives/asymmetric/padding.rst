.. hazmat::

Padding
=======

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.padding

.. warning::
    `Padding is critical`_ when signing or encrypting data using RSA. Without
    correct padding signatures can be forged, messages decrypted, and private
    keys compromised.

.. class:: PKCS1()

    .. versionadded:: 0.3

    PKCS1 (also known as PKCS1 v1.5) is a simple padding scheme developed for
    use with RSA keys. It is also defined in :rfc:`3447`.

.. _`Padding is critical`: http://rdist.root.org/2009/10/06/why-rsa-encryption-padding-is-critical/
