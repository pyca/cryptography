.. hazmat::

Padding
=======

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.padding

.. warning::
    `Padding is critical`_ when signing or encrypting data using RSA. Without
    correct padding signatures can be forged, messages decrypted, and private
    keys compromised.

.. class:: PKCS1v15()

    .. versionadded:: 0.3

    PKCS1 v1.5 (also known as simply PKCS1) is a simple padding scheme
    developed for use with RSA keys. It is defined in :rfc:`3447`.

Mask Generation Functions
~~~~~~~~~~~~~~~~~~~~~~~~~

.. class:: MGF1(algorithm, salt_length)

    .. versionadded:: 0.3

    MGF1 (Mask Generation Function 1) is used as the mask generation function
    in :class:`PSS` padding. It takes a hash algorithm and a salt length.

    :param algorithm: An instance of a
        :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
        provider.

    :param int salt_length: The length of the salt. It is recommended that this
        be set to ``MGF1.MAX_LENGTH``.


.. _`Padding is critical`: http://rdist.root.org/2009/10/06/why-rsa-encryption-padding-is-critical/
