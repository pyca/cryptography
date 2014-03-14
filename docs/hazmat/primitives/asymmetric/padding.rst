.. hazmat::

Padding
=======

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.padding

.. warning::
    `Padding is critical`_ when signing or encrypting data using RSA. Without
    correct padding signatures can be forged, messages decrypted, and private
    keys compromised.

.. class:: PSS(mgf)

    .. versionadded:: 0.3

    PSS (Probabilistic Signature Scheme) is a signature scheme defined in
    :rfc:`3447`. It is more complex than PKCS1 but possesses a `security proof`_.
    This is the recommended padding algorithm for RSA.

    :param mgf: A mask generation function object. At this time the only
        supported MGF is :class:`MGF1`.

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

    .. attribute:: MAX_LENGTH

        Pass this attribute to ``salt_length`` to get the maximum salt length
        available.


.. _`Padding is critical`: http://rdist.root.org/2009/10/06/why-rsa-encryption-padding-is-critical/
.. _`security proof`: http://eprint.iacr.org/2001/062.pdf
