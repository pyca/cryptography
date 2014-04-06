.. hazmat::

Padding
=======

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.padding

.. warning::
    `Padding is critical`_ when signing or encrypting data using RSA. Without
    correct padding signatures can be forged, messages decrypted, and private
    keys compromised.

.. class:: OAEP(mgf, label)

    .. versionadded:: 0.4

    OAEP (Optimal Asymmetric Encryption Padding) is a padding scheme defined in
    :rfc:`3447`. It provides probabilistic encryption and is `proven secure`_
    against several attack types. This is the `recommended padding algorithm`_
    for RSA encryption. It cannot be used with RSA signing.

    :param mgf: A mask generation function object. At this time the only
        supported MGF is :class:`MGF1`.

    :param bytes label: A label to apply. This is a rarely used field and many
        backends do not support it.

.. class:: PSS(mgf, salt_length)

    .. versionadded:: 0.3

    .. versionchanged:: 0.4
        Added ``salt_length`` parameter.

    PSS (Probabilistic Signature Scheme) is a signature scheme defined in
    :rfc:`3447`. It is more complex than PKCS1 but possesses a `security proof`_.
    This is the `recommended padding algorithm`_ for RSA signatures. It cannot
    be used with RSA encryption.

    :param mgf: A mask generation function object. At this time the only
        supported MGF is :class:`MGF1`.

    :param int salt_length: The length of the salt. It is recommended that this
        be set to ``PSS.MAX_LENGTH``.

    .. attribute:: MAX_LENGTH

        Pass this attribute to ``salt_length`` to get the maximum salt length
        available.

.. class:: PKCS1v15()

    .. versionadded:: 0.3

    PKCS1 v1.5 (also known as simply PKCS1) is a simple padding scheme
    developed for use with RSA keys. It is defined in :rfc:`3447`. This padding
    can be used for signing and encryption.

Mask generation functions
~~~~~~~~~~~~~~~~~~~~~~~~~

.. class:: MGF1(algorithm)

    .. versionadded:: 0.3

    .. versionchanged:: 0.4
        Deprecated the ``salt_length`` parameter.

    MGF1 (Mask Generation Function 1) is used as the mask generation function
    in :class:`PSS` padding. It takes a hash algorithm and a salt length.

    :param algorithm: An instance of a
        :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
        provider.


.. _`Padding is critical`: http://rdist.root.org/2009/10/06/why-rsa-encryption-padding-is-critical/
.. _`proven secure`: http://cseweb.ucsd.edu/users/mihir/papers/oae.pdf
.. _`security proof`: http://eprint.iacr.org/2001/062.pdf
.. _`recommended padding algorithm`: http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
