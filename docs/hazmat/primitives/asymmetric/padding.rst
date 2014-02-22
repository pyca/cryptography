.. hazmat::

Padding
=======

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.padding

.. warning::
    `Padding is critical`_ when signing or encrypting data using RSA. Failure to do so can result in forgeable signatures,
    decryption of encrypted data, and compromise of the private key.


.. class:: PSS()

    PSS (Probabilistic Signature Scheme) is a signature scheme defined in
    :rfc:`3447`. It is more complex than PKCS1 but possesses a `security proof`_.
    This is the recommended padding algorithm for RSA.

.. class:: PKCS1()

    PKCS1 (also known as PKCS1 v1.5) is a simpler padding scheme developed for
    use with RSA keys. It is also defined in :rfc:`3447`. While it is generally
    considered sufficient, users are encouraged to use :class:`PSS` when
    possible.

.. _`Padding is critical`: http://rdist.root.org/2009/10/06/why-rsa-encryption-padding-is-critical/
.. _`security proof`: http://eprint.iacr.org/2001/062.pdf
