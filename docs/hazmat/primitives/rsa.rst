.. hazmat::

RSA
===

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.rsa

`RSA`_ is a `public-key`_ algorithm for encrypting and signing messages.

.. class:: RSAPrivateKey(p, q, private_exponent, dmp1, dmq1, iqmp,
                         public_exponent, modulus)

    .. versionadded:: 0.2

    An RSA private key is required for decryption and signing of messages.

    You should use
    :meth:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.generate`
    to generate new keys.

    .. warning::
        This method only checks a limited set of properties of its arguments.
        Using an RSA that you do not trust or with incorrect parameters may
        lead to insecure operation, crashes, and other undefined behavior. We
        recommend that you only ever load private keys that were generated with
        software you trust.


    This class conforms to the
    :class:`~cryptography.hazmat.primitives.interfaces.RSAPrivateKey`
    interface.

    :raises TypeError: This is raised when the arguments are not all integers.

    :raises ValueError: This is raised when the values of `p`, `q`,
                        `private_exponent`, `public_exponent` or `modulus` do
                        not match the bounds specified in `RFC 3447`_.

    .. classmethod:: generate(public_exponent, key_size, backend)

        Generate a new ``RSAPrivateKey`` instance using ``backend``.

        :param int public_exponent: The public exponent of the new key.
            Usually one of the small Fermat primes 3, 5, 17, 257, 65537. If in
            doubt you should `use 65537`_.
        :param int key_size: The length of the modulus in bits. For keys
            generated in 2014 this should be `at least 2048`_. (See page 41.)
            Must be at least 512. Some backends may have additional
            limitations.
        :param backend: A
            :class:`~cryptography.hazmat.backends.interfaces.RSABackend`
            provider.
        :return: A new instance of ``RSAPrivateKey``.

.. class:: RSAPublicKey(public_exponent, modulus)

    .. versionadded:: 0.2

    An RSA public key is required for encryption and verification of messages.

    Normally you do not need to directly construct public keys because you'll
    be loading them from a file, generating them automatically or receiving
    them from a 3rd party.

    This class conforms to the
    :class:`~cryptography.hazmat.primitives.interfaces.RSAPublicKey`
    interface.

    :raises TypeError: This is raised when the arguments are not all integers.

    :raises ValueError: This is raised when the values of `public_exponent` or
                        `modulus` do not match the bounds specified in
                        `RFC 3447`_.

.. _`RSA`: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
.. _`public-key`: https://en.wikipedia.org/wiki/Public-key_cryptography
.. _`RFC 3447`: https://tools.ietf.org/html/rfc3447
.. _`use 65537`: http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
.. _`at least 2048`: http://www.ecrypt.eu.org/documents/D.SPA.20.pdf
