.. hazmat::

RSA
===

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.rsa

`RSA`_ is a `public-key`_ algorithm for encrypting and signing messages.

.. class:: RSAPrivateKey(p, q, private_exponent, dmp1, dmq1, iqmp, public_exponent, modulus)

    .. versionadded:: 0.2

    An RSA private key is required for decryption and signing of messages.

    You should use :meth:`~generate` to generate new keys.

    .. warning::
        This method only checks a limited set of properties of its arguments.
        Using an RSA private key that you do not trust or with incorrect
        parameters may lead to insecure operation, crashes, and other undefined
        behavior. We recommend that you only ever load private keys that were
        generated with software you trust.


    This class conforms to the
    :class:`~cryptography.hazmat.primitives.interfaces.RSAPrivateKey`
    interface.

    :raises TypeError: This is raised when the arguments are not all integers.

    :raises ValueError: This is raised when the values of ``p``, ``q``,
                        ``private_exponent``, ``public_exponent``, or
                        ``modulus`` do not match the bounds specified in
                        :rfc:`3447`.

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

    .. method:: signer(padding, algorithm, backend)

        .. versionadded:: 0.3

        :param padding: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.AsymmetricPadding`
            provider.

        :param algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
            provider.

        :param backend: A
            :class:`~cryptography.hazmat.backends.interfaces.RSABackend`
            provider.

        :returns:
            :class:`~cryptography.hazmat.primitives.interfaces.AsymmetricSignatureContext`

        .. doctest::

            >>> from cryptography.hazmat.backends import default_backend
            >>> from cryptography.hazmat.primitives import hashes
            >>> from cryptography.hazmat.primitives.asymmetric import rsa, padding
            >>> private_key = rsa.RSAPrivateKey.generate(
            ...     public_exponent=65537,
            ...     key_size=2048,
            ...     backend=default_backend()
            ... )
            >>> signer = private_key.signer(padding.PKCS1(), hashes.SHA256(), default_backend())
            >>> signer.update(b"this is some data I'd like")
            >>> signer.update(b" to sign")
            >>> signature = signer.finalize()


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

    :raises ValueError: This is raised when the values of ``public_exponent``
                        or ``modulus`` do not match the bounds specified in
                        :rfc:`3447`.

.. _`RSA`: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
.. _`public-key`: https://en.wikipedia.org/wiki/Public-key_cryptography
.. _`use 65537`: http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
.. _`at least 2048`: http://www.ecrypt.eu.org/documents/D.SPA.20.pdf
