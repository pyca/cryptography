.. hazmat::

DSA
===

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.dsa

`DSA`_ is a `public-key`_ algorithm for signing messages.

.. class:: DSAParameters(modulus, subgroup_order, generator)

    .. versionadded:: 0.4

    DSA Parameters are required for generating a DSA private key.

    You should use :meth:`~generate` to generate new parameters.

    .. warning::
        This method only checks a limited set of properties of its arguments.
        Using DSA parameters that you do not trust or with incorrect arguments
        may lead to insecure operation, crashes, and other undefined behavior.
        We recommend that you only ever load parameters that were generated
        with software you trust.


    This class conforms to the
    :class:`~cryptography.hazmat.primitives.interfaces.DSAParameters`
    interface.

    :raises TypeError: This is raised when the arguments are not all integers.

    :raises ValueError: This is raised when the values of ``modulus``,
                        ``subgroup_order``, or ``generator`` do
                        not match the bounds specified in `FIPS 186-4`_.

    .. classmethod:: generate(key_size, backend)

        Generate a new ``DSAParameters`` instance using ``backend``.

        :param int key_size: The length of the modulus in bits. It should be
            either "1024, 2048 or 3072". For keys generated in 2014 this should
            be `at least 2048`_ (See page 41).
            Note that some applications (such as SSH) have not yet gained support
            for larger key sizes specified in FIPS 186-3 and are still restricted
            to only the 1024-bit keys specified in FIPS 186-2.

        :return: A new instance of ``DSAParameters``

        :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if
            the provided ``backend`` does not implement
            :class:`~cryptography.hazmat.backends.interfaces.DSABackend`


.. class:: DSAPrivateKey(modulus, subgroup_order, generator, x, y)

    .. versionadded:: 0.4

    A DSA private key is required for signing messages.

    You should use :meth:`~generate` to generate new keys.

    .. warning::
        This method only checks a limited set of properties of its arguments.
        Using a DSA private key that you do not trust or with incorrect
        parameters may lead to insecure operation, crashes, and other undefined
        behavior. We recommend that you only ever load private keys that were
        generated with software you trust.


    This class conforms to the
    :class:`~cryptography.hazmat.primitives.interfaces.DSAPrivateKey`
    interface.

    :raises TypeError: This is raised when the arguments are not all integers.

    :raises ValueError: This is raised when the values of ``modulus``,
                        ``subgroup_order``, or ``generator`` do
                        not match the bounds specified in `FIPS 186-4`_.

    .. classmethod:: generate(parameters, backend)

        Generate a new ``DSAPrivateKey`` instance using ``backend``.

        :param parameters: A
            :class:`~cryptography.hazmat.primitives.interfaces.DSAParameters`
            provider.
        :param backend: A
            :class:`~cryptography.hazmat.backends.interfaces.DSABackend`
            provider.
        :return: A new instance of ``DSAPrivateKey``.

        :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if
            the provided ``backend`` does not implement
            :class:`~cryptography.hazmat.backends.interfaces.DSABackend`

        :raises ValueError: This is raised if the key size is not (1024 or 2048 or 3072)
            or if the OpenSSL version is older than 1.0.0 and the key size is larger than 1024
            because older OpenSSL versions don't support a key size larger than 1024.

    .. method:: signer(algorithm, backend)

        .. versionadded:: 0.4

        Sign data which can be verified later by others using the public key.

        .. code-block:: pycon

            >>> from cryptography.hazmat.backends import default_backend
            >>> from cryptography.hazmat.primitives import hashes
            >>> from cryptography.hazmat.primitives.asymmetric import dsa
            >>> parameters = dsa.DSAParameters.generate(
            ...     key_size=1024,
            ...     backend=default_backend()
            ... )
            >>> private_key = dsa.DSAPrivateKey.generate(
            ...     parameters=parameters,
            ...     backend=default_backend()
            ... )
            >>> signer = private_key.signer(
            ...     hashes.SHA256(),
            ...     default_backend()
            ... )
            >>> data= b"this is some data I'd like to sign"
            >>> signer.update(data)
            >>> signature = signer.finalize()

        :param algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
            provider.

        :param backend: A
            :class:`~cryptography.hazmat.backends.interfaces.RSABackend`
            provider.

        :returns:
            :class:`~cryptography.hazmat.primitives.interfaces.AsymmetricSignatureContext`

        :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if
            the provided ``backend`` does not implement
            :class:`~cryptography.hazmat.backends.interfaces.DSABackend`


.. class:: DSAPublicKey(modulus, subgroup_order, generator, y)

    .. versionadded:: 0.4

    A DSA public key is required for verifying messages.

    Normally you do not need to directly construct public keys because you'll
    be loading them from a file, generating them automatically or receiving
    them from a 3rd party.

    This class conforms to the
    :class:`~cryptography.hazmat.primitives.interfaces.DSAPublicKey`
    interface.

    :raises TypeError: This is raised when the arguments are not all integers.

    :raises ValueError: This is raised when the values of ``modulus``,
                        ``subgroup_order``, ``generator``, or ``y``
                        do not match the bounds specified in `FIPS 186-4`_.

    .. method:: verifier(signature, algorithm, backend)

        .. versionadded:: 0.4

        Verify data was signed by the private key associated with this public
        key.

        .. code-block:: pycon

            >>> from cryptography.hazmat.backends import default_backend
            >>> from cryptography.hazmat.primitives import hashes
            >>> from cryptography.hazmat.primitives.asymmetric import dsa
            >>> parameters = dsa.DSAParameters.generate(
            ...     key_size=1024,
            ...     backend=default_backend()
            ... )
            >>> private_key = dsa.DSAPrivateKey.generate(
            ...     parameters=parameters,
            ...     backend=default_backend()
            ... )
            >>> signer = private_key.signer(
            ...     hashes.SHA256(),
            ...     default_backend()
            ... )
            >>> data = b"this is some data I'd like to sign"
            >>> signer.update(data)
            >>> signature = signer.finalize()
            >>> public_key = private_key.public_key()
            >>> verifier = public_key.verifier(
            ...     signature,
            ...     hashes.SHA256(),
            ...     default_backend()
            ... )
            >>> verifier.update(data)
            >>> verifier.verify()

        :param bytes signature: The signature to verify. DER encoded as
            specified in :rfc:`6979`.

        :param algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
            provider.

        :param backend: A
            :class:`~cryptography.hazmat.backends.interfaces.DSABackend`
            provider.

        :returns:
            :class:`~cryptography.hazmat.primitives.interfaces.AsymmetricVerificationContext`

.. _`DSA`: https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
.. _`public-key`: https://en.wikipedia.org/wiki/Public-key_cryptography
.. _`FIPS 186-4`: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
.. _`at least 2048`: http://www.ecrypt.eu.org/documents/D.SPA.20.pdf
