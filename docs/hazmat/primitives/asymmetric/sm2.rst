.. hazmat::

SM2 signing
===============

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.sm2


The SM2 family of elliptic curve algorithms is standardized in OSCCA publication
`GM/T 0003-2012`_, and later in `ISO/IEC 14888-3:2018`_. It includes a signature
scheme (`GM/T 0003-2012.2`). Unlike other elliptic curve algorithms, SM2
algorithms additionally include a user id string as an input. SM2 is currently
only supported with the SM3 hash algorithm, and should be used for compatibility
purposes where required and is not otherwise recommended for use.


Signing & Verification
~~~~~~~~~~~~~~~~~~~~~~

.. doctest::

    >>> from cryptography.hazmat.primitives.asymmetric.sm2 import SM2PrivateKey
    >>> private_key = SM2PrivateKey.generate()
    >>> signature = private_key.sign(b"my authenticated message", b"user@example.com")
    >>> public_key = private_key.public_key()
    >>> # Raises InvalidSignature if verification fails
    >>> public_key.verify(signature, b"my authenticated message", b"user@example.com")

Key interfaces
~~~~~~~~~~~~~~

.. class:: SM2PrivateKey

    .. versionadded:: 2.6

    .. classmethod:: generate()

        Generate an SM2 private key.

        :returns: :class:`SM2PrivateKey`

    .. classmethod:: from_private_bytes(data)

        :param data: PKCS8 format and DER encoded private key.
        :type data: :term:`bytes-like`

        :returns: :class:`SM2PrivateKey`

        :raises cryptography.exceptions.UnsupportedAlgorithm: If the private key
            is of a type that is not supported by the backend.

        .. doctest::

            >>> from cryptography.hazmat.primitives import serialization
            >>> from cryptography.hazmat.primitives.asymmetric import sm2
            >>> private_key = sm2.SM2PrivateKey.generate()
            >>> private_bytes = private_key.private_bytes(
            ...     encoding=serialization.Encoding.DER,
            ...     format=serialization.PrivateFormat.PKCS8,
            ...     encryption_algorithm=serialization.NoEncryption()
            ... )
            >>> loaded_private_key = sm2.SM2PrivateKey.from_private_bytes(private_bytes)


    .. method:: public_key()

        :returns: :class:`SM2PublicKey`

    .. method:: sign(data, user_id)

        :param bytes data: The data to sign.

        :param bytes user_id: The user id to include in the signature. A common
            default is b'1234567812345678', or the empty string for use in PGP.

        :returns bytes: The encoded signature.

    .. method:: private_bytes(encoding, format, encryption_algorithm)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`,
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`, or
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`) and
        format (
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8`,
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.OpenSSH`
        or
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`
        ) are chosen to define the exact serialization.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.PrivateFormat`
            enum. If the ``encoding`` is
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
            then ``format`` must be
            :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`
            , otherwise it must be
            :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8` or
            :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.OpenSSH`.

        :param encryption_algorithm: An instance of an object conforming to the
            :class:`~cryptography.hazmat.primitives.serialization.KeySerializationEncryption`
            interface.

        :return bytes: Serialized key.

.. class:: SM2PublicKey

    .. versionadded:: 2.6

    .. classmethod:: from_public_bytes(data)

        :param bytes data: encoded uncompressed public key point.

        :returns: :class:`SM2PublicKey`

        :raises cryptography.exceptions.UnsupportedAlgorithm: If the public key
            is of a type that is not supported by the backend.

        .. doctest::

            >>> from cryptography.hazmat.primitives import serialization
            >>> from cryptography.hazmat.primitives.asymmetric import sm2
            >>> private_key = sm2.SM2PrivateKey.generate()
            >>> public_key = private_key.public_key()
            >>> public_bytes = public_key.public_bytes(
            ...     encoding=serialization.Encoding.Raw,
            ...     format=serialization.PublicFormat.Raw
            ... )
            >>> loaded_public_key = sm2.SM2PublicKey.from_public_bytes(public_bytes)

    .. method:: public_bytes(encoding, format)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`,
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`,
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.OpenSSH`,
        or
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`) and
        format (
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo`,
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.OpenSSH`
        , or
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`
        ) are chosen to define the exact serialization.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.PublicFormat`
            enum. If the ``encoding`` is
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
            then ``format`` must be
            :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`.
            If ``encoding`` is
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.OpenSSH`
            then ``format`` must be
            :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.OpenSSH`.
            In all other cases ``format`` must be
            :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo`.

        :returns bytes: The public key bytes.

    .. method:: verify(signature, data, user_id)

        :param bytes signature: The signature to verify.

        :param bytes data: The data to verify.

        :param bytes user_id: The user id the data was signed with

        :raises cryptography.exceptions.InvalidSignature: Raised when the
            signature cannot be verified.

.. _`GM/T 0003-2012`: http://www.gmbz.org.cn/upload/2018-07-24/1532401673134070738.pdf
.. _`GM/T 0003-2012.2`: http://www.gmbz.org.cn/upload/2018-07-24/1532401673138056311.pdf
.. _`ISO/IEC 14888-3:2018`: https://www.iso.org/standard/76382.html
