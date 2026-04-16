.. hazmat::

ML-KEM key encapsulation
========================

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.mlkem

ML-KEM is a post-quantum key encapsulation mechanism based on module
lattices, standardized in `FIPS 203`_.

Encapsulation & Decapsulation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doctest::
    :skipif: not _backend.mlkem_supported()

    >>> from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
    >>> private_key = MLKEM768PrivateKey.generate()
    >>> public_key = private_key.public_key()
    >>> shared_secret, ciphertext = public_key.encapsulate()
    >>> recovered_secret = private_key.decapsulate(ciphertext)
    >>> shared_secret == recovered_secret
    True

Key interfaces
~~~~~~~~~~~~~~

.. class:: MLKEM768PrivateKey

    .. versionadded:: 47.0

    .. classmethod:: generate()

        Generate an ML-KEM-768 private key.

        :returns: :class:`MLKEM768PrivateKey`

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-KEM-768 is
            not supported by the backend ``cryptography`` is using.

    .. classmethod:: from_seed_bytes(data)

        Load an ML-KEM-768 private key from seed bytes.

        :param data: 64 byte seed.
        :type data: :term:`bytes-like`

        :returns: :class:`MLKEM768PrivateKey`

        :raises ValueError: If the seed is not 64 bytes.

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-KEM-768 is
            not supported by the backend ``cryptography`` is using.

        .. doctest::
            :skipif: not _backend.mlkem_supported()

            >>> from cryptography.hazmat.primitives.asymmetric import mlkem
            >>> private_key = mlkem.MLKEM768PrivateKey.generate()
            >>> seed = private_key.private_bytes_raw()
            >>> same_key = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)

    .. method:: public_key()

        :returns: :class:`MLKEM768PublicKey`

    .. method:: decapsulate(ciphertext)

        Decapsulate a ciphertext using ML-KEM-768, returning the shared
        secret.

        :param ciphertext: The ciphertext to decapsulate (1088 bytes).
        :type ciphertext: :term:`bytes-like`

        :returns bytes: The shared secret (32 bytes).

        :raises ValueError: If the ciphertext is not the correct length.

    .. method:: private_bytes(encoding, format, encryption_algorithm)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`,
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`, or
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`) and
        format (
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8`
        or
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`
        ) are chosen to define the exact serialization.

        This method only returns the serialization of the seed form of the
        private key, never the expanded one.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.PrivateFormat`
            enum. If the ``encoding`` is
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
            then ``format`` must be
            :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`
            , otherwise it must be
            :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8`.

        :param encryption_algorithm: An instance of an object conforming to the
            :class:`~cryptography.hazmat.primitives.serialization.KeySerializationEncryption`
            interface.

        :return bytes: Serialized key.

    .. method:: private_bytes_raw()

        Allows serialization of the key to raw bytes. This method is a
        convenience shortcut for calling :meth:`private_bytes` with
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
        encoding,
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`
        format, and
        :class:`~cryptography.hazmat.primitives.serialization.NoEncryption`.

        This method only returns the seed form of the private key (64 bytes).

        :return bytes: Raw key (64-byte seed).

.. class:: MLKEM768PublicKey

    .. versionadded:: 47.0

    .. classmethod:: from_public_bytes(data)

        :param bytes data: 1184 byte public key.

        :returns: :class:`MLKEM768PublicKey`

        :raises ValueError: If the public key is not 1184 bytes.

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-KEM-768 is
            not supported by the backend ``cryptography`` is using.

        .. doctest::
            :skipif: not _backend.mlkem_supported()

            >>> from cryptography.hazmat.primitives import serialization
            >>> from cryptography.hazmat.primitives.asymmetric import mlkem
            >>> private_key = mlkem.MLKEM768PrivateKey.generate()
            >>> public_key = private_key.public_key()
            >>> public_bytes = public_key.public_bytes(
            ...     encoding=serialization.Encoding.Raw,
            ...     format=serialization.PublicFormat.Raw
            ... )
            >>> loaded_public_key = mlkem.MLKEM768PublicKey.from_public_bytes(public_bytes)

    .. method:: encapsulate()

        Generate a shared secret and encapsulate it for this public key.

        :returns: A ``(shared_secret, ciphertext)`` tuple where both values
            are :class:`bytes`. The shared secret is 32 bytes and the
            ciphertext is 1088 bytes.

    .. method:: public_bytes(encoding, format)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`,
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`, or
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`) and
        format (
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo`
        or
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`
        ) are chosen to define the exact serialization.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.PublicFormat`
            enum. If the ``encoding`` is
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
            then ``format`` must be
            :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`
            , otherwise it must be
            :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo`.

        :returns bytes: The public key bytes.

    .. method:: public_bytes_raw()

        Allows serialization of the key to raw bytes. This method is a
        convenience shortcut for calling :meth:`public_bytes` with
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
        encoding and
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`
        format.

        :return bytes: 1184-byte raw public key.

.. class:: MLKEM1024PrivateKey

    .. versionadded:: 47.0

    .. classmethod:: generate()

        Generate an ML-KEM-1024 private key.

        :returns: :class:`MLKEM1024PrivateKey`

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-KEM-1024 is
            not supported by the backend ``cryptography`` is using.

    .. classmethod:: from_seed_bytes(data)

        Load an ML-KEM-1024 private key from seed bytes.

        :param data: 64 byte seed.
        :type data: :term:`bytes-like`

        :returns: :class:`MLKEM1024PrivateKey`

        :raises ValueError: If the seed is not 64 bytes.

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-KEM-1024 is
            not supported by the backend ``cryptography`` is using.

        .. doctest::
            :skipif: not _backend.mlkem_supported()

            >>> from cryptography.hazmat.primitives.asymmetric import mlkem
            >>> private_key = mlkem.MLKEM1024PrivateKey.generate()
            >>> seed = private_key.private_bytes_raw()
            >>> same_key = mlkem.MLKEM1024PrivateKey.from_seed_bytes(seed)

    .. method:: public_key()

        :returns: :class:`MLKEM1024PublicKey`

    .. method:: decapsulate(ciphertext)

        Decapsulate a ciphertext using ML-KEM-1024, returning the shared
        secret.

        :param ciphertext: The ciphertext to decapsulate (1568 bytes).
        :type ciphertext: :term:`bytes-like`

        :returns bytes: The shared secret (32 bytes).

        :raises ValueError: If the ciphertext is not the correct length.

    .. method:: private_bytes(encoding, format, encryption_algorithm)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`,
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`, or
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`) and
        format (
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8`
        or
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`
        ) are chosen to define the exact serialization.

        This method only returns the serialization of the seed form of the
        private key, never the expanded one.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.PrivateFormat`
            enum. If the ``encoding`` is
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
            then ``format`` must be
            :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`
            , otherwise it must be
            :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8`.

        :param encryption_algorithm: An instance of an object conforming to the
            :class:`~cryptography.hazmat.primitives.serialization.KeySerializationEncryption`
            interface.

        :return bytes: Serialized key.

    .. method:: private_bytes_raw()

        Allows serialization of the key to raw bytes. This method is a
        convenience shortcut for calling :meth:`private_bytes` with
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
        encoding,
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.Raw`
        format, and
        :class:`~cryptography.hazmat.primitives.serialization.NoEncryption`.

        This method only returns the seed form of the private key (64 bytes).

        :return bytes: Raw key (64-byte seed).

.. class:: MLKEM1024PublicKey

    .. versionadded:: 47.0

    .. classmethod:: from_public_bytes(data)

        :param bytes data: 1568 byte public key.

        :returns: :class:`MLKEM1024PublicKey`

        :raises ValueError: If the public key is not 1568 bytes.

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-KEM-1024 is
            not supported by the backend ``cryptography`` is using.

        .. doctest::
            :skipif: not _backend.mlkem_supported()

            >>> from cryptography.hazmat.primitives import serialization
            >>> from cryptography.hazmat.primitives.asymmetric import mlkem
            >>> private_key = mlkem.MLKEM1024PrivateKey.generate()
            >>> public_key = private_key.public_key()
            >>> public_bytes = public_key.public_bytes(
            ...     encoding=serialization.Encoding.Raw,
            ...     format=serialization.PublicFormat.Raw
            ... )
            >>> loaded_public_key = mlkem.MLKEM1024PublicKey.from_public_bytes(public_bytes)

    .. method:: encapsulate()

        Generate a shared secret and encapsulate it for this public key.

        :returns: A ``(shared_secret, ciphertext)`` tuple where both values
            are :class:`bytes`. The shared secret is 32 bytes and the
            ciphertext is 1568 bytes.

    .. method:: public_bytes(encoding, format)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`,
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`, or
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`) and
        format (
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo`
        or
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`
        ) are chosen to define the exact serialization.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.PublicFormat`
            enum. If the ``encoding`` is
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
            then ``format`` must be
            :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`
            , otherwise it must be
            :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo`.

        :returns bytes: The public key bytes.

    .. method:: public_bytes_raw()

        Allows serialization of the key to raw bytes. This method is a
        convenience shortcut for calling :meth:`public_bytes` with
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.Raw`
        encoding and
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.Raw`
        format.

        :return bytes: 1568-byte raw public key.


.. _`FIPS 203`: https://csrc.nist.gov/pubs/fips/203/final
