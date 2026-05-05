.. hazmat::

ML-DSA signing
=================

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.mldsa

ML-DSA is a post-quantum digital signature algorithm based on module
lattices, standardized in `FIPS 204`_.

Signing & Verification
~~~~~~~~~~~~~~~~~~~~~~~

.. doctest::
    :skipif: not _backend.mldsa_supported()

    >>> from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
    >>> private_key = MLDSA65PrivateKey.generate()
    >>> signature = private_key.sign(b"my authenticated message")
    >>> public_key = private_key.public_key()
    >>> public_key.verify(signature, b"my authenticated message")

Context-based Signing & Verification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ML-DSA supports context strings to bind additional information to signatures.
The context can be up to 255 bytes and is used to differentiate signatures in
different contexts or protocols.

.. doctest::
    :skipif: not _backend.mldsa_supported()

    >>> from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
    >>> private_key = MLDSA65PrivateKey.generate()
    >>> context = b"email-signature-v1"
    >>> signature = private_key.sign(b"my authenticated message", context)
    >>> public_key = private_key.public_key()
    >>> # Verification requires the same context
    >>> public_key.verify(signature, b"my authenticated message", context)

Key interfaces
~~~~~~~~~~~~~~

.. class:: MLDSA44PrivateKey

    .. versionadded:: 47.0.0

    .. classmethod:: generate()

        Generate an ML-DSA-44 private key.

        :returns: :class:`MLDSA44PrivateKey`

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-DSA-44 is
            not supported by the backend ``cryptography`` is using.

    .. classmethod:: from_seed_bytes(data)

        Load an ML-DSA-44 private key from seed bytes.

        :param data: 32 byte seed.
        :type data: :term:`bytes-like`

        :returns: :class:`MLDSA44PrivateKey`

        :raises ValueError: If the seed is not 32 bytes.

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-DSA-44 is
            not supported by the backend ``cryptography`` is using.

        .. doctest::
            :skipif: not _backend.mldsa_supported()

            >>> from cryptography.hazmat.primitives.asymmetric import mldsa
            >>> private_key = mldsa.MLDSA44PrivateKey.generate()
            >>> seed = private_key.private_bytes_raw()
            >>> same_key = mldsa.MLDSA44PrivateKey.from_seed_bytes(seed)

    .. method:: public_key()

        :returns: :class:`MLDSA44PublicKey`

    .. method:: sign(data, context=None)

        Sign the data using ML-DSA-44. An optional context string can be
        provided.

        :param data: The data to sign.
        :type data: :term:`bytes-like`

        :param context: An optional context string (up to 255 bytes).
        :type context: :term:`bytes-like` or ``None``

        :returns bytes: The signature (2420 bytes).

        :raises ValueError: If the context is longer than 255 bytes.

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

        This method only returns the seed form of the private key (32 bytes).

        :return bytes: Raw key (32-byte seed).

.. class:: MLDSA44PublicKey

    .. versionadded:: 47.0.0

    .. classmethod:: from_public_bytes(data)

        :param bytes data: 1312 byte public key.

        :returns: :class:`MLDSA44PublicKey`

        :raises ValueError: If the public key is not 1312 bytes.

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-DSA-44 is
            not supported by the backend ``cryptography`` is using.

        .. doctest::
            :skipif: not _backend.mldsa_supported()

            >>> from cryptography.hazmat.primitives import serialization
            >>> from cryptography.hazmat.primitives.asymmetric import mldsa
            >>> private_key = mldsa.MLDSA44PrivateKey.generate()
            >>> public_key = private_key.public_key()
            >>> public_bytes = public_key.public_bytes(
            ...     encoding=serialization.Encoding.Raw,
            ...     format=serialization.PublicFormat.Raw
            ... )
            >>> loaded_public_key = mldsa.MLDSA44PublicKey.from_public_bytes(public_bytes)

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

        :return bytes: 1312-byte raw public key.

    .. method:: verify(signature, data, context=None)

        Verify a signature using ML-DSA-44. If a context string was used during
        signing, the same context must be provided for verification to succeed.

        :param signature: The signature to verify.
        :type signature: :term:`bytes-like`

        :param data: The data to verify.
        :type data: :term:`bytes-like`

        :param context: An optional context string (up to 255 bytes) that was
            used during signing.
        :type context: :term:`bytes-like` or ``None``

        :returns: None
        :raises cryptography.exceptions.InvalidSignature: Raised when the
            signature cannot be verified.
        :raises ValueError: If the context is longer than 255 bytes.

.. class:: MLDSA65PrivateKey

    .. versionadded:: 47.0.0

    .. classmethod:: generate()

        Generate an ML-DSA-65 private key.

        :returns: :class:`MLDSA65PrivateKey`

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-DSA-65 is
            not supported by the backend ``cryptography`` is using.

    .. classmethod:: from_seed_bytes(data)

        Load an ML-DSA-65 private key from seed bytes.

        :param data: 32 byte seed.
        :type data: :term:`bytes-like`

        :returns: :class:`MLDSA65PrivateKey`

        :raises ValueError: If the seed is not 32 bytes.

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-DSA-65 is
            not supported by the backend ``cryptography`` is using.

        .. doctest::
            :skipif: not _backend.mldsa_supported()

            >>> from cryptography.hazmat.primitives.asymmetric import mldsa
            >>> private_key = mldsa.MLDSA65PrivateKey.generate()
            >>> seed = private_key.private_bytes_raw()
            >>> same_key = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed)

    .. method:: public_key()

        :returns: :class:`MLDSA65PublicKey`

    .. method:: sign(data, context=None)

        Sign the data using ML-DSA-65. An optional context string can be
        provided.

        :param data: The data to sign.
        :type data: :term:`bytes-like`

        :param context: An optional context string (up to 255 bytes).
        :type context: :term:`bytes-like` or ``None``

        :returns bytes: The signature (3309 bytes).

        :raises ValueError: If the context is longer than 255 bytes.

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

        This method only returns the seed form of the private key (32 bytes).

        :return bytes: Raw key (32-byte seed).

.. class:: MLDSA65PublicKey

    .. versionadded:: 47.0.0

    .. classmethod:: from_public_bytes(data)

        :param bytes data: 1952 byte public key.

        :returns: :class:`MLDSA65PublicKey`

        :raises ValueError: If the public key is not 1952 bytes.

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-DSA-65 is
            not supported by the backend ``cryptography`` is using.

        .. doctest::
            :skipif: not _backend.mldsa_supported()

            >>> from cryptography.hazmat.primitives import serialization
            >>> from cryptography.hazmat.primitives.asymmetric import mldsa
            >>> private_key = mldsa.MLDSA65PrivateKey.generate()
            >>> public_key = private_key.public_key()
            >>> public_bytes = public_key.public_bytes(
            ...     encoding=serialization.Encoding.Raw,
            ...     format=serialization.PublicFormat.Raw
            ... )
            >>> loaded_public_key = mldsa.MLDSA65PublicKey.from_public_bytes(public_bytes)

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

        :return bytes: 1952-byte raw public key.

    .. method:: verify(signature, data, context=None)

        Verify a signature using ML-DSA-65. If a context string was used during
        signing, the same context must be provided for verification to succeed.

        :param signature: The signature to verify.
        :type signature: :term:`bytes-like`

        :param data: The data to verify.
        :type data: :term:`bytes-like`

        :param context: An optional context string (up to 255 bytes) that was
            used during signing.
        :type context: :term:`bytes-like` or ``None``

        :returns: None
        :raises cryptography.exceptions.InvalidSignature: Raised when the
            signature cannot be verified.
        :raises ValueError: If the context is longer than 255 bytes.

.. class:: MLDSA87PrivateKey

    .. versionadded:: 47.0.0

    .. classmethod:: generate()

        Generate an ML-DSA-87 private key.

        :returns: :class:`MLDSA87PrivateKey`

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-DSA-87 is
            not supported by the backend ``cryptography`` is using.

    .. classmethod:: from_seed_bytes(data)

        Load an ML-DSA-87 private key from seed bytes.

        :param data: 32 byte seed.
        :type data: :term:`bytes-like`

        :returns: :class:`MLDSA87PrivateKey`

        :raises ValueError: If the seed is not 32 bytes.

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-DSA-87 is
            not supported by the backend ``cryptography`` is using.

        .. doctest::
            :skipif: not _backend.mldsa_supported()

            >>> from cryptography.hazmat.primitives.asymmetric import mldsa
            >>> private_key = mldsa.MLDSA87PrivateKey.generate()
            >>> seed = private_key.private_bytes_raw()
            >>> same_key = mldsa.MLDSA87PrivateKey.from_seed_bytes(seed)

    .. method:: public_key()

        :returns: :class:`MLDSA87PublicKey`

    .. method:: sign(data, context=None)

        Sign the data using ML-DSA-87. An optional context string can be
        provided.

        :param data: The data to sign.
        :type data: :term:`bytes-like`

        :param context: An optional context string (up to 255 bytes).
        :type context: :term:`bytes-like` or ``None``

        :returns bytes: The signature (4627 bytes).

        :raises ValueError: If the context is longer than 255 bytes.

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

        This method only returns the seed form of the private key (32 bytes).

        :return bytes: Raw key (32-byte seed).

.. class:: MLDSA87PublicKey

    .. versionadded:: 47.0.0

    .. classmethod:: from_public_bytes(data)

        :param bytes data: 2592 byte public key.

        :returns: :class:`MLDSA87PublicKey`

        :raises ValueError: If the public key is not 2592 bytes.

        :raises cryptography.exceptions.UnsupportedAlgorithm: If ML-DSA-87 is
            not supported by the backend ``cryptography`` is using.

        .. doctest::
            :skipif: not _backend.mldsa_supported()

            >>> from cryptography.hazmat.primitives import serialization
            >>> from cryptography.hazmat.primitives.asymmetric import mldsa
            >>> private_key = mldsa.MLDSA87PrivateKey.generate()
            >>> public_key = private_key.public_key()
            >>> public_bytes = public_key.public_bytes(
            ...     encoding=serialization.Encoding.Raw,
            ...     format=serialization.PublicFormat.Raw
            ... )
            >>> loaded_public_key = mldsa.MLDSA87PublicKey.from_public_bytes(public_bytes)

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

        :return bytes: 2592-byte raw public key.

    .. method:: verify(signature, data, context=None)

        Verify a signature using ML-DSA-87. If a context string was used during
        signing, the same context must be provided for verification to succeed.

        :param signature: The signature to verify.
        :type signature: :term:`bytes-like`

        :param data: The data to verify.
        :type data: :term:`bytes-like`

        :param context: An optional context string (up to 255 bytes) that was
            used during signing.
        :type context: :term:`bytes-like` or ``None``

        :returns: None
        :raises cryptography.exceptions.InvalidSignature: Raised when the
            signature cannot be verified.
        :raises ValueError: If the context is longer than 255 bytes.


.. _`FIPS 204`: https://csrc.nist.gov/pubs/fips/204/final
