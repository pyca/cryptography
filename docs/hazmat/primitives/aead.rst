.. hazmat::


Authenticated encryption
========================

.. module:: cryptography.hazmat.primitives.ciphers.aead

Authenticated encryption with associated data (AEAD) are encryption schemes
which provide both confidentiality and integrity for their ciphertext. They
also support providing integrity for associated data which is not encrypted.

.. class:: ChaCha20Poly1305(key)

    .. versionadded:: 2.0

    The ChaCha20Poly1305 construction is defined in :rfc:`7539` section 2.8.
    It is a stream cipher combined with a MAC that offers strong integrity
    guarantees.

    :param key: A 32-byte key. This **must** be kept secret.
    :type key: :term:`bytes-like`

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the version of
        OpenSSL does not support ChaCha20Poly1305.

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        >>> data = b"a secret message"
        >>> aad = b"authenticated but unencrypted data"
        >>> key = ChaCha20Poly1305.generate_key()
        >>> chacha = ChaCha20Poly1305(key)
        >>> nonce = os.urandom(12)
        >>> ct = chacha.encrypt(nonce, data, aad)
        >>> chacha.decrypt(nonce, ct, aad)
        b'a secret message'

    .. classmethod:: generate_key()

        Securely generates a random ChaCha20Poly1305 key.

        :returns bytes: A 32 byte key.

    .. method:: encrypt(nonce, data, associated_data)

        .. warning::

            Reuse of a ``nonce`` with a given ``key`` compromises the security
            of any message with that ``nonce`` and ``key`` pair.

        Encrypts the ``data`` provided and authenticates the
        ``associated_data``.  The output of this can be passed directly
        to the ``decrypt`` method.

        :param nonce: A 12 byte value. **NEVER REUSE A NONCE** with a key.
        :type nonce: :term:`bytes-like`
        :param bytes data: The data to encrypt.
        :param bytes associated_data: Additional data that should be
            authenticated with the key, but does not need to be encrypted. Can
            be ``None``.
        :returns bytes: The ciphertext bytes with the 16 byte tag appended.
        :raises OverflowError: If ``data`` or ``associated_data`` is larger
            than 2\ :sup:`32` bytes.

    .. method:: decrypt(nonce, data, associated_data)

        Decrypts the ``data`` and authenticates the ``associated_data``. If you
        called encrypt with ``associated_data`` you must pass the same
        ``associated_data`` in decrypt or the integrity check will fail.

        :param nonce: A 12 byte value. **NEVER REUSE A NONCE** with a
            key.
        :type nonce: :term:`bytes-like`
        :param bytes data: The data to decrypt (with tag appended).
        :param bytes associated_data: Additional data to authenticate. Can be
            ``None`` if none was passed during encryption.
        :returns bytes: The original plaintext.
        :raises cryptography.exceptions.InvalidTag: If the authentication tag
            doesn't validate this exception will be raised. This will occur
            when the ciphertext has been changed, but will also occur when the
            key, nonce, or associated data are wrong.

.. class:: AESGCM(key)

    .. versionadded:: 2.0

    The AES-GCM construction is composed of the
    :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES` block
    cipher utilizing Galois Counter Mode (GCM).

    :param key: A 128, 192, or 256-bit key. This **must** be kept secret.
    :type key: :term:`bytes-like`

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        >>> data = b"a secret message"
        >>> aad = b"authenticated but unencrypted data"
        >>> key = AESGCM.generate_key(bit_length=128)
        >>> aesgcm = AESGCM(key)
        >>> nonce = os.urandom(12)
        >>> ct = aesgcm.encrypt(nonce, data, aad)
        >>> aesgcm.decrypt(nonce, ct, aad)
        b'a secret message'

    .. classmethod:: generate_key(bit_length)

        Securely generates a random AES-GCM key.

        :param bit_length: The bit length of the key to generate. Must be
            128, 192, or 256.

        :returns bytes: The generated key.

    .. method:: encrypt(nonce, data, associated_data)

        .. warning::

            Reuse of a ``nonce`` with a given ``key`` compromises the security
            of any message with that ``nonce`` and ``key`` pair.

        Encrypts and authenticates the ``data`` provided as well as
        authenticating the ``associated_data``.  The output of this can be
        passed directly to the ``decrypt`` method.

        :param nonce: NIST `recommends a 96-bit IV length`_ for best
            performance but it can be up to 2\ :sup:`64` - 1 :term:`bits`.
            **NEVER REUSE A NONCE** with a key.
        :type nonce: :term:`bytes-like`
        :param bytes data: The data to encrypt.
        :param bytes associated_data: Additional data that should be
            authenticated with the key, but is not encrypted. Can be ``None``.
        :returns bytes: The ciphertext bytes with the 16 byte tag appended.
        :raises OverflowError: If ``data`` or ``associated_data`` is larger
            than 2\ :sup:`32` bytes.

    .. method:: decrypt(nonce, data, associated_data)

        Decrypts the ``data`` and authenticates the ``associated_data``. If you
        called encrypt with ``associated_data`` you must pass the same
        ``associated_data`` in decrypt or the integrity check will fail.

        :param nonce: NIST `recommends a 96-bit IV length`_ for best
            performance but it can be up to 2\ :sup:`64` - 1 :term:`bits`.
            **NEVER REUSE A NONCE** with a key.
        :type nonce: :term:`bytes-like`
        :param bytes data: The data to decrypt (with tag appended).
        :param bytes associated_data: Additional data to authenticate. Can be
            ``None`` if none was passed during encryption.
        :returns bytes: The original plaintext.
        :raises cryptography.exceptions.InvalidTag: If the authentication tag
            doesn't validate this exception will be raised. This will occur
            when the ciphertext has been changed, but will also occur when the
            key, nonce, or associated data are wrong.

.. class:: AESCCM(key, tag_length=16)

    .. versionadded:: 2.0

    .. note:

        AES-CCM is provided largely for compatibility with existing protocols.
        Due to its construction it is not as computationally efficient as
        other AEAD ciphers.

    The AES-CCM construction is composed of the
    :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES` block
    cipher utilizing Counter with CBC-MAC (CCM) (specified in :rfc:`3610`).

    :param key: A 128, 192, or 256-bit key. This **must** be kept secret.
    :type key: :term:`bytes-like`
    :param int tag_length: The length of the authentication tag. This
        defaults to 16 bytes and it is **strongly** recommended that you
        do not make it shorter unless absolutely necessary. Valid tag
        lengths are 4, 6, 8, 10, 12, 14, and 16.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the version of
        OpenSSL does not support AES-CCM.

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives.ciphers.aead import AESCCM
        >>> data = b"a secret message"
        >>> aad = b"authenticated but unencrypted data"
        >>> key = AESCCM.generate_key(bit_length=128)
        >>> aesccm = AESCCM(key)
        >>> nonce = os.urandom(13)
        >>> ct = aesccm.encrypt(nonce, data, aad)
        >>> aesccm.decrypt(nonce, ct, aad)
        b'a secret message'

    .. classmethod:: generate_key(bit_length)

        Securely generates a random AES-CCM key.

        :param bit_length: The bit length of the key to generate. Must be
            128, 192, or 256.

        :returns bytes: The generated key.

    .. method:: encrypt(nonce, data, associated_data)

        .. warning::

            Reuse of a ``nonce`` with a given ``key`` compromises the security
            of any message with that ``nonce`` and ``key`` pair.

        Encrypts and authenticates the ``data`` provided as well as
        authenticating the ``associated_data``.  The output of this can be
        passed directly to the ``decrypt`` method.

        :param nonce: A value of between 7 and 13 bytes. The maximum
            length is determined by the length of the ciphertext you are
            encrypting and must satisfy the condition:
            ``len(data) < 2 ** (8 * (15 - len(nonce)))``
            **NEVER REUSE A NONCE** with a key.
        :type nonce: :term:`bytes-like`
        :param bytes data: The data to encrypt.
        :param bytes associated_data: Additional data that should be
            authenticated with the key, but is not encrypted. Can be ``None``.
        :returns bytes: The ciphertext bytes with the tag appended.
        :raises OverflowError: If ``data`` or ``associated_data`` is larger
            than 2\ :sup:`32` bytes.

    .. method:: decrypt(nonce, data, associated_data)

        Decrypts the ``data`` and authenticates the ``associated_data``. If you
        called encrypt with ``associated_data`` you must pass the same
        ``associated_data`` in decrypt or the integrity check will fail.

        :param nonce: A value of between 7 and 13 bytes. This
            is the same value used when you originally called encrypt.
            **NEVER REUSE A NONCE** with a key.
        :type nonce: :term:`bytes-like`
        :param bytes data: The data to decrypt (with tag appended).
        :param bytes associated_data: Additional data to authenticate. Can be
            ``None`` if none was passed during encryption.
        :returns bytes: The original plaintext.
        :raises cryptography.exceptions.InvalidTag: If the authentication tag
            doesn't validate this exception will be raised. This will occur
            when the ciphertext has been changed, but will also occur when the
            key, nonce, or associated data are wrong.

.. _`recommends a 96-bit IV length`: https://csrc.nist.gov/publications/detail/sp/800-38d/final
