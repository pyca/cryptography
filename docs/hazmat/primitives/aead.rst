.. hazmat::


Authenticated encryption
========================

.. module:: cryptography.hazmat.primitives.ciphers.aead

Authenticated encryption with additional data allows the user to guarantee
the integrity of both their ciphertext and optional additional data that does
not require encryption.

.. class:: ChaCha20Poly1305(key)

    .. versionadded:: 2.0

    The ChaCha20Poly1305 construction is defined in :rfc:`7539` section 2.8.
    It is a stream cipher combined with a MAC that offers strong integrity
    guarantees.

    :param bytes key: A 32-byte key. This **must** be kept secret.

    .. doctest::

        >>> from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        >>> data = b"a secret message"
        >>> aad = b"authenticated but unencrypted data"
        >>> key = ChaCha20Poly1305.generate_key()
        >>> chacha = ChaCha20Poly1305(key)
        >>> nonce = os.urandom(12)
        >>> ct, tag = chacha.encrypt(nonce, data, aad)
        >>> chacha.decrypt(nonce, tag, ct, aad)
        'a secret message'

    .. classmethod:: generate_key()

        Generates a random ChaCha20Poly1305 key using ``os.urandom``.

        :returns bytes: A 32 byte key.

    .. method:: encrypt(nonce, data, additional_data)

        .. warning::

            Reuse of a ``nonce`` with a given ``key`` compromises the security
            of any message with that ``nonce`` and ``key`` pair.

        :param bytes nonce: A random 12 byte value. **NEVER REUSE A NONCE**
            with a key.
        :param bytes data: The data to encrypt.
        :param bytes additional_data: Additional data that should be
            authenticated with the key, but does not need to be encrypted. Can
            be ``None``.
        :returns: A tuple ``(ciphertext, tag)`` where ``ciphertext`` is the
            encrypted data and ``tag`` is a 16 byte value.

    .. method:: decrypt(nonce, tag, data, additional_data)

        :param bytes data: The data to decrypt.
        :param bytes additional_data: Additional data to authenticate. Can be
            ``None`` if none was passed during encryption.
        :returns bytes: The original plaintext.
        :raises cryptography.exceptions.InvalidTag: If the authentication tag
            doesn't match this exception will be raised. This will occur when
            the ciphertext has been changed, but will also occur when the key,
            nonce, or additional data are wrong.
