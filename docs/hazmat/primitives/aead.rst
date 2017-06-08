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

    :param bytes key: A 32-byte key. This **must** be kept secret.

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
        'a secret message'

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

        :param bytes nonce: A 12 byte value. **NEVER REUSE A NONCE** with a
            key.
        :param bytes data: The data to encrypt.
        :param bytes associated_data: Additional data that should be
            authenticated with the key, but does not need to be encrypted. Can
            be ``None``.
        :returns bytes: The ciphertext bytes with the 16 byte tag appended.

    .. method:: decrypt(nonce, data, associated_data)

        Decrypts the ``data`` and authenticates the ``associated_data``. If you
        called encrypt with ``associated_data`` you must pass the same
        ``associated_data`` in decrypt or the integrity check will fail.

        :param bytes nonce: A 12 byte value. **NEVER REUSE A NONCE** with a
            key.
        :param bytes data: The data to decrypt (with tag appended).
        :param bytes associated_data: Additional data to authenticate. Can be
            ``None`` if none was passed during encryption.
        :returns bytes: The original plaintext.
        :raises cryptography.exceptions.InvalidTag: If the authentication tag
            doesn't validate this exception will be raised. This will occur
            when the ciphertext has been changed, but will also occur when the
            key, nonce, or associated data are wrong.
