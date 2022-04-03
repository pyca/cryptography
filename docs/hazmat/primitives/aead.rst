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
            than 2\ :sup:`31` - 1 bytes.

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
            than 2\ :sup:`31` - 1 bytes.

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

.. class:: AESOCB3(key)

    .. versionadded:: 36.0

    The OCB3 construction is defined in :rfc:`7253`. It is an AEAD mode
    that offers strong integrity guarantees and good performance.

    :param key: A 128, 192, or 256-bit key. This **must** be kept secret.
    :type key: :term:`bytes-like`

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the version of
        OpenSSL does not support AES-OCB3.

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives.ciphers.aead import AESOCB3
        >>> data = b"a secret message"
        >>> aad = b"authenticated but unencrypted data"
        >>> key = AESOCB3.generate_key(bit_length=128)
        >>> aesocb = AESOCB3(key)
        >>> nonce = os.urandom(12)
        >>> ct = aesocb.encrypt(nonce, data, aad)
        >>> aesocb.decrypt(nonce, ct, aad)
        b'a secret message'

    .. classmethod:: generate_key(bit_length)

        Securely generates a random AES-OCB3 key.

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

        :param nonce: A 12-15 byte value. **NEVER REUSE A NONCE** with a key.
        :type nonce: :term:`bytes-like`
        :param bytes data: The data to encrypt.
        :param bytes associated_data: Additional data that should be
            authenticated with the key, but is not encrypted. Can be ``None``.
        :returns bytes: The ciphertext bytes with the 16 byte tag appended.
        :raises OverflowError: If ``data`` or ``associated_data`` is larger
            than 2\ :sup:`31` - 1 bytes.

    .. method:: decrypt(nonce, data, associated_data)

        Decrypts the ``data`` and authenticates the ``associated_data``. If you
        called encrypt with ``associated_data`` you must pass the same
        ``associated_data`` in decrypt or the integrity check will fail.

        :param nonce: A 12 byte value. **NEVER REUSE A NONCE** with a key.
        :type nonce: :term:`bytes-like`
        :param bytes data: The data to decrypt (with tag appended).
        :param bytes associated_data: Additional data to authenticate. Can be
            ``None`` if none was passed during encryption.
        :returns bytes: The original plaintext.
        :raises cryptography.exceptions.InvalidTag: If the authentication tag
            doesn't validate this exception will be raised. This will occur
            when the ciphertext has been changed, but will also occur when the
            key, nonce, or associated data are wrong.

.. class:: AESSIV(key)

    .. versionadded:: 37.0

    The SIV (synthetic initialization vector) construction is defined in
    :rfc:`5297`. Depending on how it is used, SIV allows either
    deterministic authenticated encryption or nonce-based,
    misuse-resistant authenticated encryption.

    :param key: A 256, 384, or 512-bit key (double sized from typical AES).
        This **must** be kept secret.
    :type key: :term:`bytes-like`

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the version of
        OpenSSL does not support AES-SIV.

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives.ciphers.aead import AESSIV
        >>> data = b"a secret message"
        >>> nonce = os.urandom(16)
        >>> aad = [b"authenticated but unencrypted data", nonce]
        >>> key = AESSIV.generate_key(bit_length=512)  # AES256 requires 512-bit keys for SIV
        >>> aessiv = AESSIV(key)
        >>> ct = aessiv.encrypt(data, aad)
        >>> aessiv.decrypt(ct, aad)
        b'a secret message'

    .. classmethod:: generate_key(bit_length)

        Securely generates a random AES-SIV key.

        :param bit_length: The bit length of the key to generate. Must be
            256, 384, or 512. AES-SIV splits the key into an encryption and
            MAC key, so these lengths correspond to AES 128, 192, and 256.

        :returns bytes: The generated key.

    .. method:: encrypt(data, associated_data)

        .. note::

            SIV performs nonce-based authenticated encryption when a component of
            the associated data is a nonce. The final associated data in the
            list is used for the nonce.

            Random nonces should have at least 128-bits of entropy. If a nonce is
            reused with SIV authenticity is retained and confidentiality is only
            compromised to the extent that an attacker can determine that the
            same plaintext (and same associated data) was protected with the same
            nonce and key.

            If you do not supply a nonce encryption is deterministic and the same
            (plaintext, key) pair will always produce the same ciphertext.

        Encrypts and authenticates the ``data`` provided as well as
        authenticating the ``associated_data``.  The output of this can be
        passed directly to the ``decrypt`` method.

        :param bytes data: The data to encrypt.
        :param list associated_data: An optional ``list`` of ``bytes``. This
            is additional data that should be authenticated with the key, but
            is not encrypted. Can be ``None``.  In SIV mode the final element
            of this list is treated as a ``nonce``.
        :returns bytes: The ciphertext bytes with the 16 byte tag **prepended**.
        :raises OverflowError: If ``data`` or an ``associated_data`` element
            is larger than 2\ :sup:`31` - 1 bytes.

    .. method:: decrypt(data, associated_data)

        Decrypts the ``data`` and authenticates the ``associated_data``. If you
        called encrypt with ``associated_data`` you must pass the same
        ``associated_data`` in decrypt or the integrity check will fail.

        :param bytes data: The data to decrypt (with tag **prepended**).
        :param list associated_data: An optional ``list`` of ``bytes``. This
            is additional data that should be authenticated with the key, but
            is not encrypted. Can be ``None`` if none was used during
            encryption.
        :returns bytes: The original plaintext.
        :raises cryptography.exceptions.InvalidTag: If the authentication tag
            doesn't validate this exception will be raised. This will occur
            when the ciphertext has been changed, but will also occur when the
            key or associated data are wrong.

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
            than 2\ :sup:`31` - 1 bytes.

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
