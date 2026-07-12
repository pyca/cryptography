Chunked encryption (streaming symmetric encryption)
====================================================

.. currentmodule:: cryptography.chunked_encryption

Chunked encryption provides authenticated symmetric encryption of large
messages — up to 4 PiB — as a stream, without ever holding the whole
message in memory. It is an implementation of the `C2SP
chunked-encryption specification`_, providing its two named
instantiations: **Cobblestone-128** (SHA-512 and AES-128-GCM, the
recommended choice) and **Cobblestone-256** (SHA-512 and AES-256-GCM,
for environments that mandate 256-bit keys).

A message is encrypted in 16 KiB chunks, each of which is individually
authenticated, so decryption can also be performed as a stream:
decrypted data is returned incrementally, and only authenticated
plaintext is ever returned. Reordering, truncating, or extending the
ciphertext is detected. The scheme is also key committing: a ciphertext
can only be decrypted with the key it was encrypted with.

.. doctest::

    >>> from cryptography.chunked_encryption import (
    ...     Cobblestone128Decryptor, Cobblestone128Encryptor
    ... )
    >>> key = Cobblestone128Encryptor.generate_key()
    >>> encryptor = Cobblestone128Encryptor(
    ...     key, context=b"example-app file encryption"
    ... )
    >>> ciphertext = encryptor.update(b"a secret message")
    >>> ciphertext += encryptor.finalize()
    >>> decryptor = Cobblestone128Decryptor(
    ...     key, context=b"example-app file encryption"
    ... )
    >>> decryptor.update(ciphertext) + decryptor.finalize()
    b'a secret message'

.. class:: Cobblestone128Encryptor(key, context)

    .. versionadded:: 50.0.0

    Encrypts a single message under ``key`` with Cobblestone-128. Each
    instance must be used for exactly one message: call :meth:`update`
    (or :meth:`update_into`) any number of times, then call
    :meth:`finalize` exactly once. The concatenation of the returned
    bytes is the ciphertext.

    :param key: A 16-byte key. This **must** be kept secret, and
        **must** be uniformly random (e.g. the output of
        :meth:`generate_key`, :func:`os.urandom`, or a key derivation
        function — never a password). A single key may be used to
        encrypt a practically unlimited number of messages.
    :type key: :term:`bytes-like`
    :param context: Application-provided context, bound to the
        ciphertext. Decryption fails unless the same value is passed to
        :class:`Cobblestone128Decryptor`. It is not secret, may be
        empty, and is not part of the ciphertext, so it must be
        available to the decrypting party independently. It can be used
        for domain separation, e.g. ``b"myapp v2 backup encryption"``.
    :type context: :term:`bytes-like`
    :raises ValueError: If ``key`` is not 16 bytes.

    .. staticmethod:: generate_key()

        Generates a fresh 16-byte key.

        :return bytes: A new key.

    .. method:: update(data)

        Encrypts ``data``. Data is internally buffered into 16 KiB
        chunks, so between 0 and ``len(data) + 16 KiB`` bytes of
        ciphertext are returned.

        :param data: The data to encrypt.
        :type data: :term:`bytes-like`
        :return bytes: The next portion of the ciphertext.

    .. method:: update_into(data, buf)

        Encrypts ``data``, writing the resulting ciphertext into
        ``buf``, and returns the number of bytes written. This avoids
        allocating a new buffer for each call.

        :param data: The data to encrypt.
        :type data: :term:`bytes-like`
        :param buf: A writable buffer to write the ciphertext into. A
            buffer of ``len(data) + len(data) // 1024 + 16456`` bytes
            is always large enough; the exact number of bytes required
            for a given call is included in the :class:`ValueError`
            raised if the buffer is too small.
        :type buf: :term:`bytes-like`
        :return int: The number of bytes written to ``buf``.
        :raises ValueError: If ``buf`` is too small.

    .. method:: finalize()

        Encrypts the final chunk and returns the last portion of the
        ciphertext. This must always be called, even if ``update``
        returned all but the last few bytes of ciphertext, and the
        instance cannot be used afterwards.

        :return bytes: The remainder of the ciphertext.
        :raises cryptography.exceptions.AlreadyFinalized: If
            ``finalize`` has already been called.

.. class:: Cobblestone128Decryptor(key, context)

    .. versionadded:: 50.0.0

    Decrypts a single message encrypted by
    :class:`Cobblestone128Encryptor` with the same ``key`` and
    ``context``. Call :meth:`update` (or :meth:`update_into`) with the
    ciphertext any number of times, then call :meth:`finalize` exactly
    once. The concatenation of the returned bytes is the plaintext.

    Any returned plaintext is authenticated, but until
    :meth:`finalize` returns successfully the message could still turn
    out to be truncated: an application acting on streamed plaintext
    before that point must be prepared to discard its work if a later
    call raises :class:`~cryptography.exceptions.InvalidTag`.

    Once any method raises
    :class:`~cryptography.exceptions.InvalidTag`, the instance is
    permanently unusable and all further calls raise
    :class:`~cryptography.exceptions.AlreadyFinalized`.

    :param key: The 16-byte key the message was encrypted with.
    :type key: :term:`bytes-like`
    :param context: The context value the message was encrypted with.
    :type context: :term:`bytes-like`
    :raises ValueError: If ``key`` is not 16 bytes.

    .. staticmethod:: generate_key()

        Generates a fresh 16-byte key.

        :return bytes: A new key.

    .. method:: update(data)

        Processes ``data``, which need not be aligned to any boundary,
        and returns the plaintext of all complete chunks that have been
        authenticated so far.

        :param data: The next portion of the ciphertext.
        :type data: :term:`bytes-like`
        :return bytes: The next portion of the plaintext.
        :raises cryptography.exceptions.InvalidTag: If the ciphertext
            was encrypted with a different key or context, or has been
            modified.

    .. method:: update_into(data, buf)

        Like ``update``, but writes the plaintext into ``buf`` and
        returns the number of bytes written.

        :param data: The next portion of the ciphertext.
        :type data: :term:`bytes-like`
        :param buf: A writable buffer to write the plaintext into. A
            buffer of ``len(data) + 16400`` bytes is always large
            enough; the exact number of bytes required for a given call
            is included in the :class:`ValueError` raised if the buffer
            is too small.
        :type buf: :term:`bytes-like`
        :return int: The number of bytes written to ``buf``.
        :raises ValueError: If ``buf`` is too small.
        :raises cryptography.exceptions.InvalidTag: If the ciphertext
            was encrypted with a different key or context, or has been
            modified. Note that in this case unauthenticated data may
            have been written to ``buf`` and must not be used.

    .. method:: finalize()

        Decrypts and authenticates the final chunk, verifying that the
        entire message has been processed, and returns the final
        portion of the plaintext. This must always be called: a
        successful return is what guarantees the complete message was
        authentic and not truncated.

        :return bytes: The remainder of the plaintext.
        :raises cryptography.exceptions.InvalidTag: If the ciphertext
            was truncated or otherwise modified.
        :raises cryptography.exceptions.AlreadyFinalized: If
            ``finalize`` has already been called.

.. class:: Cobblestone256Encryptor(key, context)

    .. versionadded:: 50.0.0

    Exactly like :class:`Cobblestone128Encryptor`, but implements
    Cobblestone-256: the ``key`` is 32 bytes and messages are encrypted
    with AES-256-GCM. Use this when a 256-bit key is mandated;
    otherwise Cobblestone-128 is recommended.

.. class:: Cobblestone256Decryptor(key, context)

    .. versionadded:: 50.0.0

    Exactly like :class:`Cobblestone128Decryptor`, but decrypts
    messages produced by :class:`Cobblestone256Encryptor` with a
    32-byte key.

Implementation
--------------

This module implements `version 1 of the C2SP chunked-encryption
specification`_, and is interoperable with other implementations of
its Cobblestone-128 and Cobblestone-256 instantiations.

For each message, a fresh AEAD key, base nonce, and key commitment are
derived with HKDF-Expand-SHA-512 from the input key, a random 24-byte
salt, and the context. The message is split into 16 KiB chunks (the
final chunk is always shorter, and may be empty), and each chunk is
encrypted with the AEAD, with a nonce derived from the base nonce and
the chunk counter. The ciphertext is the salt, followed by the 32-byte
commitment, followed by the encrypted chunks.

.. _`C2SP chunked-encryption specification`: https://c2sp.org/chunked-encryption
.. _`version 1 of the C2SP chunked-encryption specification`: https://c2sp.org/chunked-encryption
