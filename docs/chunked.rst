Chunked encryption
==================

.. currentmodule:: cryptography.chunked

.. testsetup::

    import io

Chunked encryption splits a message into fixed-size chunks that are each
encrypted with an AEAD (authenticated encryption with associated data)
construction, so that arbitrarily large messages can be
encrypted and decrypted as a stream without holding the whole message — or any
unauthenticated plaintext — in memory. It implements the
`chunked encryption`_ specification from the `C2SP`_ project, using its
RECOMMENDED instantiation of SHA-256 and AES-128-GCM.

Unlike :doc:`/fernet`, which is designed for messages that fit comfortably in
memory, chunked encryption is suitable for encrypting large files or streams.

.. class:: ChunkedEncryption(key)

    .. versionadded:: 50.0

    This class provides streaming encryption and decryption.

    .. doctest::

        >>> from cryptography.chunked import ChunkedEncryption
        >>> key = ChunkedEncryption.generate_key()
        >>> scheme = ChunkedEncryption(key)
        >>> encryptor = scheme.encryptor()
        >>> ciphertext = encryptor.update(b"a secret message")
        >>> ciphertext += encryptor.finalize()
        >>> decryptor = scheme.decryptor()
        >>> decryptor.update(ciphertext) + decryptor.finalize()
        b'a secret message'

    :param key: A 16-byte key. This **must** be kept secret and **must** be
        generated with a cryptographically secure source of randomness, such as
        :func:`os.urandom` or :meth:`generate_key`. Anyone with this key is able
        to create and read messages.
    :type key: :term:`bytes-like`

    :raises ValueError: If ``key`` is not 16 bytes long.

    .. classmethod:: generate_key()

        Generates a fresh key suitable for use with :class:`ChunkedEncryption`.
        Keep this some place safe! If you lose it you'll no longer be able to
        decrypt messages; if anyone else gains access to it, they'll be able to
        decrypt all of your messages, and they'll also be able to forge
        arbitrary messages that will be authenticated and decrypted.

        :returns bytes: A 16-byte key.

    .. method:: encryptor(context=b"")

        :param context: Optional additional data that is bound to the message.
            The same ``context`` must be supplied to :meth:`decryptor` in order
            to decrypt. It is **not** included in the ciphertext and is not kept
            secret; it might, for example, identify the file or protocol the
            message belongs to.
        :type context: bytes

        :returns: An encryption object that exposes ``update`` and ``finalize``
            methods.

        :raises TypeError: If ``context`` is not ``bytes``.

        The returned object encrypts a message that is supplied incrementally:

        .. method:: update(data)
            :noindex:

            :param data: A portion of the message to encrypt.
            :type data: :term:`bytes-like`
            :returns bytes: Zero or more bytes of ciphertext. The amount
                returned does not correspond directly to the amount of ``data``
                passed in, since output is produced one chunk at a time.
            :raises cryptography.exceptions.AlreadyFinalized: If
                ``finalize()`` has already been called.

        .. method:: finalize()
            :noindex:

            Finalizes the message and returns any remaining ciphertext. After
            this is called the encryption object can no longer be used.

            :returns bytes: The remaining ciphertext.
            :raises cryptography.exceptions.AlreadyFinalized: If
                ``finalize()`` has already been called.

    .. method:: decryptor(context=b"")

        :param context: The same ``context`` that was passed to
            :meth:`encryptor` when the message was created.
        :type context: bytes

        :returns: A decryption object that exposes ``update`` and ``finalize``
            methods.

        :raises TypeError: If ``context`` is not ``bytes``.

        The returned object decrypts a ciphertext that is supplied
        incrementally:

        .. method:: update(data)
            :noindex:

            :param data: A portion of the ciphertext to decrypt.
            :type data: :term:`bytes-like`
            :returns bytes: Zero or more bytes of plaintext. Decrypted plaintext
                is only returned once the chunk it belongs to has been fully
                received and authenticated.
            :raises cryptography.chunked.InvalidChunk: If the ciphertext has
                been tampered with, was encrypted with a different key or
                ``context``, or has been truncated.
            :raises cryptography.exceptions.AlreadyFinalized: If
                ``finalize()`` has already been called.

        .. method:: finalize()
            :noindex:

            Finalizes decryption. This verifies that the ciphertext was not
            truncated; you **must** call it and check that it does not raise
            before trusting the decrypted plaintext.

            :returns bytes: Any remaining plaintext.
            :raises cryptography.chunked.InvalidChunk: If the message was
                truncated or is otherwise invalid.
            :raises cryptography.exceptions.AlreadyFinalized: If
                ``finalize()`` has already been called.

The following example encrypts and decrypts a file-like object in 16 KiB
chunks without ever loading it entirely into memory:

.. doctest::

    >>> from cryptography.chunked import ChunkedEncryption
    >>> scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
    >>> plaintext = io.BytesIO(b"a large message" * 5000)
    >>> ciphertext = io.BytesIO()
    >>> encryptor = scheme.encryptor()
    >>> while chunk := plaintext.read(16 * 1024):
    ...     _ = ciphertext.write(encryptor.update(chunk))
    >>> _ = ciphertext.write(encryptor.finalize())
    >>> ciphertext.seek(0)
    0
    >>> recovered = io.BytesIO()
    >>> decryptor = scheme.decryptor()
    >>> while chunk := ciphertext.read(16 * 1024):
    ...     _ = recovered.write(decryptor.update(chunk))
    >>> _ = recovered.write(decryptor.finalize())
    >>> recovered.getvalue() == plaintext.getvalue()
    True


.. class:: InvalidChunk

    .. versionadded:: 50.0

    Raised when decryption fails because a chunk could not be authenticated,
    the wrong key or ``context`` was used, or the message was truncated. See
    :meth:`ChunkedEncryption.decryptor` for more information.


.. _`chunked encryption`: https://github.com/C2SP/C2SP/blob/main/chunked-encryption.md
.. _`C2SP`: https://c2sp.org/
