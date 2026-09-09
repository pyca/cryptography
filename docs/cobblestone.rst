Cobblestone (streaming symmetric encryption)
=============================================

.. currentmodule:: cryptography.cobblestone

Cobblestone provides authenticated symmetric encryption of large
messages — up to 4 PiB — as a stream, without ever holding the whole
message in memory. It is an implementation of the `C2SP
chunked-encryption specification`_'s two named instantiations:
**Cobblestone-128** (SHA-512 and AES-128-GCM, the recommended choice)
and **Cobblestone-256** (SHA-512 and AES-256-GCM, for environments
that mandate 256-bit keys).

.. doctest::

    >>> from cryptography.cobblestone import (
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
        :meth:`generate_key` — never a password). A single key may be
        used to encrypt a practically unlimited number of messages.
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
            is always large enough.
        :type buf: :term:`bytes-like`
        :return int: The number of bytes written to ``buf``.
        :raises ValueError: If ``buf`` is too small.

    .. method:: finalize()

        Encrypts the final chunk and returns the last portion of the
        ciphertext. This must always be called, and the instance cannot
        be used afterwards.

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
            enough.
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

.. class:: Cobblestone128RangeDecryptor(key, context)

    .. versionadded:: 50.0.0

    Decrypts arbitrary ranges of a message encrypted by
    :class:`Cobblestone128Encryptor`, reading only the ciphertext that
    covers each requested range rather than the whole message. See
    :ref:`random access <cobblestone-random-access>` below.

    This is a separate class from :class:`Cobblestone128Decryptor`:
    random access and streaming are distinct modes and cannot be
    interleaved on one object. Unlike the streaming decryptor, an
    instance is not consumed and may be used for any number of ranges.

    :param key: The 16-byte key the message was encrypted with.
    :type key: :term:`bytes-like`
    :param context: The context value the message was encrypted with.
    :type context: :term:`bytes-like`
    :raises ValueError: If ``key`` is not 16 bytes.

    .. method:: decrypt_range(reader, offset, length)

        Decrypts and returns the ``length`` plaintext bytes beginning at
        ``offset``.

        The requested range is silently widened to whole 16 KiB chunk
        boundaries so that every chunk it touches can be authenticated
        by its tag; the requested sub-range is then sliced out of the
        authenticated plaintext. Unauthenticated bytes are never
        returned.

        .. warning::

            A range read authenticates the bytes it returns, but **not
            the message as a whole**. It cannot detect that chunks beyond
            the requested range were removed, so it provides no
            protection against truncation of the overall message. The
            total plaintext length must come from a trusted source; do
            not infer it from the size of the ciphertext. Whole-message
            truncation protection is only provided by streaming through
            :meth:`Cobblestone128Decryptor.finalize`.

        :param reader: The ciphertext, as a :class:`RangeReader` —
            typically a :class:`BufferReader` or :class:`FileReader`.
        :param int offset: The plaintext offset to start at.
        :param int length: The number of plaintext bytes to return.
        :return bytes: The authenticated plaintext for the requested
            range.
        :raises cryptography.exceptions.InvalidTag: If a covering chunk
            was encrypted with a different key or context, has been
            modified, or is missing because the ciphertext is truncated
            within the requested range (which includes reading past the
            end of the message).
        :raises ValueError: If ``offset`` or ``length`` is negative, or
            the range exceeds the maximum message length.

.. class:: Cobblestone256RangeDecryptor(key, context)

    .. versionadded:: 50.0.0

    Exactly like :class:`Cobblestone128RangeDecryptor`, but decrypts
    ranges of messages produced by :class:`Cobblestone256Encryptor` with
    a 32-byte key.

.. _cobblestone-random-access:

Random-access decryption
-------------------------

Because each 16 KiB chunk is encrypted independently, a range of a large
message can be decrypted without processing everything before it. A
:class:`Cobblestone128RangeDecryptor` reads only the chunks covering the
requested range, authenticates each of them, and returns just the bytes
asked for.

Ciphertext is read through a :class:`RangeReader`. Wrap whatever holds
the ciphertext in the matching reader and pass it to
:meth:`~Cobblestone128RangeDecryptor.decrypt_range`:

.. doctest::

    >>> from cryptography.cobblestone import (
    ...     BufferReader, Cobblestone128Encryptor,
    ...     Cobblestone128RangeDecryptor
    ... )
    >>> key = Cobblestone128Encryptor.generate_key()
    >>> encryptor = Cobblestone128Encryptor(key, context=b"ranged")
    >>> plaintext = b"the quick brown fox" * 10000
    >>> ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    >>> decryptor = Cobblestone128RangeDecryptor(key, context=b"ranged")
    >>> decryptor.decrypt_range(BufferReader(ciphertext), 40005, 9)
    b'brown fox'
    >>> _ == plaintext[40005:40014]
    True

.. class:: RangeReader

    .. versionadded:: 50.0.0

    The interface a range decryptor reads ciphertext through. This is a
    :class:`typing.Protocol`: implement it to read from a source this
    module does not provide a reader for, such as an object store.

    .. method:: read_at(offset, length)

        Returns up to ``length`` bytes of ciphertext starting at
        ``offset``.

        Reads are *positional*: this method must not depend on, or
        disturb, any cursor, so that concurrent calls on one reader
        cannot interfere with each other.

        Returning fewer than ``length`` bytes signals the end of the
        ciphertext, so a short read must not be used for any other
        reason. The decryptor will ask again for whatever remains.

        :param int offset: The ciphertext offset to read from.
        :param int length: The maximum number of bytes to return.
        :return: The bytes read.
        :rtype: :term:`bytes-like`

.. class:: BufferReader(data)

    .. versionadded:: 50.0.0

    A :class:`RangeReader` over an in-memory buffer.

    :param data: The ciphertext. This may be any :term:`bytes-like`
        object, including an :class:`mmap.mmap` of a file, which allows
        reading ranges out of a large file without loading it into
        memory.

.. class:: FileReader(fileobj)

    .. versionadded:: 50.0.0

    A :class:`RangeReader` over an open binary file.

    Where the platform provides ``pread`` (via :func:`os.pread`) the
    file's cursor is neither used nor modified, so one reader can serve
    concurrent range requests; elsewhere reads are serialized around a
    seek.

    :param fileobj: A file object opened in binary mode, which must have
        a file descriptor (:meth:`~io.IOBase.fileno`).

Reading from remote storage
~~~~~~~~~~~~~~~~~~~~~~~~~~~

For ciphertext held remotely, implement :class:`RangeReader` in terms of
whatever ranged read the service offers — an HTTP ``Range`` request, or
an object-storage ranged ``GET``. Because ``read_at`` takes the offset as
an argument, no cursor is kept and the reader is safe to share:

.. code-block:: python

    class S3Reader:
        def __init__(self, client, bucket, key):
            self._client = client
            self._bucket = bucket
            self._key = key

        def read_at(self, offset, length):
            if length == 0:
                return b""
            end = offset + length - 1
            response = self._client.get_object(
                Bucket=self._bucket,
                Key=self._key,
                Range=f"bytes={offset}-{end}",
            )
            return response["Body"].read()

    decryptor = Cobblestone128RangeDecryptor(key, context=b"ranged")
    reader = S3Reader(client, "my-bucket", "backup.bin")
    data = decryptor.decrypt_range(reader, 40000, 4096)

Each call makes two reads: one for the 56-byte header, which binds the
plaintext to this particular message, and one contiguous read covering
every chunk the range touches.

.. warning::

    A range read authenticates the bytes it returns, but not the
    message as a whole: it cannot detect that chunks beyond the
    requested range were removed. Obtain the total plaintext length from
    a trusted source rather than inferring it from the ciphertext, and
    rely on streaming through
    :meth:`Cobblestone128Decryptor.finalize` when you need to verify
    that a whole message is intact and has not been truncated.

.. _`C2SP chunked-encryption specification`: https://c2sp.org/chunked-encryption
