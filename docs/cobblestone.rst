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

    .. method:: decrypt_range(source, offset, length)

        .. versionadded:: 50.0.0

        Decrypts and returns the ``length`` plaintext bytes beginning at
        ``offset``, reading only the ciphertext needed to cover that
        range rather than the whole message. See :ref:`random access
        <cobblestone-random-access>` below.

        The requested range is silently widened to whole 16 KiB chunk
        boundaries so that every chunk it touches can be authenticated
        by its tag; the requested sub-range is then sliced out of the
        authenticated plaintext. Unauthenticated bytes are never
        returned.

        This method is an alternative to :meth:`update`/:meth:`finalize`:
        a single instance may be used for streaming **or** random-access
        decryption, not both. It does not consume the instance and may be
        called repeatedly for different ranges.

        .. warning::

            A range read authenticates the bytes it returns, but **not
            the message as a whole**. It cannot detect that chunks beyond
            the requested range were removed, so it provides no
            protection against truncation of the overall message. The
            total plaintext length must come from a trusted source; do
            not infer it from the (possibly truncated) size of
            ``source``. Whole-message truncation protection is only
            provided by streaming through :meth:`finalize`.

        :param source: The ciphertext, as either a :term:`bytes-like`
            object (for example an :class:`mmap.mmap` of a file, which
            avoids reading it all into memory) or a binary file-like
            object. A file-like ``source`` only needs to implement
            ``seek(offset)`` and ``read(size)``; nothing else is used, so
            an object that fetches byte ranges from remote storage on
            demand works as well as an open file.
        :param int offset: The plaintext offset to start at.
        :param int length: The number of plaintext bytes to return.
        :return bytes: The authenticated plaintext for the requested
            range.
        :raises cryptography.exceptions.InvalidTag: If a covering chunk
            was encrypted with a different key or context, has been
            modified, or is missing because ``source`` is truncated
            within the requested range (which includes reading past the
            end of the message).
        :raises ValueError: If ``length`` is negative, ``offset`` is
            negative, the range exceeds the maximum message length, or
            the instance has already been used for streaming
            decryption.

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
    32-byte key. It provides the same :meth:`~Cobblestone128Decryptor.decrypt_range`
    method for random access.

.. _cobblestone-random-access:

Random-access decryption
-------------------------

Because each 16 KiB chunk is encrypted independently, a range of a large
message can be decrypted without processing everything before it, using
:meth:`~Cobblestone128Decryptor.decrypt_range`. The decryptor reads only
the chunks that cover the requested range, authenticates each of them,
and returns just the requested bytes.

Any object supporting the buffer protocol, or any binary file-like
object, can be the source. To read a range out of a large file without
loading it into memory, pass an :class:`mmap.mmap`:

.. doctest::

    >>> import io
    >>> from cryptography.cobblestone import (
    ...     Cobblestone128Decryptor, Cobblestone128Encryptor
    ... )
    >>> key = Cobblestone128Encryptor.generate_key()
    >>> encryptor = Cobblestone128Encryptor(key, context=b"ranged")
    >>> plaintext = b"the quick brown fox" * 10000
    >>> ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    >>> decryptor = Cobblestone128Decryptor(key, context=b"ranged")
    >>> decryptor.decrypt_range(io.BytesIO(ciphertext), 40005, 9)
    b'brown fox'
    >>> _ == plaintext[40005:40014]
    True

For data held remotely, a file-like ``source`` only needs to implement
``seek`` and ``read``, so a small adapter that turns those into ranged
requests (for example an HTTP ``Range`` request or an object-storage
ranged ``GET``) is enough — ``decrypt_range`` issues one contiguous read
for the covering chunks:

.. code-block:: python

    class RangeReader:
        def __init__(self, client, key):
            self._client = client
            self._key = key
            self._pos = 0

        def seek(self, offset, whence=0):
            assert whence == 0
            self._pos = offset
            return self._pos

        def read(self, size):
            end = self._pos + size - 1
            data = self._client.get_range(self._key, self._pos, end)
            self._pos += len(data)
            return data

    decryptor = Cobblestone128Decryptor(key, context=b"ranged")
    chunk = decryptor.decrypt_range(RangeReader(client, "blob"), 40000, 4096)

.. warning::

    A range read authenticates the bytes it returns, but not the
    message as a whole: it cannot detect that chunks beyond the
    requested range were removed. Obtain the total plaintext length from
    a trusted source rather than inferring it from the ciphertext, and
    rely on streaming through
    :meth:`~Cobblestone128Decryptor.finalize` when you need to verify
    that a whole message is intact and has not been truncated.

.. _`C2SP chunked-encryption specification`: https://c2sp.org/chunked-encryption
