.. hazmat::

Message digests (Hashing)
=========================

.. module:: cryptography.hazmat.primitives.hashes

.. class:: Hash(algorithm, backend)

    A cryptographic hash function takes an arbitrary block of data and
    calculates a fixed-size bit string (a digest), such that different data
    results (with a high probability) in different digests.

    This is an implementation of
    :class:`~cryptography.hazmat.primitives.hashes.HashContext` meant to
    be used with
    :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
    implementations to provide an incremental interface to calculating
    various message digests.

    .. doctest::

        >>> from cryptography.hazmat.backends import default_backend
        >>> from cryptography.hazmat.primitives import hashes
        >>> digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        >>> digest.update(b"abc")
        >>> digest.update(b"123")
        >>> digest.finalize()
        'l\xa1=R\xcap\xc8\x83\xe0\xf0\xbb\x10\x1eBZ\x89\xe8bM\xe5\x1d\xb2\xd29%\x93\xafj\x84\x11\x80\x90'

    If the backend doesn't support the requested ``algorithm`` an
    :class:`~cryptography.exceptions.UnsupportedAlgorithm` exception will be
    raised.

    Keep in mind that attacks against cryptographic hashes only get stronger
    with time, and that often algorithms that were once thought to be strong,
    become broken. Because of this it's important to include a plan for
    upgrading the hash algorithm you use over time. For more information, see
    `Lifetimes of cryptographic hash functions`_.

    :param algorithm: A
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
        instance such as those described in
        :ref:`below <cryptographic-hash-algorithms>`.
    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.HashBackend`
        instance.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if the
        provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.HashBackend`

    .. method:: update(data)

        :param bytes data: The bytes to be hashed.
        :raises cryptography.exceptions.AlreadyFinalized: See :meth:`finalize`.
        :raises TypeError: This exception is raised if ``data`` is not ``bytes``.

    .. method:: copy()

        Copy this :class:`Hash` instance, usually so that you may call
        :meth:`finalize` to get an intermediate digest value while we continue
        to call :meth:`update` on the original instance.

        :return: A new instance of :class:`Hash` that can be updated
             and finalized independently of the original instance.
        :raises cryptography.exceptions.AlreadyFinalized: See :meth:`finalize`.

    .. method:: finalize()

        Finalize the current context and return the message digest as bytes.

        After ``finalize`` has been called this object can no longer be used
        and :meth:`update`, :meth:`copy`, and :meth:`finalize` will raise an
        :class:`~cryptography.exceptions.AlreadyFinalized` exception.

        :return bytes: The message digest as bytes.


.. _cryptographic-hash-algorithms:

SHA-2 family
~~~~~~~~~~~~

.. class:: SHA224()

    SHA-224 is a cryptographic hash function from the SHA-2 family and is
    standardized by NIST. It produces a 224-bit message digest.

.. class:: SHA256()

    SHA-256 is a cryptographic hash function from the SHA-2 family and is
    standardized by NIST. It produces a 256-bit message digest.

.. class:: SHA384()

    SHA-384 is a cryptographic hash function from the SHA-2 family and is
    standardized by NIST. It produces a 384-bit message digest.

.. class:: SHA512()

    SHA-512 is a cryptographic hash function from the SHA-2 family and is
    standardized by NIST. It produces a 512-bit message digest.

BLAKE2
~~~~~~

`BLAKE2`_ is a cryptographic hash function specified in :rfc:`7693`. BLAKE2's
design makes it immune to `length-extension attacks`_, an advantage over the
SHA-family of hashes.

.. note::

    While the RFC specifies keying, personalization, and salting features,
    these are not supported at this time due to limitations in OpenSSL 1.1.0.

.. class:: BLAKE2b(digest_size)

    BLAKE2b is optimized for 64-bit platforms and produces an 1 to 64-byte
    message digest.

    :param int digest_size: The desired size of the hash output in bytes. Only
        ``64`` is supported at this time.

    :raises ValueError: If the ``digest_size`` is invalid.

.. class:: BLAKE2s(digest_size)

    BLAKE2s is optimized for 8 to 32-bit platforms and produces a
    1 to 32-byte message digest.

    :param int digest_size: The desired size of the hash output in bytes. Only
        ``32`` is supported at this time.

    :raises ValueError: If the ``digest_size`` is invalid.

SHA-1
~~~~~

.. warning::

    SHA-1 is a deprecated hash algorithm that has practical known collision
    attacks. You are strongly discouraged from using it. Existing applications
    should strongly consider moving away.

.. class:: SHA1()

    SHA-1 is a cryptographic hash function standardized by NIST. It produces an
    160-bit message digest. Cryptanalysis of SHA-1 has demonstrated that it is
    vulnerable to practical collision attacks, and collisions have been
    demonstrated.

MD5
~~~

.. warning::

    MD5 is a deprecated hash algorithm that has practical known collision
    attacks. You are strongly discouraged from using it. Existing applications
    should strongly consider moving away.

.. class:: MD5()

    MD5 is a deprecated cryptographic hash function. It produces a 128-bit
    message digest and has practical known collision attacks.


Interfaces
~~~~~~~~~~

.. class:: HashAlgorithm

    .. attribute:: name

        :type: str

        The standard name for the hash algorithm, for example: ``"sha256"`` or
        ``"whirlpool"``.

    .. attribute:: digest_size

        :type: int

        The size of the resulting digest in bytes.

    .. attribute:: block_size

        :type: int

        The internal block size of the hash algorithm in bytes.


.. class:: HashContext

    .. attribute:: algorithm

        A :class:`HashAlgorithm` that will be used by this context.

    .. method:: update(data)

        :param bytes data: The data you want to hash.

    .. method:: finalize()

        :return: The final digest as bytes.

    .. method:: copy()

        :return: A :class:`HashContext` that is a copy of the current context.


.. _`Lifetimes of cryptographic hash functions`: https://valerieaurora.org/hash.html
.. _`BLAKE2`: https://blake2.net
.. _`length-extension attacks`: https://en.wikipedia.org/wiki/Length_extension_attack
