.. hazmat::

Message digests (Hashing)
=========================

.. module:: cryptography.hazmat.primitives.hashes

.. class:: Hash(algorithm)

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

        >>> from cryptography.hazmat.primitives import hashes
        >>> digest = hashes.Hash(hashes.SHA256())
        >>> digest.update(b"abc")
        >>> digest.update(b"123")
        >>> digest.finalize()
        b'l\xa1=R\xcap\xc8\x83\xe0\xf0\xbb\x10\x1eBZ\x89\xe8bM\xe5\x1d\xb2\xd29%\x93\xafj\x84\x11\x80\x90'

    Keep in mind that attacks against cryptographic hashes only get stronger
    with time, and that often algorithms that were once thought to be strong,
    become broken. Because of this it's important to include a plan for
    upgrading the hash algorithm you use over time. For more information, see
    `Lifetimes of cryptographic hash functions`_.

    :param algorithm: A
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
        instance such as those described in
        :ref:`below <cryptographic-hash-algorithms>`.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if the
        provided ``algorithm`` is unsupported.

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

.. class:: SHA512_224()

    .. versionadded:: 2.5

    SHA-512/224 is a cryptographic hash function from the SHA-2 family and is
    standardized by NIST. It produces a 224-bit message digest.

.. class:: SHA512_256()

    .. versionadded:: 2.5

    SHA-512/256 is a cryptographic hash function from the SHA-2 family and is
    standardized by NIST. It produces a 256-bit message digest.

BLAKE2
~~~~~~

`BLAKE2`_ is a cryptographic hash function specified in :rfc:`7693`. BLAKE2's
design makes it immune to `length-extension attacks`_, an advantage over the
SHA-family of hashes.

.. note::

    While the RFC specifies keying, personalization, and salting features,
    these are not supported at this time due to limitations in OpenSSL.

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

SHA-3 family
~~~~~~~~~~~~

SHA-3 is the most recent NIST secure hash algorithm standard. Despite the
larger number SHA-3 is not considered to be better than SHA-2. Instead, it uses
a significantly different internal structure so that **if** an attack appears
against SHA-2 it is unlikely to apply to SHA-3. SHA-3 is significantly slower
than SHA-2 so at this time most users should choose SHA-2.

.. class:: SHA3_224()

    .. versionadded:: 2.5

    SHA3/224 is a cryptographic hash function from the SHA-3 family and is
    standardized by NIST. It produces a 224-bit message digest.

.. class:: SHA3_256()

    .. versionadded:: 2.5

    SHA3/256 is a cryptographic hash function from the SHA-3 family and is
    standardized by NIST. It produces a 256-bit message digest.

.. class:: SHA3_384()

    .. versionadded:: 2.5

    SHA3/384 is a cryptographic hash function from the SHA-3 family and is
    standardized by NIST. It produces a 384-bit message digest.

.. class:: SHA3_512()

    .. versionadded:: 2.5

    SHA3/512 is a cryptographic hash function from the SHA-3 family and is
    standardized by NIST. It produces a 512-bit message digest.

.. class:: SHAKE128(digest_size)

    .. versionadded:: 2.5

    SHAKE128 is an extendable output function (XOF) based on the same core
    permutations as SHA3. It allows the caller to obtain an arbitrarily long
    digest length. Longer lengths, however, do not increase security or
    collision resistance and lengths shorter than 128 bit (16 bytes) will
    decrease it.

    :param int digest_size: The length of output desired. Must be greater than
        zero.

    :raises ValueError: If the ``digest_size`` is invalid.

.. class:: SHAKE256(digest_size)

    .. versionadded:: 2.5

    SHAKE256 is an extendable output function (XOF) based on the same core
    permutations as SHA3. It allows the caller to obtain an arbitrarily long
    digest length. Longer lengths, however, do not increase security or
    collision resistance and lengths shorter than 256 bit (32 bytes) will
    decrease it.

    :param int digest_size: The length of output desired. Must be greater than
        zero.

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


SM3
~~~

.. class:: SM3()

    .. versionadded:: 35.0.0

    SM3 is a cryptographic hash function standardized by the Chinese National
    Cryptography Administration in `GM/T 0004-2012`_. It produces 256-bit
    message digests. (An English description is available at
    `draft-sca-cfrg-sm3`_.) This hash should be used for compatibility
    purposes where required and is not otherwise recommended for use.


Interfaces
~~~~~~~~~~

.. class:: HashAlgorithm

    .. attribute:: name

        :type: str

        The standard name for the hash algorithm, for example: ``"sha256"`` or
        ``"blake2b"``.

    .. attribute:: digest_size

        :type: int

        The size of the resulting digest in bytes.


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
.. _`GM/T 0004-2012`: https://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf
.. _`draft-sca-cfrg-sm3`: https://datatracker.ietf.org/doc/html/draft-sca-cfrg-sm3
