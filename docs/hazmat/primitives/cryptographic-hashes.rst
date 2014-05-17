.. hazmat::

Message digests
===============

.. currentmodule:: cryptography.hazmat.primitives.hashes

.. class:: Hash(algorithm, backend)

    A cryptographic hash function takes an arbitrary block of data and
    calculates a fixed-size bit string (a digest), such that different data
    results (with a high probability) in different digests.

    This is an implementation of
    :class:`~cryptography.hazmat.primitives.interfaces.HashContext` meant to
    be used with
    :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
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
        :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
        provider such as those described in
        :ref:`below <cryptographic-hash-algorithms>`.
    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.HashBackend`
        provider.

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

SHA-1
~~~~~

.. attention::

    NIST has deprecated SHA-1 in favor of the SHA-2 variants. New applications
    are strongly suggested to use SHA-2 over SHA-1.

.. class:: SHA1()

    SHA-1 is a cryptographic hash function standardized by NIST. It produces an
    160-bit message digest.

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

RIPEMD160
~~~~~~~~~

.. class:: RIPEMD160()

    RIPEMD160 is a cryptographic hash function that is part of ISO/IEC
    10118-3:2004. It produces a 160-bit message digest.

Whirlpool
~~~~~~~~~

.. class:: Whirlpool()

    Whirlpool is a cryptographic hash function that is part of ISO/IEC
    10118-3:2004. It produces a 512-bit message digest.

MD5
~~~

.. warning::

    MD5 is a deprecated hash algorithm that has practical known collision
    attacks. You are strongly discouraged from using it. Existing applications
    should strongly consider moving away.

.. class:: MD5()

    MD5 is a deprecated cryptographic hash function. It produces a 128-bit
    message digest and has practical known collision attacks.


.. _`Lifetimes of cryptographic hash functions`: http://valerieaurora.org/hash.html
