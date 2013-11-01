.. hazmat::

Message Digests
===============

.. currentmodule:: cryptography.hazmat.primitives.hashes

.. class:: Hash(algorithm)

    A cryptographic hash function takes an arbitrary block of data and
    calculates a fixed-size bit string (a digest), such that different data
    results (with a high probability) in different digests.

    This is an implementation of
    :class:`cryptography.hazmat.primitives.interfaces.HashContext` meant to
    be used with
    :class:`cryptography.hazmat.primitives.interfaces.HashAlgorithm`
    implementations to provide an incremental interface to calculating
    various message digests.

    .. doctest::

        >>> from cryptography.hazmat.primitives import hashes
        >>> digest = hashes.Hash(hashes.SHA256())
        >>> digest.update(b"abc")
        >>> digest.update(b"123")
        >>> digest.finalize()
        'l\xa1=R\xcap\xc8\x83\xe0\xf0\xbb\x10\x1eBZ\x89\xe8bM\xe5\x1d\xb2\xd29%\x93\xafj\x84\x11\x80\x90'

    .. method:: update(data)

        :param bytes data: The bytes you wish to hash.

    .. method:: copy()

        :return: a new instance of this object with a copied internal state.

    .. method:: finalize()

        Finalize the current context and return the message digest as bytes.

        Once ``finalize`` is called this object can no longer be used.

        :return bytes: The message digest as bytes.


SHA-1
~~~~~

.. attention::

    NIST has deprecated SHA-1 in favor of the SHA-2 variants. New applications
    are strongly suggested to use SHA-2 over SHA-1.

.. class:: SHA1()

    SHA-1 is a cryptographic hash function standardized by NIST. It has a
    160-bit message digest.

SHA-2 Family
~~~~~~~~~~~~

.. class:: SHA224()

    SHA-224 is a cryptographic hash function from the SHA-2 family and
    standardized by NIST. It has a 224-bit message digest.

.. class:: SHA256()

    SHA-256 is a cryptographic hash function from the SHA-2 family and
    standardized by NIST. It has a 256-bit message digest.

.. class:: SHA384()

    SHA-384 is a cryptographic hash function from the SHA-2 family and
    standardized by NIST. It has a 384-bit message digest.

.. class:: SHA512()

    SHA-512 is a cryptographic hash function from the SHA-2 family and
    standardized by NIST. It has a 512-bit message digest.

RIPEMD160
~~~~~~~~~

.. class:: RIPEMD160()

    RIPEMD160 is a cryptographic hash function that is part of ISO/IEC
    10118-3:2004. It has a 160-bit message digest.

Whirlpool
~~~~~~~~~

.. class:: Whirlpool()

    Whirlpool is a cryptographic hash function that is part of ISO/IEC
    10118-3:2004. It has a 512-bit message digest.

MD5
~~~

.. warning::

    MD5 is a deprecated hash algorithm that has practical known collision
    attacks. You are strongly discouraged from using it.

.. class:: MD5()

    MD5 is a deprecated cryptographic hash function. It has a 128-bit message
    digest and has practical known collision attacks.
