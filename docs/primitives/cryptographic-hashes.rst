Message Digests
===============

.. currentmodule:: cryptography.primitives.hashes

.. class:: BaseHash(data=None)

   Abstract base class that implements a common interface for all hash
   algorithms that follow here.

   If ``data`` is provided ``update(data)`` is called upon construction.

    .. method:: update(data)

        :param bytes data: The bytes you wish to hash.

    .. method:: copy()

        :return: a new instance of this object with a copied internal state.

    .. method:: digest()

        :return bytes: The message digest as bytes.

    .. method:: hexdigest()

        :return str: The message digest as hex.

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

    MD5 is a deprecated cryptographic hash function. It has a 160-bit message
    digest and has practical known collision attacks.
