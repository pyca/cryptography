Message Digests
====================

SHA-1
~~~~~~~

.. attention::

    NIST has deprecated SHA-1 in favor of the SHA-2 variants. New applications
    are strongly suggested to use SHA-2 over SHA-1.

.. class:: cryptography.primitives.hashes.SHA1()

    SHA-1 is a cryptographic hash function standardized by NIST. It has a
    160-bit message digest.

    .. method:: update(string)

        :param bytes string: The bytes you wish to hash.

    .. method:: digest()

        :return bytes: The message digest as bytes.

    .. method:: hexdigest()

        :return str: The message digest as hex.


SHA-2 Family
~~~~~~~

.. class:: cryptography.primitives.hashes.SHA224()

    SHA-224 is a cryptographic hash function from the SHA-2 family and
    standardized by NIST. It has a 224-bit message digest.

    .. method:: update(string)

        :param bytes string: The bytes you wish to hash.

    .. method:: digest()

        :return bytes: The message digest as bytes.

    .. method:: hexdigest()

        :return str: The message digest as hex.

.. class:: cryptography.primitives.hashes.SHA256()

    SHA-256 is a cryptographic hash function from the SHA-2 family and
    standardized by NIST. It has a 256-bit message digest.

    .. method:: update(string)

        :param bytes string: The bytes you wish to hash.

    .. method:: digest()

        :return bytes: The message digest as bytes.

    .. method:: hexdigest()

        :return str: The message digest as hex.

.. class:: cryptography.primitives.hashes.SHA384()

    SHA-384 is a cryptographic hash function from the SHA-2 family and
    standardized by NIST. It has a 384-bit message digest.

    .. method:: update(string)

        :param bytes string: The bytes you wish to hash.

    .. method:: digest()

        :return bytes: The message digest as bytes.

    .. method:: hexdigest()

        :return str: The message digest as hex.

.. class:: cryptography.primitives.hashes.SHA512()

    SHA-512 is a cryptographic hash function from the SHA-2 family and
    standardized by NIST. It has a 512-bit message digest.

    .. method:: update(string)

        :param bytes string: The bytes you wish to hash.

    .. method:: digest()

        :return bytes: The message digest as bytes.

    .. method:: hexdigest()

        :return str: The message digest as hex.

RIPEMD160
~~~~~~~

.. class:: cryptography.primitives.hashes.RIPEMD160()

    RIPEMD160 is a cryptographic hash function that is part of ISO/IEC
    10118-3:2004. It has a 160-bit message digest.

    .. method:: update(string)

        :param bytes string: The bytes you wish to hash.

    .. method:: digest()

        :return bytes: The message digest as bytes.

    .. method:: hexdigest()

        :return str: The message digest as hex.

Whirlpool
~~~~~~~

.. class:: cryptography.primitives.hashes.Whirlpool()

    Whirlpool is a cryptographic hash function that is part of ISO/IEC
    10118-3:2004. It has a 512-bit message digest.

    .. method:: update(string)

        :param bytes string: The bytes you wish to hash.

    .. method:: digest()

        :return bytes: The message digest as bytes.

    .. method:: hexdigest()

        :return str: The message digest as hex.

MD5
~~~~~~~

.. warning::

    MD5 is a deprecated hash algorithm that has practical known collision
    attacks. You are strongly discouraged from using it.

.. class:: cryptography.primitives.hashes.MD5()

    MD5 is a deprecated cryptographic hash function. It has a 160-bit message
    digest and has practical known collision attacks.

    .. method:: update(string)

        :param bytes string: The bytes you wish to hash.

    .. method:: digest()

        :return bytes: The message digest as bytes.

    .. method:: hexdigest()

        :return str: The message digest as hex.
