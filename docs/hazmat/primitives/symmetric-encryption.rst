.. hazmat::


Symmetric Encryption
====================

.. currentmodule:: cryptography.hazmat.primitives.ciphers

.. testsetup::

    import binascii
    key = binascii.unhexlify(b"0" * 32)
    iv = binascii.unhexlify(b"0" * 32)


Symmetric encryption is a way to encrypt (hide the plaintext value) material
where the encrypter and decrypter both use the same key.

.. class:: Cipher(algorithm, mode)

    Cipher objects combine an algorithm (such as AES) with a mode (such as
    CBC, CTR, or GCM). A simple example of encrypting (and then decrypting)
    content with AES is:

    .. doctest::

        >>> from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        >>> cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        >>> encryptor = cipher.encryptor()
        >>> ct = encryptor.update(b"a secret message") + encryptor.finalize()
        >>> decryptor = cipher.decryptor()
        >>> decryptor.update(ct) + decryptor.finalize()
        'a secret message'

    :param algorithms: One of the algorithms described below.
    :param mode: One of the modes described below.

    .. method:: encryptor()

        :return: An encrypting
            :class:`~cryptography.hazmat.primitives.interfaces.CipherContext`
            provider.

        If the backend doesn't support the requested combination of ``cipher``
        and ``mode`` an :class:`cryptography.exceptions.UnsupportedAlgorithm`
        will be raised.

    .. method:: decryptor()

        :return: A decrypting
            :class:`~cryptography.hazmat.primitives.interfaces.CipherContext`
            provider.

        If the backend doesn't support the requested combination of ``cipher``
        and ``mode`` an :class:`cryptography.exceptions.UnsupportedAlgorithm`
        will be raised.


.. currentmodule:: cryptography.hazmat.primitives.interfaces

.. class:: CipherContext

    When calling ``encryptor()`` or ``decryptor()`` on a ``Cipher`` object
    you will receive a return object conforming to the ``CipherContext``
    interface. You can then call ``update(data)`` with data until you have fed
    everything into the context. Once that is done call ``finalize()`` to
    finish the operation and obtain the remainder of the data.

    .. method:: update(data)

        :param bytes data: The data you wish to pass into the context.
        :return bytes: Returns the data that was encrypted or decrypted.

        When the ``Cipher`` was constructed in a mode that turns it into a
        stream cipher (e.g.
        :class:`cryptography.hazmat.primitives.ciphers.modes.CTR`), this will
        return bytes immediately, however in other modes it will return chunks,
        whose size is determined by the cipher's block size.

    .. method:: finalize()

        :return bytes: Returns the remainder of the data.

Algorithms
~~~~~~~~~~

.. currentmodule:: cryptography.hazmat.primitives.ciphers.algorithms

.. class:: AES(key)

    AES (Advanced Encryption Standard) is a block cipher standardized by NIST.
    AES is both fast, and cryptographically strong. It is a good default
    choice for encryption.

    :param bytes key: The secret key, either ``128``, ``192``, or ``256`` bits.
                      This must be kept secret.

.. class:: Camellia(key)

    Camellia is a block cipher approved for use by CRYPTREC and ISO/IEC.
    It is considered to have comparable security and performance to AES, but
    is not as widely studied or deployed.

    :param bytes key: The secret key, either ``128``, ``192``, or ``256`` bits.
                      This must be kept secret.


.. class:: TripleDES(key)

    Triple DES (Data Encryption Standard), sometimes refered to as 3DES, is a
    block cipher standardized by NIST. Triple DES has known cryptoanalytic
    flaws, however none of them currently enable a practical attack.
    Nonetheless, Triples DES is not reccomended for new applications because it
    is incredibly slow; old applications should consider moving away from it.

    :param bytes key: The secret key, either ``64``, ``128``, or ``192`` bits
                      (note that DES functionally uses ``56``, ``112``, or
                      ``168`` bits of the key, there is a parity byte in each
                      component of the key), in some materials these are
                      referred to as being up to three separate keys (each
                      ``56`` bits long), they can simply be concatenated to
                      produce the full key. This must be kept secret.

.. class:: CAST5(key)

    CAST5 (also known as CAST-128) is a block cipher approved for use in the
    Canadian government by their Communications Security Establishment. It is a
    variable key length cipher and supports keys from 40-128 bits in length.

    :param bytes key: The secret key, 40-128 bits in length (in increments of
                      8).  This must be kept secret.

Weak Ciphers
------------

.. warning::

    These ciphers are considered weak for a variety of reasons. New
    applications should avoid their use and existing applications should
    strongly consider migrating away.

.. class:: Blowfish(key)

    Blowfish is a block cipher developed by Bruce Schneier. It is known to be
    susceptible to attacks when using weak keys. The author has recommended
    that users of Blowfish move to newer algorithms like
    :class:`AES`.

    :param bytes key: The secret key, 32-448 bits in length (in increments of
                      8).  This must be kept secret.


.. _symmetric-encryption-modes:

Modes
~~~~~

.. currentmodule:: cryptography.hazmat.primitives.ciphers.modes

.. class:: CBC(initialization_vector)

    CBC (Cipher block chaining) is a mode of operation for block ciphers. It is
    considered cryptographically strong.

    :param bytes initialization_vector: Must be random bytes. They do not need
                                        to be kept secret (they can be included
                                        in a transmitted message). Must be the
                                        same number of bytes as the
                                        ``block_size`` of the cipher. Each time
                                        something is encrypted a new
                                        ``initialization_vector`` should be
                                        generated. Do not reuse an
                                        ``initialization_vector`` with
                                        a given ``key``, and particularly do
                                        not use a constant
                                        ``initialization_vector``.

    A good construction looks like:

    .. code-block:: pycon

        >>> import os
        >>> iv = os.urandom(16)
        >>> mode = CBC(iv)

    While the following is bad and will leak information:

    .. code-block:: pycon

        >>> iv = "a" * 16
        >>> mode = CBC(iv)


.. class:: CTR(nonce)

    .. warning::

        Counter mode is not recommended for use with block ciphers that have a
        block size of less than 128-bits.

    CTR (Counter) is a mode of operation for block ciphers. It is considered
    cryptographically strong. It transforms a block cipher into a stream
    cipher.

    :param bytes nonce: Should be random bytes. It is critical to never reuse a
                        ``nonce`` with a given key.  Any reuse of a nonce
                        with the same key compromises the security of every
                        message encrypted with that key. Must be the same
                        number of bytes as the ``block_size`` of the cipher
                        with a given key. The nonce does not need to be kept
                        secret and may be included alongside the ciphertext.

.. class:: OFB(initialization_vector)

    OFB (Output Feedback) is a mode of operation for block ciphers. It
    transforms a block cipher into a stream cipher.

    :param bytes initialization_vector: Must be random bytes. They do not need
                                        to be kept secret (they can be included
                                        in a transmitted message). Must be the
                                        same number of bytes as the
                                        ``block_size`` of the cipher. Do not
                                        reuse an ``initialization_vector`` with
                                        a given ``key``.

.. class:: CFB(initialization_vector)

    CFB (Cipher Feedback) is a mode of operation for block ciphers. It
    transforms a block cipher into a stream cipher.

    :param bytes initialization_vector: Must be random bytes. They do not need
                                        to be kept secret (they can be included
                                        in a transmitted message). Must be the
                                        same number of bytes as the
                                        ``block_size`` of the cipher. Do not
                                        reuse an ``initialization_vector`` with
                                        a given ``key``.


Insecure Modes
--------------

.. warning::

    These modes are insecure. New applications should never make use of them,
    and existing applications should strongly consider migrating away.


.. class:: ECB()

    ECB (Electronic Code Book) is the simplest mode of operation for block
    ciphers. Each block of data is encrypted in the same way. This means
    identical plaintext blocks will always result in identical ciphertext
    blocks, and thus result in information leakage
