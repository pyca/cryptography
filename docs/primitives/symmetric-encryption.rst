Symmetric Encryption
====================

.. currentmodule:: cryptography.primitives.block

.. testsetup::

    import binascii
    key = binascii.unhexlify(b"0" * 32)
    iv = binascii.unhexlify(b"0" * 32)


Symmetric encryption is a way to encrypt (hide the plaintext value) material
where the encrypter and decrypter both use the same key.

.. class:: BlockCipher(cipher, mode)

    Block ciphers work by encrypting content in chunks, often 64- or 128-bits.
    They combine an underlying algorithm (such as AES), with a mode (such as
    CBC, CTR, or GCM). A simple example of encrypting (and then decrypting)
    content with AES is:

    .. doctest::

        >>> from cryptography.primitives.block import BlockCipher, ciphers, modes
        >>> cipher = BlockCipher(ciphers.AES(key), modes.CBC(iv))
        >>> encryptor = cipher.encryptor()
        >>> ct = encryptor.update(b"a secret message") + encryptor.finalize()
        >>> decryptor = cipher.decryptor()
        >>> decryptor.update(ct) + decryptor.finalize()
        'a secret message'

    :param cipher: One of the ciphers described below.
    :param mode: One of the modes described below.

    .. method:: encryptor()

        :return: An encrypting
            :class:`~cryptography.primitives.interfaces.CipherContext`
            provider.

    .. method:: decryptor()

        :return: A decrypting
            :class:`~cryptography.primitives.interfaces.CipherContext`
            provider.

.. currentmodule:: cryptography.primitives.interfaces

.. class:: CipherContext()

    When calling ``encryptor()`` or ``decryptor()`` on a BlockCipher object you
    will receive a return object conforming to the CipherContext interface. You
    can then call ``update(data)`` with data until you have fed everything into
    the context. Once that is done call ``finalize()`` to finish the operation and
    obtain the remainder of the data.


    .. method:: update(data)

        :param bytes data: The text you wish to pass into the context.
        :return bytes: Returns the data that was encrypted or decrypted.

    .. method:: finalize()

        :return bytes: Returns the remainder of the data.

Ciphers
~~~~~~~

.. currentmodule:: cryptography.primitives.block.ciphers

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


Modes
~~~~~

.. currentmodule:: cryptography.primitives.block.modes

.. class:: CBC(initialization_vector)

    CBC (Cipher block chaining) is a mode of operation for block ciphers. It is
    considered cryptographically strong.

    :param bytes initialization_vector: Must be random bytes. They do not need
                                        to be kept secret (they can be included
                                        in a transmitted message). Must be the
                                        same number of bytes as the
                                        ``block_size`` of the cipher. Do not
                                        reuse an ``initialization_vector`` with
                                        a given ``key``.


.. class:: CTR(nonce)

    .. warning::

        Counter mode is not recommended for use with block ciphers that have a
        block size of less than 128-bits.

    CTR (Counter) is a mode of operation for block ciphers. It is considered
    cryptographically strong.

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
