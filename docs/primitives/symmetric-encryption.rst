Symmetric Encryption
====================

Symmetric encryption is a way to encrypt (hide the plaintext value) material
where the encrypter and decrypter both use the same key.

.. class:: cryptography.primitives.block.BlockCipher(cipher, mode)

    Block ciphers work by encrypting content in chunks, often 64- or 128-bits.
    They combine an underlying algorithm (such as AES), with a mode (such as
    CBC, CTR, or GCM). A simple example of encrypting content with AES is:

    .. code-block:: pycon

        >>> from cryptography.primitives.block import BlockCipher, ciphers, modes, padding
        >>> cipher = BlockCipher(cipher.AES(key), mode.CBC(iv, padding.PKCS7()))
        >>> cipher.encrypt("my secret message") + cipher.finalize()
        # The ciphertext
        [...]

    :param cipher: One of the ciphers described below.
    :param mode: One of the modes described below.

    ``encrypt()`` should be called repeatedly with new plaintext, and once the
    full plaintext is fed in, ``finalize()`` should be called.

    .. method:: encrypt(plaintext)

        :param bytes plaintext: The text you wish to encrypt.
        :return bytes: Returns the ciphertext that was added.

    .. method:: finalize()

        :return bytes: Returns the remainder of the ciphertext.

Ciphers
~~~~~~~

.. class:: cryptography.primitives.block.ciphers.AES(key)

    AES (Advanced Encryption Standard) is a block cipher standardized by NIST.
    AES is both fast, and cryptographically strong. It is a good default
    choice for encryption.

    :param bytes key: The secret key, either ``128``, ``192``, or ``256`` bits.
                      This must be kept secret.


Modes
~~~~~

.. class:: cryptography.primitives.block.modes.CBC(initialization_vector, padding)

    CBC (Cipher block chaining) is a mode of operation for block ciphers. It is
    considered cryptographically strong.

    :param bytes initialization_vector: Must be random bytes. They do not need
                                        to be kept secret (they can be included
                                        in a transmitted message). Must be the
                                        same number of bytes as the
                                        ``block_size`` of the cipher. Do not
                                        reuse an ``initialization_vector`` with
                                        a given ``key``.
