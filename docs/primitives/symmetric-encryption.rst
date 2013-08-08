Symmetric Encryption
====================

Symmetric encryption is a way to encrypt (hide the plaintext value) material
where the encrypter and decrypter both use the same key.

.. class:: cryptography.primitives.block.BlockCipher(cipher, mode)

    Block ciphers work by encrypting content in chunks, often 64- or 128-bits.
    Theycombine an underlying algorithm (such as AES), with a mode (such as CBC,
    CTR, or GCM). A simple example of encrypting content with AES is:

    .. code-block:: pycon

        >>> from cryptography.primitives.block import BlockCipher, cipher, mode
        >>> cipher = BlockCipher(cipher.AES(key), mode.CBC(iv))
        >>> cipher.encrypt("my secret message") + cipher.finalize()
        # The ciphertext
        [...]

    Here ``key`` is the encryption key (which must be kept secret), and ``iv``
    is the initialization vector (which must be random). Exactly what form
    these values should take is described for each of the ciphers and modes.

    ``encrypt()`` should be called repeatedly with additional plaintext, and it
    will return the encrypted bytes, if there isn't enough data, it will buffer
    it internally. ``finalize()`` should be called at the end, and will return
    whatever data is left.

Ciphers
~~~~~~~

.. class:: cryptography.primitives.block.cipher.AES(key)

    AES (Advanced Encryption Standard) is a block cipher standardized by NIST.
    AES is both fast, and cryptographically strong. It is a good default
    choice for encryption.

    :param bytes key: The secret key, either ``128``, ``192``, or ``256`` bits.
                      This must be kept secret.


Modes
~~~~~

.. class:: cryptography.primitives.block.mode.CBC(initialization_vector)

    CBC (Cipher block chaining) is a mode of operation for block ciphers. It is
    considered cryptographically strong.

    :param bytes initialization_vector: Must be random bytes. They do not need
                                        to be kept secret (they can be included
                                        in a transmitted message). Must be the
                                        same number of bytes as the
                                        ``block_size`` of the cipher. Do not
                                        reuse an ``initialization_vector`` with
                                        a given ``key``.
