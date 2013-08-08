Symmetric Encryption
====================

Symmetric encryption is a way to encrypt (hide the plaintext value) material
where the encrypter and decrypter both use the same key.

Block ciphers
-------------

Block ciphers work by encrypting content in chunks, often 64- or 128-bits. They
combine an underlying algorithm (such as AES), with a mode (such as CBC, CTR,
or GCM). A simple example of encrypting content with AES is:

.. code-block:: pycon

    >>> from cryptography.primitives import BlockCipher, CBC
    >>> from cryptography.primitives.aes import AES
    >>> cipher = BlockCipher(AES(key), CBC(iv))
    >>> cipher.encrypt("my secret message") + cipher.finalize()
    # The ciphertext
    [...]

