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

Here ``key`` is the encryption key (which must be kept secret), and ``iv`` is
the initialization vector (which must be random). Exactly what form these
values should take is described for each of the ciphers and modes.

``encrypt()`` should be called repeatedly with additional plaintext, and it
will return the encrypted bytes, if there isn't enough data, it will buffer it
internally. ``finalize()`` should be called at the end, and will return
whatever data is left.

Ciphers
~~~~~~~

.. class:: cryptography.primitives.aes.AES(key)

    AES (Advanced encryption standard) is a block cipher standardized by NIST.
    AES is both fast, and cryptographically strong. It is a good default
    choice for encryption.

    :param bytes key: The secret key, either ``128``, ``192``, or ``256`` bits.


Modes
~~~~~

CBC
+++
