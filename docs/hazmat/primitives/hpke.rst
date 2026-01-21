.. hazmat::

HPKE (Hybrid Public Key Encryption)
===================================

.. module:: cryptography.hazmat.primitives.hpke

HPKE is a standard for public key encryption that combines a Key Encapsulation
Mechanism (KEM), a Key Derivation Function (KDF), and an Authenticated
Encryption with Associated Data (AEAD) scheme. It is defined in :rfc:`9180`.

This implementation supports Base mode with DHKEM(X25519, HKDF-SHA256),
HKDF-SHA256, and AES-128-GCM.

HPKE provides authenticated encryption: the recipient can be certain that the
message was encrypted by someone who knows the recipient's public key, but
the sender is anonymous. Each call to :meth:`Suite.encrypt` generates a fresh
ephemeral key pair, so encrypting the same plaintext twice will produce
different ciphertext.

The ``info`` parameter should be used to bind the encryption to a specific
context (e.g., "MyApp-v1-UserMessages"). The ``aad`` parameter provides
additional authenticated data that is not encrypted but is authenticated
along with the ciphertext.

.. code-block:: python

    from cryptography.hazmat.primitives.hpke import Suite, KEM, KDF, AEAD
    from cryptography.hazmat.primitives.asymmetric import x25519

    suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

    # Generate recipient key pair
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Encrypt
    ciphertext = suite.encrypt(b"secret message", public_key, info=b"app info")

    # Decrypt
    plaintext = suite.decrypt(ciphertext, private_key, info=b"app info")

.. class:: Suite(kem, kdf, aead)

    An HPKE cipher suite combining a KEM, KDF, and AEAD.

    :param kem: The key encapsulation mechanism.
    :type kem: :class:`KEM`
    :param kdf: The key derivation function.
    :type kdf: :class:`KDF`
    :param aead: The authenticated encryption algorithm.
    :type aead: :class:`AEAD`

    .. method:: encrypt(plaintext, public_key, info=b"", aad=b"")

        Encrypt a message using HPKE.

        :param bytes plaintext: The message to encrypt.
        :param public_key: The recipient's public key.
        :type public_key: :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey`
        :param bytes info: Application-specific info string.
        :param bytes aad: Additional authenticated data.
        :returns: The encapsulated key concatenated with ciphertext (enc || ct).
        :rtype: bytes

    .. method:: decrypt(ciphertext, private_key, info=b"", aad=b"")

        Decrypt a message using HPKE.

        :param bytes ciphertext: The enc || ct value from :meth:`encrypt`.
        :param private_key: The recipient's private key.
        :type private_key: :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey`
        :param bytes info: Application-specific info string.
        :param bytes aad: Additional authenticated data.
        :returns: The decrypted plaintext.
        :rtype: bytes
        :raises cryptography.exceptions.InvalidTag: If decryption fails.

.. class:: KEM

    An enumeration of key encapsulation mechanisms.

    .. attribute:: X25519

        DHKEM(X25519, HKDF-SHA256)

.. class:: KDF

    An enumeration of key derivation functions.

    .. attribute:: HKDF_SHA256

        HKDF-SHA256

.. class:: AEAD

    An enumeration of authenticated encryption algorithms.

    .. attribute:: AES_128_GCM

        AES-128-GCM
