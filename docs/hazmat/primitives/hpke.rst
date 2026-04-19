.. hazmat::

HPKE (Hybrid Public Key Encryption)
===================================

.. module:: cryptography.hazmat.primitives.hpke

HPKE is a standard for public key encryption that combines a Key Encapsulation
Mechanism (KEM), a Key Derivation Function (KDF), and an Authenticated
Encryption with Associated Data (AEAD) scheme. It is defined in :rfc:`9180`.

HPKE provides authenticated encryption: the recipient can be certain that the
message was encrypted by someone who knows the recipient's public key, but
the sender is anonymous. Each call to :meth:`Suite.encrypt` generates a fresh
ephemeral key pair, so encrypting the same plaintext twice will produce
different ciphertext.

The ``info`` parameter should be used to bind the encryption to a specific
context (e.g., "MyApp-v1-UserMessages"). Per :rfc:`9180#section-8.1`,
applications using single-shot APIs should use the ``info`` parameter for
specifying auxiliary authenticated information.

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

    .. method:: encrypt(plaintext, public_key, info=b"")

        Encrypt a message using HPKE.

        :param bytes plaintext: The message to encrypt.
        :param public_key: The recipient's public key.
        :type public_key: :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey`
        :param bytes info: Application-specific context string for binding the
            encryption to a specific application or protocol.
        :returns: The encapsulated key concatenated with ciphertext (enc || ct).
        :rtype: bytes

    .. method:: decrypt(ciphertext, private_key, info=b"")

        Decrypt a message using HPKE.

        :param bytes ciphertext: The enc || ct value from :meth:`encrypt`.
        :param private_key: The recipient's private key.
        :type private_key: :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey`
        :param bytes info: Application-specific context string (must match the
            value used during encryption).
        :returns: The decrypted plaintext.
        :rtype: bytes
        :raises cryptography.exceptions.InvalidTag: If decryption fails.

.. class:: KEM

    An enumeration of key encapsulation mechanisms.

    .. attribute:: X25519

        DHKEM(X25519, HKDF-SHA256)

    .. attribute:: P256

        DHKEM(P-256, HKDF-SHA256)

    .. attribute:: P384

        DHKEM(P-384, HKDF-SHA384)

    .. attribute:: P521

        DHKEM(P-521, HKDF-SHA512)

    .. attribute:: MLKEM768

        ML-KEM-768. Post-quantum secure. Only available on backends that
        support ML-KEM.

    .. attribute:: MLKEM1024

        ML-KEM-1024. Post-quantum secure. Only available on backends that
        support ML-KEM.

    .. attribute:: MLKEM768_X25519

        A hybrid KEM combining ML-KEM-768 with X25519 (also known as X-Wing).
        Post-quantum secure. Only available on backends that support ML-KEM.
        Public and private keys are :class:`MLKEM768X25519PublicKey` and
        :class:`MLKEM768X25519PrivateKey`.

.. class:: MLKEM768X25519PrivateKey(mlkem_key, x25519_key)

    .. versionadded:: 47.0.0

    A hybrid ML-KEM-768 / X25519 private key for use with
    :attr:`KEM.MLKEM768_X25519`. Combines an
    :class:`~cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey`
    and an
    :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey`
    into a single recipient key.

    :param mlkem_key: The ML-KEM-768 private key component.
    :type mlkem_key: :class:`~cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey`

    :param x25519_key: The X25519 private key component.
    :type x25519_key: :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey`

    .. method:: public_key()

        :returns: :class:`MLKEM768X25519PublicKey`

.. class:: MLKEM768X25519PublicKey(mlkem_key, x25519_key)

    .. versionadded:: 47.0.0

    A hybrid ML-KEM-768 / X25519 public key for use with
    :attr:`KEM.MLKEM768_X25519`. Combines an
    :class:`~cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PublicKey`
    and an
    :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey`
    into a single recipient key.

    :param mlkem_key: The ML-KEM-768 public key component.
    :type mlkem_key: :class:`~cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PublicKey`

    :param x25519_key: The X25519 public key component.
    :type x25519_key: :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey`

.. class:: KDF

    An enumeration of key derivation functions.

    .. attribute:: HKDF_SHA256

        HKDF-SHA256

    .. attribute:: HKDF_SHA384

        HKDF-SHA384

    .. attribute:: HKDF_SHA512

        HKDF-SHA512

    .. attribute:: SHAKE128

        SHAKE-128

    .. attribute:: SHAKE256

        SHAKE-256

.. class:: AEAD

    An enumeration of authenticated encryption algorithms.

    .. attribute:: AES_128_GCM

        AES-128-GCM

    .. attribute:: AES_256_GCM

        AES-256-GCM

    .. attribute:: CHACHA20_POLY1305

        ChaCha20Poly1305
