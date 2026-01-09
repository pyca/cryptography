.. hazmat::

HPKE (Hybrid Public Key Encryption)
===================================

.. module:: cryptography.hazmat.primitives.hpke

HPKE is a standard for public key encryption that combines a Key Encapsulation
Mechanism (KEM), a Key Derivation Function (KDF), and an Authenticated
Encryption with Associated Data (AEAD) scheme. It is defined in :rfc:`9180`.

This implementation supports Base mode with DHKEM(X25519, HKDF-SHA256),
HKDF-SHA256, and AES-128-GCM.

Quick Start
-----------

.. code-block:: python

    from cryptography.hazmat.primitives.hpke import create_sender, create_recipient
    from cryptography.hazmat.primitives.asymmetric import x25519

    # Generate recipient key pair
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Sender: encrypt a message
    sender = create_sender(public_key, info=b"application info")
    ciphertext = sender.encrypt(b"secret message", aad=b"authenticated data")
    enc = sender.enc  # Send enc + ciphertext to recipient

    # Recipient: decrypt the message
    recipient = create_recipient(enc, private_key, info=b"application info")
    plaintext = recipient.decrypt(ciphertext, aad=b"authenticated data")

Functions
---------

.. function:: create_sender(public_key, info=b"")

    Create a sender context for encrypting messages.

    This uses DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.

    :param public_key: The recipient's X25519 public key.
    :type public_key: :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey`
    :param bytes info: Optional application-specific info string.
    :returns: A :class:`SenderContext` for encrypting messages.

.. function:: create_recipient(enc, private_key, info=b"")

    Create a recipient context for decrypting messages.

    This uses DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.

    :param bytes enc: The encapsulated key from the sender.
    :param private_key: The recipient's X25519 private key.
    :type private_key: :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey`
    :param bytes info: Optional application-specific info string.
    :returns: A :class:`RecipientContext` for decrypting messages.

SenderContext
-------------

.. class:: SenderContext

    Context for encrypting messages. Obtained from :func:`create_sender`.

    .. attribute:: enc

        The encapsulated key (bytes). Send this to the recipient along with
        the ciphertext.

    .. method:: encrypt(plaintext, aad=b"")

        Encrypt a message.

        :param bytes plaintext: The message to encrypt.
        :param bytes aad: Optional additional authenticated data.
        :returns: The ciphertext.
        :rtype: bytes

RecipientContext
----------------

.. class:: RecipientContext

    Context for decrypting messages. Obtained from :func:`create_recipient`.

    .. method:: decrypt(ciphertext, aad=b"")

        Decrypt a message.

        :param bytes ciphertext: The ciphertext to decrypt.
        :param bytes aad: Optional additional authenticated data.
        :returns: The plaintext.
        :rtype: bytes
        :raises cryptography.exceptions.InvalidTag: If decryption fails.

Exceptions
----------

.. class:: HPKEError

    Base exception for HPKE errors.

.. class:: MessageLimitReachedError

    Raised when the message limit for a context is reached.
