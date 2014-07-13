Fernet (symmetric encryption)
=============================

.. currentmodule:: cryptography.fernet

Fernet provides guarantees that a message encrypted using it cannot be
manipulated or read without the key. `Fernet`_ is an implementation of
symmetric (also known as "secret key") authenticated cryptography.

.. class:: Fernet(key)

    This class provides both encryption and decryption facilities.

    .. doctest::

        >>> from cryptography.fernet import Fernet
        >>> key = Fernet.generate_key()
        >>> f = Fernet(key)
        >>> token = f.encrypt(b"my deep dark secret")
        >>> token
        '...'
        >>> f.decrypt(token)
        'my deep dark secret'

    :param bytes key: A URL-safe base64-encoded 32-byte key. This **must** be
                      kept secret. Anyone with this key is able to create and
                      read messages.

    .. classmethod:: generate_key()

        Generates a fresh fernet key. Keep this some place safe! If you lose it
        you'll no longer be able to decrypt messages; if anyone else gains
        access to it, they'll be able to decrypt all of your messages, and
        they'll also be able forge arbitrary messages that will be
        authenticated and decrypted.

    .. method:: encrypt(data)

        :param bytes data: The message you would like to encrypt.
        :returns bytes: A secure message that cannot be read or altered
                        without the key. It is URL-safe base64-encoded. This is
                        referred to as a "Fernet token".
        :raises TypeError: This exception is raised if ``data`` is not ``bytes``.

        .. note::

            The encrypted message contains the current time when it was
            generated in *plaintext*, the time a message was created will
            therefore be visible to a possible attacker.

    .. method:: decrypt(token, ttl=None)

        :param bytes token: The Fernet token. This is the result of calling
                            :meth:`encrypt`.
        :param int ttl: Optionally, the number of seconds old a message may be
                        for it to be valid. If the message is older than
                        ``ttl`` seconds (from the time it was originally
                        created) an exception will be raised. If ``ttl`` is not
                        provided (or is ``None``), the age of the message is
                        not considered.
        :returns bytes: The original plaintext.
        :raises cryptography.fernet.InvalidToken: If the ``token`` is in any
                                                  way invalid, this exception
                                                  is raised. A token may be
                                                  invalid for a number of
                                                  reasons: it is older than the
                                                  ``ttl``, it is malformed, or
                                                  it does not have a valid
                                                  signature.
        :raises TypeError: This exception is raised if ``token`` is not ``bytes``.


.. class:: InvalidToken

    See :meth:`Fernet.decrypt` for more information.

Implementation
--------------

Fernet is built on top of a number of standard cryptographic primitives.
Specifically it uses:

* :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES` in
  :class:`~cryptography.hazmat.primitives.ciphers.modes.CBC` mode with a
  128-bit key for encryption; using
  :class:`~cryptography.hazmat.primitives.padding.PKCS7` padding.
* :class:`~cryptography.hazmat.primitives.hmac.HMAC` using
  :class:`~cryptography.hazmat.primitives.hashes.SHA256` for authentication.
* Initialization vectors are generated using ``os.urandom()``.

For complete details consult the `specification`_.


.. _`Fernet`: https://github.com/fernet/spec/
.. _`specification`: https://github.com/fernet/spec/blob/master/Spec.md
