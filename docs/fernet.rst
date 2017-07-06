Fernet (symmetric encryption)
=============================

.. currentmodule:: cryptography.fernet

Fernet guarantees that a message encrypted using it cannot be
manipulated or read without the key. `Fernet`_ is an implementation of
symmetric (also known as "secret key") authenticated cryptography. Fernet also
has support for implementing key rotation via :class:`MultiFernet`.

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

        Encrypts data passed. The result of this encryption is known as a
        "Fernet token" and has strong privacy and authenticity guarantees.

        :param bytes data: The message you would like to encrypt.
        :returns bytes: A secure message that cannot be read or altered
                        without the key. It is URL-safe base64-encoded. This is
                        referred to as a "Fernet token".
        :raises TypeError: This exception is raised if ``data`` is not
                           ``bytes``.

        .. note::

            The encrypted message contains the current time when it was
            generated in *plaintext*, the time a message was created will
            therefore be visible to a possible attacker.

    .. method:: decrypt(token, ttl=None)

        Decrypts a Fernet token. If successfully decrypted you will receive the
        original plaintext as the result, otherwise an exception will be
        raised. It is safe to use this data immediately as Fernet verifies
        that the data has not been tampered with prior to returning it.

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
        :raises TypeError: This exception is raised if ``token`` is not
                           ``bytes``.


.. class:: MultiFernet(fernets)

    .. versionadded:: 0.7

    This class implements key rotation for Fernet. It takes a ``list`` of
    :class:`Fernet` instances, and implements the same API:

    .. doctest::

        >>> from cryptography.fernet import Fernet, MultiFernet
        >>> key1 = Fernet(Fernet.generate_key())
        >>> key2 = Fernet(Fernet.generate_key())
        >>> f = MultiFernet([key1, key2])
        >>> token = f.encrypt(b"Secret message!")
        >>> token
        '...'
        >>> f.decrypt(token)
        'Secret message!'

    MultiFernet performs all encryption options using the *first* key in the
    ``list`` provided. MultiFernet attempts to decrypt tokens with each key in
    turn. A :class:`cryptography.fernet.InvalidToken` exception is raised if
    the correct key is not found in the ``list`` provided.

    Key rotation makes it easy to replace old keys. You can add your new key at
    the front of the list to start encrypting new messages, and remove old keys
    as they are no longer needed.


.. class:: InvalidToken

    See :meth:`Fernet.decrypt` for more information.


Using passwords with Fernet
---------------------------

It is possible to use passwords with Fernet. To do this, you need to run the
password through a key derivation function such as
:class:`~cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC`, bcrypt or
:class:`~cryptography.hazmat.primitives.kdf.scrypt.Scrypt`.

.. doctest::

    >>> import base64
    >>> import os
    >>> from cryptography.fernet import Fernet
    >>> from cryptography.hazmat.backends import default_backend
    >>> from cryptography.hazmat.primitives import hashes
    >>> from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    >>> password = b"password"
    >>> salt = os.urandom(16)
    >>> kdf = PBKDF2HMAC(
    ...     algorithm=hashes.SHA256(),
    ...     length=32,
    ...     salt=salt,
    ...     iterations=100000,
    ...     backend=default_backend()
    ... )
    >>> key = base64.urlsafe_b64encode(kdf.derive(password))
    >>> f = Fernet(key)
    >>> token = f.encrypt(b"Secret message!")
    >>> token
    '...'
    >>> f.decrypt(token)
    'Secret message!'

In this scheme, the salt has to be stored in a retrievable location in order
to derive the same key from the password in the future.

The iteration count used should be adjusted to be as high as your server can
tolerate. A good default is at least 100,000 iterations which is what Django
recommended in 2014.

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

Limitations
-----------

Fernet is ideal for encrypting data that easily fits in memory. As a design
feature it does not expose unauthenticated bytes. Unfortunately, this makes it
generally unsuitable for very large files at this time.


.. _`Fernet`: https://github.com/fernet/spec/
.. _`specification`: https://github.com/fernet/spec/blob/master/Spec.md
