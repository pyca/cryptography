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
        b'...'
        >>> f.decrypt(token)
        b'my deep dark secret'

    :param key: A URL-safe base64-encoded 32-byte key. This **must** be
                kept secret. Anyone with this key is able to create and
                read messages.
    :type key: bytes or str

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

    .. method:: encrypt_at_time(data, current_time)

       .. versionadded:: 3.0

       Encrypts data passed using explicitly passed current time. See
       :meth:`encrypt` for the documentation of the ``data`` parameter, the
       return type and the exceptions raised.

       The motivation behind this method is for the client code to be able to
       test token expiration. Since this method can be used in an insecure
       manner one should make sure the correct time (``int(time.time())``)
       is passed as ``current_time`` outside testing.

       :param int current_time: The current time.

       .. note::

            Similarly to :meth:`encrypt` the encrypted message contains the
            timestamp in *plaintext*, in this case the timestamp is the value
            of the ``current_time`` parameter.


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

    .. method:: decrypt_at_time(token, ttl, current_time)

       .. versionadded:: 3.0

       Decrypts a token using explicitly passed current time. See
       :meth:`decrypt` for the documentation of the ``token`` and ``ttl``
       parameters (``ttl`` is required here), the return type and the exceptions
       raised.

       The motivation behind this method is for the client code to be able to
       test token expiration. Since this method can be used in an insecure
       manner one should make sure the correct time (``int(time.time())``)
       is passed as ``current_time`` outside testing.

       :param int current_time: The current time.


    .. method:: extract_timestamp(token)

        .. versionadded:: 2.3

        Returns the timestamp for the token. The caller can then decide if
        the token is about to expire and, for example, issue a new token.

        :param bytes token: The Fernet token. This is the result of calling
                            :meth:`encrypt`.
        :returns int: The UNIX timestamp of the token.
        :raises cryptography.fernet.InvalidToken: If the ``token``'s signature
                                                  is invalid this exception
                                                  is raised.
        :raises TypeError: This exception is raised if ``token`` is not
                           ``bytes``.


.. class:: MultiFernet(fernets)

    .. versionadded:: 0.7

    This class implements key rotation for Fernet. It takes a ``list`` of
    :class:`Fernet` instances and implements the same API with the exception
    of one additional method: :meth:`MultiFernet.rotate`:

    .. doctest::

        >>> from cryptography.fernet import Fernet, MultiFernet
        >>> key1 = Fernet(Fernet.generate_key())
        >>> key2 = Fernet(Fernet.generate_key())
        >>> f = MultiFernet([key1, key2])
        >>> token = f.encrypt(b"Secret message!")
        >>> token
        b'...'
        >>> f.decrypt(token)
        b'Secret message!'

    MultiFernet performs all encryption options using the *first* key in the
    ``list`` provided. MultiFernet attempts to decrypt tokens with each key in
    turn. A :class:`cryptography.fernet.InvalidToken` exception is raised if
    the correct key is not found in the ``list`` provided.

    Key rotation makes it easy to replace old keys. You can add your new key at
    the front of the list to start encrypting new messages, and remove old keys
    as they are no longer needed.

    Token rotation as offered by :meth:`MultiFernet.rotate` is a best practice
    and manner of cryptographic hygiene designed to limit damage in the event of
    an undetected event and to increase the difficulty of attacks. For example,
    if an employee who had access to your company's fernet keys leaves, you'll
    want to generate new fernet key, rotate all of the tokens currently deployed
    using that new key, and then retire the old fernet key(s) to which the
    employee had access.

    .. method:: rotate(msg)

        .. versionadded:: 2.2

        Rotates a token by re-encrypting it under the :class:`MultiFernet`
        instance's primary key. This preserves the timestamp that was originally
        saved with the token. If a token has successfully been rotated then the
        rotated token will be returned. If rotation fails this will raise an
        exception.

        .. doctest::

           >>> from cryptography.fernet import Fernet, MultiFernet
           >>> key1 = Fernet(Fernet.generate_key())
           >>> key2 = Fernet(Fernet.generate_key())
           >>> f = MultiFernet([key1, key2])
           >>> token = f.encrypt(b"Secret message!")
           >>> token
           b'...'
           >>> f.decrypt(token)
           b'Secret message!'
           >>> key3 = Fernet(Fernet.generate_key())
           >>> f2 = MultiFernet([key3, key1, key2])
           >>> rotated = f2.rotate(token)
           >>> f2.decrypt(rotated)
           b'Secret message!'

        :param bytes msg: The token to re-encrypt.
        :returns bytes: A secure message that cannot be read or altered without
           the key. This is URL-safe base64-encoded. This is referred to as a
           "Fernet token".
        :raises cryptography.fernet.InvalidToken: If a ``token`` is in any
           way invalid this exception is raised.
        :raises TypeError: This exception is raised if the ``msg`` is not
           ``bytes``.


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
    >>> from cryptography.hazmat.primitives import hashes
    >>> from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    >>> password = b"password"
    >>> salt = os.urandom(16)
    >>> kdf = PBKDF2HMAC(
    ...     algorithm=hashes.SHA256(),
    ...     length=32,
    ...     salt=salt,
    ...     iterations=100000,
    ... )
    >>> key = base64.urlsafe_b64encode(kdf.derive(password))
    >>> f = Fernet(key)
    >>> token = f.encrypt(b"Secret message!")
    >>> token
    b'...'
    >>> f.decrypt(token)
    b'Secret message!'

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
feature it does not expose unauthenticated bytes. This means that the complete
message contents must be available in memory, making Fernet generally
unsuitable for very large files at this time.


.. _`Fernet`: https://github.com/fernet/spec/
.. _`specification`: https://github.com/fernet/spec/blob/master/Spec.md
