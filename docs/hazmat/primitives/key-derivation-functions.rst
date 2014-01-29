.. hazmat::

Key Derivation Functions
========================

.. currentmodule:: cryptography.hazmat.primitives.kdf

Key derivation functions derive key material from passwords or other data
sources using a pseudo-random function (PRF). Different KDFs are suitable for
different tasks such as:

- Cryptographic key derivation

    Deriving a key suitable for use as input to an encryption algorithm.
    Typically this means taking a password and running it through an algorithm
    such as :class:`~cryptography.hazmat.primitives.kdf.PBKDF2HMAC` or HKDF.
    This process is typically known as `key stretching`_.

- Password storage

    When storing passwords you want to use an algorithm that is computationally
    intensive. Legitimate users will only need to compute it once (for example,
    taking the user's password, running it through the KDF, then comparing it
    to the stored value), while attackers will need to do it billions of times.
    Ideal password storage KDFs will be demanding on both computational and
    memory resources.

.. class:: PBKDF2HMAC(algorithm, length, salt, iterations, backend):

    .. versionadded:: 0.2

    `PBKDF2`_ (Password Based Key Derivation Function 2) is typically used for
    deriving a cryptographic key from a password. It may also be used for
    key storage, but an alternate key storage KDF such as `scrypt` is generally
    considered a better solution.

    This class conforms to the
    :class:`~cryptography.hazmat.primitives.interfaces.KeyDerivationFunction`
    interface.

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives import hashes
        >>> from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        >>> from cryptography.hazmat.backends import default_backend
        >>> backend = default_backend()
        >>> salt = os.urandom(16)
        >>> # derive
        >>> kdf = PBKDF2HMAC(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     salt=salt,
        ...     iterations=100000,
        ...     backend=backend
        ... )
        >>> key = kdf.derive(b"my great password")
        >>> # verify
        >>> kdf = PBKDF2HMAC(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     salt=salt,
        ...     iterations=100000,
        ...     backend=backend
        ... )
        >>> kdf.verify(b"my great password", key)

    :param algorithm: An instance of a
        :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
        provider.
    :param int length: The desired length of the derived key. Maximum is
        (2\ :sup:`32` - 1) * ``algorithm.digest_size``.
    :param bytes salt: A salt. `NIST SP 800-132`_ recommends 128-bits or
        longer.
    :param int iterations: The number of iterations to perform of the hash
        function. This can be used to control the length of time the operation
        takes. Higher numbers help mitigate brute force attacks against derived
        keys. See OWASP's `Password Storage Cheat Sheet`_ for more
        detailed recommendations if you intend to use this for password storage.
    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.CipherBackend`
        provider.

    .. method:: derive(key_material)

        :param key_material bytes: The input key material. For PBKDF2 this
            should be a password.
        :return: The new key.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive` or
                                                          :meth:`verify` is
                                                          called more than
                                                          once.

        This generates and returns a new key from the supplied password.

    .. method:: verify(key_material, expected_key)

        :param key_material bytes: The input key material. This is the same as
                                   ``key_material`` in :meth:`derive`.
        :param expected_key bytes: The expected result of deriving a new key,
                                   this is the same as the return value of
                                   :meth:`derive`.
        :raises cryptography.exceptions.InvalidKey: This is raised when the
                                                    derived key does not match
                                                    the expected key.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive` or
                                                          :meth:`verify` is
                                                          called more than
                                                          once.

        This checks whether deriving a new key from the supplied
        ``key_material`` generates the same key as the ``expected_key``, and
        raises an exception if they do not match. This can be used for
        checking whether the password a user provides matches the stored derived
        key.

.. _`NIST SP 800-132`: http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf
.. _`Password Storage Cheat Sheet`: https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
.. _`PBKDF2`: http://en.wikipedia.org/wiki/PBKDF2
.. _`scrypt`: http://en.wikipedia.org/wiki/Scrypt
.. _`key stretching`: http://en.wikipedia.org/wiki/Key_stretching
