.. hazmat::

Key derivation functions
========================

.. currentmodule:: cryptography.hazmat.primitives.kdf

Key derivation functions derive bytes suitable for cryptographic operations
from passwords or other data sources using a pseudo-random function (PRF).
Different KDFs are suitable for different tasks such as:

* Cryptographic key derivation

    Deriving a key suitable for use as input to an encryption algorithm.
    Typically this means taking a password and running it through an algorithm
    such as :class:`~cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC` or
    :class:`~cryptography.hazmat.primitives.kdf.hkdf.HKDF`.
    This process is typically known as `key stretching`_.

* Password storage

    When storing passwords you want to use an algorithm that is computationally
    intensive. Legitimate users will only need to compute it once (for example,
    taking the user's password, running it through the KDF, then comparing it
    to the stored value), while attackers will need to do it billions of times.
    Ideal password storage KDFs will be demanding on both computational and
    memory resources.

.. currentmodule:: cryptography.hazmat.primitives.kdf.pbkdf2

.. class:: PBKDF2HMAC(algorithm, length, salt, iterations, backend)

    .. versionadded:: 0.2

    `PBKDF2`_ (Password Based Key Derivation Function 2) is typically used for
    deriving a cryptographic key from a password. It may also be used for
    key storage, but an alternate key storage KDF such as `scrypt`_ is generally
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
        :class:`~cryptography.hazmat.backends.interfaces.PBKDF2HMACBackend`
        provider.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if the
        provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.PBKDF2HMACBackend`

    :raises TypeError: This exception is raised if ``salt`` is not ``bytes``.

    .. method:: derive(key_material)

        :param bytes key_material: The input key material. For PBKDF2 this
            should be a password.
        :return bytes: the derived key.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive` or
                                                          :meth:`verify` is
                                                          called more than
                                                          once.

        :raises TypeError: This exception is raised if ``key_material`` is not
                           ``bytes``.

        This generates and returns a new key from the supplied password.

    .. method:: verify(key_material, expected_key)

        :param bytes key_material: The input key material. This is the same as
                                   ``key_material`` in :meth:`derive`.
        :param bytes expected_key: The expected result of deriving a new key,
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


.. currentmodule:: cryptography.hazmat.primitives.kdf.hkdf

.. class:: HKDF(algorithm, length, salt, info, backend)

    .. versionadded:: 0.2

    `HKDF`_ (HMAC-based Extract-and-Expand Key Derivation Function) is suitable
    for deriving keys of a fixed size used for other cryptographic operations.

    .. warning::

        HKDF should not be used for password storage.

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives import hashes
        >>> from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        >>> from cryptography.hazmat.backends import default_backend
        >>> backend = default_backend()
        >>> salt = os.urandom(16)
        >>> info = b"hkdf-example"
        >>> hkdf = HKDF(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     salt=salt,
        ...     info=info,
        ...     backend=backend
        ... )
        >>> key = hkdf.derive(b"input key")
        >>> hkdf = HKDF(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     salt=salt,
        ...     info=info,
        ...     backend=backend
        ... )
        >>> hkdf.verify(b"input key", key)

    :param algorithm: An instance of a
        :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
        provider.

    :param int length: The desired length of the derived key. Maximum is
        ``255 * (algorithm.digest_size // 8)``.

    :param bytes salt: A salt. Randomizes the KDF's output. Optional, but
        highly recommended. Ideally as many bits of entropy as the security
        level of the hash: often that means cryptographically random and as
        long as the hash output. Worse (shorter, less entropy) salt values can
        still meaningfully contribute to security. May be reused. Does not have
        to be secret, but may cause stronger security guarantees if secret; see
        `RFC 5869`_ and the `HKDF paper`_ for more details. If ``None`` is
        explicitly passed a default salt of ``algorithm.digest_size // 8`` null
        bytes will be used.

    :param bytes info: Application specific context information.  If ``None``
        is explicitly passed an empty byte string will be used.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.HMACBackend`
        provider.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if the
        provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.HMACBackend`

    :raises TypeError: This exception is raised if ``salt`` or ``info`` is not
                       ``bytes``.

    .. method:: derive(key_material)

        :param bytes key_material: The input key material.
        :return bytes: The derived key.
        :raises TypeError: This exception is raised if ``key_material`` is not
                           ``bytes``.

        Derives a new key from the input key material by performing both the
        extract and expand operations.

    .. method:: verify(key_material, expected_key)

        :param bytes key_material: The input key material. This is the same as
                                   ``key_material`` in :meth:`derive`.
        :param bytes expected_key: The expected result of deriving a new key,
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
        raises an exception if they do not match.


.. class:: HKDFExpand(algorithm, length, info, backend)

    .. versionadded:: 0.5

    HKDF consists of two stages, extract and expand. This class exposes an
    expand only version of HKDF that is suitable when the key material is
    already cryptographically strong.

    .. warning::

        HKDFExpand should only be used if the key material is
        cryptographically strong. You should use
        :class:`~cryptography.hazmat.primitives.kdf.hkdf.HKDF` if
        you are unsure.

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives import hashes
        >>> from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
        >>> from cryptography.hazmat.backends import default_backend
        >>> backend = default_backend()
        >>> info = b"hkdf-example"
        >>> key_material = os.urandom(16)
        >>> hkdf = HKDFExpand(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     info=info,
        ...     backend=backend
        ... )
        >>> key = hkdf.derive(key_material)
        >>> hkdf = HKDFExpand(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     info=info,
        ...     backend=backend
        ... )
        >>> hkdf.verify(key_material, key)

    :param algorithm: An instance of a
        :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
        provider.

    :param int length: The desired length of the derived key. Maximum is
        ``255 * (algorithm.digest_size // 8)``.

    :param bytes info: Application specific context information.  If ``None``
        is explicitly passed an empty byte string will be used.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.HMACBackend`
        provider.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if the
        provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.HMACBackend`
    :raises TypeError: This is raised if the provided ``info`` is a unicode object
    :raises TypeError: This exception is raised if ``info`` is not ``bytes``.

    .. method:: derive(key_material)

        :param bytes key_material: The input key material.
        :return bytes: The derived key.

        :raises TypeError: This is raised if the provided ``key_material`` is
            a unicode object
        :raises TypeError: This exception is raised if ``key_material`` is not
                           ``bytes``.

        Derives a new key from the input key material by performing both the
        extract and expand operations.

    .. method:: verify(key_material, expected_key)

        :param bytes key_material: The input key material. This is the same as
                                   ``key_material`` in :meth:`derive`.
        :param bytes expected_key: The expected result of deriving a new key,
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
        :raises TypeError: This is raised if the provided ``key_material`` is
            a unicode object

        This checks whether deriving a new key from the supplied
        ``key_material`` generates the same key as the ``expected_key``, and
        raises an exception if they do not match.

.. _`NIST SP 800-132`: http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf
.. _`Password Storage Cheat Sheet`: https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
.. _`PBKDF2`: https://en.wikipedia.org/wiki/PBKDF2
.. _`scrypt`: https://en.wikipedia.org/wiki/Scrypt
.. _`key stretching`: https://en.wikipedia.org/wiki/Key_stretching
.. _`HKDF`:
.. _`RFC 5869`: https://tools.ietf.org/html/rfc5869
.. _`HKDF paper`: https://eprint.iacr.org/2010/264
