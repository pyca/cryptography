.. hazmat::

Key derivation functions
========================

.. module:: cryptography.hazmat.primitives.kdf

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


Variable cost algorithms
~~~~~~~~~~~~~~~~~~~~~~~~

Argon2 Family
-------------

.. currentmodule:: cryptography.hazmat.primitives.kdf.argon2

The Argon2 family of key derivation functions are designed for password storage and is described in :rfc:`9106`.
It consists of three variants that differ only how they access an internal memory buffer, which leads to different
trade-offs in resistance to hardware attacks.

Each of the classes constructors and parameters are the same; only details of Argon2id are defined before, for brevity.

.. class:: Argon2d(*, salt, length, iterations, lanes, memory_cost, ad=None, secret=None)

    .. versionadded:: 46.0.4

    This variant of the Argon2 family maximizes resistance to time-memory-trade-off attacks, but introduces possible side-channels


.. class:: Argon2i(*, salt, length, iterations, lanes, memory_cost, ad=None, secret=None)

    .. versionadded:: 46.0.4

    This variant of the Argon2 family resists side-channel attacks, but is vulernable to tim time-memory-trade-off attacks


.. class:: Argon2id(*, salt, length, iterations, lanes, memory_cost, ad=None, secret=None)

    .. versionadded:: 44.0.0

    Argon2id is a blend of the previous two variants.  Argon2id should be used by most users, as recommended in :rfc:`9106`.

    This class conforms to the
    :class:`~cryptography.hazmat.primitives.kdf.KeyDerivationFunction`
    interface.

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        >>> salt = os.urandom(16)
        >>> # derive
        >>> kdf = Argon2id(
        ...     salt=salt,
        ...     length=32,
        ...     iterations=1,
        ...     lanes=4,
        ...     memory_cost=64 * 1024,
        ...     ad=None,
        ...     secret=None,
        ... )
        >>> key = kdf.derive(b"my great password")
        >>> # verify
        >>> kdf = Argon2id(
        ...     salt=salt,
        ...     length=32,
        ...     iterations=1,
        ...     lanes=4,
        ...     memory_cost=64 * 1024,
        ...     ad=None,
        ...     secret=None,
        ... )
        >>> kdf.verify(b"my great password", key)

    **All arguments to the constructor are keyword-only.**

    :param bytes salt: A salt should be unique (and randomly generated) per
        password and is recommended to be 16 bytes or longer
    :param int length: The desired length of the derived key in bytes.
    :param int iterations: Also known as passes, this is used to tune
        the running time independently of the memory size.
    :param int lanes: The number of lanes (parallel threads) to use. Also
        known as parallelism.
    :param int memory_cost: The amount of memory to use in kibibytes.
        1 kibibyte (KiB) is 1024 bytes. This must be at minimum ``8 * lanes``.
    :param bytes ad: Optional associated data.
    :param bytes secret: Optional secret data; used for keyed hashing.

    :rfc:`9106` has recommendations for `parameter choice`_.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If Argon2id is not
        supported by the OpenSSL version ``cryptography`` is using.

    .. method:: derive(key_material)

        :param key_material: The input key material.
        :type key_material: :term:`bytes-like`
        :return bytes: the derived key.
        :raises TypeError: This exception is raised if ``key_material`` is not
                           ``bytes``.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive` or
                                                          :meth:`verify` is
                                                          called more than
                                                          once.

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

    .. method:: derive_phc_encoded(key_material)

        .. versionadded:: 45.0.0

        :param key_material: The input key material.
        :type key_material: :term:`bytes-like`
        :return str: A PHC-formatted string containing the parameters, salt, and derived key.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          any method is
                                                          called more than
                                                          once.

        This method generates and returns a new key from the supplied password,
        formatting the result as a string according to the Password Hashing
        Competition (PHC) format. The returned string includes the algorithm,
        all parameters, the salt, and the derived key in a standardized format:
        ``$argon2id$v=19$m=<memory_cost>,t=<iterations>,p=<lanes>$<salt>$<key>``

        This format is suitable for password storage and is compatible with other
        Argon2id implementations that support the PHC format.

    .. classmethod:: verify_phc_encoded(key_material, phc_encoded, secret=None)

        .. versionadded:: 45.0.0

        :param bytes key_material: The input key material. This is the same as
                                   ``key_material`` in :meth:`derive_phc_encoded`.
        :param str phc_encoded: A PHC-formatted string as returned by
                                :meth:`derive_phc_encoded`.
        :param bytes secret: Optional secret data; used for keyed hashing.
        :raises cryptography.exceptions.InvalidKey: This is raised when the
                                                    derived key does not match
                                                    the key in the encoded string
                                                    or when the format of the
                                                    encoded string is invalid.

        This class method verifies whether the supplied ``key_material`` matches
        the key contained in the PHC-formatted string. It extracts the parameters
        from the string, recomputes the key with those parameters, and compares
        the result to the key in the string.

        This is useful for validating a password against a stored PHC-formatted
        hash string.

        .. doctest::

            >>> import os
            >>> from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
            >>> salt = os.urandom(16)
            >>> # Create an Argon2id instance and derive a PHC-formatted string
            >>> kdf = Argon2id(
            ...     salt=salt,
            ...     length=32,
            ...     iterations=1,
            ...     lanes=4,
            ...     memory_cost=64 * 1024,
            ... )
            >>> encoded = kdf.derive_phc_encoded(b"my great password")
            >>> # later, verify the password
            >>> Argon2id.verify_phc_encoded(b"my great password", encoded)


PBKDF2
------

.. currentmodule:: cryptography.hazmat.primitives.kdf.pbkdf2

.. class:: PBKDF2HMAC(algorithm, length, salt, iterations)

    .. versionadded:: 0.2

    `PBKDF2`_ (Password Based Key Derivation Function 2) is typically used for
    deriving a cryptographic key from a password. It may also be used for
    key storage, but an alternate key storage KDF such as
    :class:`~cryptography.hazmat.primitives.kdf.scrypt.Scrypt` is generally
    considered a better solution.

    This class conforms to the
    :class:`~cryptography.hazmat.primitives.kdf.KeyDerivationFunction`
    interface.

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives import hashes
        >>> from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        >>> # Salts should be randomly generated
        >>> salt = os.urandom(16)
        >>> # derive
        >>> kdf = PBKDF2HMAC(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     salt=salt,
        ...     iterations=1_200_000,
        ... )
        >>> key = kdf.derive(b"my great password")
        >>> # verify
        >>> kdf = PBKDF2HMAC(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     salt=salt,
        ...     iterations=1_200_000,
        ... )
        >>> kdf.verify(b"my great password", key)

    :param algorithm: An instance of
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.
    :param int length: The desired length of the derived key in bytes. Maximum
        is (2\ :sup:`32` - 1) * ``algorithm.digest_size``.
    :param bytes salt: A salt. Secure values [#nist]_ are 128-bits (16 bytes)
        or longer and randomly generated.
    :param int iterations: The number of iterations to perform of the hash
        function. This can be used to control the length of time the operation
        takes. Higher numbers help mitigate brute force attacks against derived
        keys. A `more detailed description`_ can be consulted for additional
        information.

    :raises TypeError: This exception is raised if ``salt`` is not ``bytes``.

    .. method:: derive(key_material)

        :param key_material: The input key material. For PBKDF2 this
            should be a password.
        :type key_material: :term:`bytes-like`
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


Scrypt
------

.. currentmodule:: cryptography.hazmat.primitives.kdf.scrypt

.. class:: Scrypt(salt, length, n, r, p)

    .. versionadded:: 1.6

    Scrypt is a KDF designed for password storage by Colin Percival to be
    resistant against hardware-assisted attackers by having a tunable memory
    cost. It is described in :rfc:`7914`.

    This class conforms to the
    :class:`~cryptography.hazmat.primitives.kdf.KeyDerivationFunction`
    interface.

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        >>> salt = os.urandom(16)
        >>> # derive
        >>> kdf = Scrypt(
        ...     salt=salt,
        ...     length=32,
        ...     n=2**14,
        ...     r=8,
        ...     p=1,
        ... )
        >>> key = kdf.derive(b"my great password")
        >>> # verify
        >>> kdf = Scrypt(
        ...     salt=salt,
        ...     length=32,
        ...     n=2**14,
        ...     r=8,
        ...     p=1,
        ... )
        >>> kdf.verify(b"my great password", key)

    :param bytes salt: A salt.
    :param int length: The desired length of the derived key in bytes.
    :param int n: CPU/Memory cost parameter. It must be larger than 1 and be a
        power of 2.
    :param int r: Block size parameter.
    :param int p: Parallelization parameter.

    The computational and memory cost of Scrypt can be adjusted by manipulating
    the 3 parameters: ``n``, ``r``, and ``p``. In general, the memory cost of
    Scrypt is affected by the values of both ``n`` and ``r``, while ``n`` also
    determines the number of iterations performed. ``p`` increases the
    computational cost without affecting memory usage. A more in-depth
    explanation of the 3 parameters can be found `here`_.

    :rfc:`7914` `recommends`_ values of ``r=8`` and ``p=1`` while scaling ``n``
    to a number appropriate for your system. `The scrypt paper`_ suggests a
    minimum value of ``n=2**14`` for interactive logins (t < 100ms), or
    ``n=2**20`` for more sensitive files (t < 5s).

    :raises cryptography.exceptions.UnsupportedAlgorithm: If Scrypt is not
        supported by the OpenSSL version ``cryptography`` is using.

    :raises TypeError: This exception is raised if ``salt`` is not ``bytes``.
    :raises ValueError: This exception is raised if ``n`` is less than 2, if
        ``n`` is not a power of 2, if ``r`` is less than 1 or if ``p`` is less
        than 1.

    .. method:: derive(key_material)

        :param key_material: The input key material.
        :type key_material: :term:`bytes-like`
        :return bytes: the derived key.
        :raises TypeError: This exception is raised if ``key_material`` is not
                           ``bytes``.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive` or
                                                          :meth:`verify` is
                                                          called more than
                                                          once.

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

Fixed cost algorithms
~~~~~~~~~~~~~~~~~~~~~


ConcatKDF
---------

.. currentmodule:: cryptography.hazmat.primitives.kdf.concatkdf

.. class:: ConcatKDFHash(algorithm, length, otherinfo)

    .. versionadded:: 1.0

    ConcatKDFHash (Concatenation Key Derivation Function) is defined by the
    NIST Special Publication `NIST SP 800-56Ar3`_ document, to be used to
    derive keys for use after a Key Exchange negotiation operation.

    .. warning::

        ConcatKDFHash should not be used for password storage.

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives import hashes
        >>> from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
        >>> otherinfo = b"concatkdf-example"
        >>> ckdf = ConcatKDFHash(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     otherinfo=otherinfo,
        ... )
        >>> key = ckdf.derive(b"input key")
        >>> ckdf = ConcatKDFHash(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     otherinfo=otherinfo,
        ... )
        >>> ckdf.verify(b"input key", key)

    :param algorithm: An instance of
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.

    :param int length: The desired length of the derived key in bytes.
        Maximum is ``hashlen * (2^32 -1)``.

    :param bytes otherinfo: Application specific context information.
        If ``None`` is explicitly passed an empty byte string will be used.

    :raises TypeError: This exception is raised if ``otherinfo`` is not
        ``bytes``.

    .. method:: derive(key_material)

        :param key_material: The input key material.
        :type key_material: :term:`bytes-like`
        :return bytes: The derived key.
        :raises TypeError: This exception is raised if ``key_material`` is
                            not ``bytes``.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive` or
                                                          :meth:`verify` is
                                                          called more than
                                                          once.

        Derives a new key from the input key material.

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


.. class:: ConcatKDFHMAC(algorithm, length, salt, otherinfo)

    .. versionadded:: 1.0

    Similar to ConcatKFDHash but uses an HMAC function instead.

    .. warning::

        ConcatKDFHMAC should not be used for password storage.

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives import hashes
        >>> from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHMAC
        >>> salt = os.urandom(16)
        >>> otherinfo = b"concatkdf-example"
        >>> ckdf = ConcatKDFHMAC(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     salt=salt,
        ...     otherinfo=otherinfo,
        ... )
        >>> key = ckdf.derive(b"input key")
        >>> ckdf = ConcatKDFHMAC(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     salt=salt,
        ...     otherinfo=otherinfo,
        ... )
        >>> ckdf.verify(b"input key", key)

    :param algorithm: An instance of
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.

    :param int length: The desired length of the derived key in bytes. Maximum
        is ``hashlen * (2^32 -1)``.

    :param bytes salt: A salt. Randomizes the KDF's output. Optional, but
        highly recommended. Ideally as many bits of entropy as the security
        level of the hash: often that means cryptographically random and as
        long as the hash output. Does not have to be secret, but may cause
        stronger security guarantees if secret; If ``None`` is explicitly
        passed a default salt of ``algorithm.block_size`` null bytes will be
        used.

    :param bytes otherinfo: Application specific context information.
        If ``None`` is explicitly passed an empty byte string will be used.

    :raises TypeError: This exception is raised if ``salt`` or ``otherinfo``
        is not ``bytes``.

    .. method:: derive(key_material)

        :param bytes key_material: The input key material.
        :return bytes: The derived key.
        :raises TypeError: This exception is raised if ``key_material`` is not
                           ``bytes``.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive` or
                                                          :meth:`verify` is
                                                          called more than
                                                          once.

        Derives a new key from the input key material.

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


HKDF
----

.. currentmodule:: cryptography.hazmat.primitives.kdf.hkdf

.. class:: HKDF(algorithm, length, salt, info)

    .. versionadded:: 0.2

    `HKDF`_ (HMAC-based Extract-and-Expand Key Derivation Function) is suitable
    for deriving keys of a fixed size used for other cryptographic operations.

    .. warning::

        HKDF should not be used for password storage.

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives import hashes
        >>> from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        >>> salt = os.urandom(16)
        >>> info = b"hkdf-example"
        >>> hkdf = HKDF(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     salt=salt,
        ...     info=info,
        ... )
        >>> key = hkdf.derive(b"input key")
        >>> hkdf = HKDF(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     salt=salt,
        ...     info=info,
        ... )
        >>> hkdf.verify(b"input key", key)

    :param algorithm: An instance of
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.

    :param int length: The desired length of the derived key in bytes. Maximum
        is ``255 * (algorithm.digest_size // 8)``.

    :param bytes salt: A salt. Randomizes the KDF's output. Optional, but
        highly recommended. Ideally as many bits of entropy as the security
        level of the hash: often that means cryptographically random and as
        long as the hash output. Worse (shorter, less entropy) salt values can
        still meaningfully contribute to security. May be reused. Does not have
        to be secret, but may cause stronger security guarantees if secret; see
        :rfc:`5869` and the `HKDF paper`_ for more details. If ``None`` is
        explicitly passed a default salt of ``algorithm.digest_size // 8`` null
        bytes will be used. See `understanding HKDF`_ for additional detail about
        the salt and info parameters.

    :param bytes info: Application specific context information.  If ``None``
        is explicitly passed an empty byte string will be used.

    :raises TypeError: This exception is raised if ``salt`` or ``info`` is not
                       ``bytes``.

    .. staticmethod:: extract(algorithm, salt, key_material)

        .. versionadded:: 47.0.0

        .. note::
            Extract is a component of the complete HKDF algorithm.
            Unless needed for implementing an existing protocol, users
            should ignore this method and use call :meth:`derive`.

        :param algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.
        :param bytes salt: A salt. Randomizes the KDF's output. Optional, but
            highly recommended. Ideally as many bits of entropy as the security
            level of the hash: often that means cryptographically random and as
            long as the hash output. Worse (shorter, less entropy) salt values can
            still meaningfully contribute to security. May be reused. Does not have
            to be secret, but may cause stronger security guarantees if secret; see
            :rfc:`5869` and the `HKDF paper`_ for more details. If ``None`` is
            explicitly passed a default salt of ``algorithm.digest_size // 8`` null
            bytes will be used. See `understanding HKDF`_ for additional detail about
            the salt and info parameters.
        :param key_material: The input key material.
        :type key_material: :term:`bytes-like`
        :return bytes: The extracted value.
        :raises TypeError: This exception is raised if ``key_material``, ``salt``, or
            ``algorithm`` are the wrong type.

    .. method:: derive(key_material)

        :param key_material: The input key material.
        :type key_material: :term:`bytes-like`
        :return bytes: The derived key.
        :raises TypeError: This exception is raised if ``key_material`` is not
                           ``bytes``.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive`,
                                                          :meth:`derive_into`,
                                                          or :meth:`verify` is
                                                          called more than
                                                          once.

        Derives a new key from the input key material by performing both the
        extract and expand operations.

    .. method:: derive_into(key_material, buffer)

        .. versionadded:: 47.0.0

        :param key_material: The input key material.
        :type key_material: :term:`bytes-like`
        :param buffer: A writable buffer to write the derived key into.
        :return int: The number of bytes written to the buffer.
        :raises TypeError: This exception is raised if ``key_material`` is not
                           ``bytes``.
        :raises ValueError: This exception is raised if the buffer is too small
                           for the derived key.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive`,
                                                          :meth:`derive_into`,
                                                          or :meth:`verify` is
                                                          called more than
                                                          once.

        Derives a new key from the input key material by performing both the
        extract and expand operations, writing the result into the provided
        buffer.

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
                                                          :meth:`derive`,
                                                          :meth:`derive_into`,
                                                          or :meth:`verify` is
                                                          called more than
                                                          once.

        This checks whether deriving a new key from the supplied
        ``key_material`` generates the same key as the ``expected_key``, and
        raises an exception if they do not match.


.. class:: HKDFExpand(algorithm, length, info)

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
        >>> info = b"hkdf-example"
        >>> key_material = os.urandom(16)
        >>> hkdf = HKDFExpand(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     info=info,
        ... )
        >>> key = hkdf.derive(key_material)
        >>> hkdf = HKDFExpand(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     info=info,
        ... )
        >>> hkdf.verify(key_material, key)

    :param algorithm: An instance of
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.

    :param int length: The desired length of the derived key in bytes. Maximum
        is ``255 * (algorithm.digest_size // 8)``.

    :param bytes info: Application specific context information.  If ``None``
        is explicitly passed an empty byte string will be used.

    :raises TypeError: This exception is raised if ``info`` is not ``bytes``.

    .. method:: derive(key_material)

        :param bytes key_material: The input key material.
        :return bytes: The derived key.

        :raises TypeError: This exception is raised if ``key_material`` is not
                           ``bytes``.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive`,
                                                          :meth:`derive_into`,
                                                          or :meth:`verify` is
                                                          called more than
                                                          once.

        Derives a new key from the input key material by only performing the
        expand operation.

    .. method:: derive_into(key_material, buffer)

        .. versionadded:: 47.0.0

        :param bytes key_material: The input key material.
        :param buffer: A writable buffer to write the derived key into.
        :return int: The number of bytes written to the buffer.
        :raises TypeError: This exception is raised if ``key_material`` is not
                           ``bytes``.
        :raises ValueError: This exception is raised if the buffer is too small
                           for the derived key.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive`,
                                                          :meth:`derive_into`,
                                                          or :meth:`verify` is
                                                          called more than
                                                          once.

        Derives a new key from the input key material by only performing the
        expand operation, writing the result into the provided buffer.

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
                                                          :meth:`derive`,
                                                          :meth:`derive_into`,
                                                          or :meth:`verify` is
                                                          called more than
                                                          once.
        :raises TypeError: This is raised if the provided ``key_material`` is
            a ``unicode`` object

        This checks whether deriving a new key from the supplied
        ``key_material`` generates the same key as the ``expected_key``, and
        raises an exception if they do not match.


KBKDF
-----

.. currentmodule:: cryptography.hazmat.primitives.kdf.kbkdf

.. class:: KBKDFHMAC(algorithm, mode, length, rlen, llen, location,\
           label, context, fixed)

    .. versionadded:: 1.4

    KBKDF (Key Based Key Derivation Function) is defined by the
    `NIST SP 800-108`_ document, to be used to derive additional
    keys from a key that has been established through an automated
    key-establishment scheme.

    .. warning::

        KBKDFHMAC should not be used for password storage.

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives import hashes
        >>> from cryptography.hazmat.primitives.kdf.kbkdf import (
        ...    CounterLocation, KBKDFHMAC, Mode
        ... )
        >>> label = b"KBKDF HMAC Label"
        >>> context = b"KBKDF HMAC Context"
        >>> kdf = KBKDFHMAC(
        ...     algorithm=hashes.SHA256(),
        ...     mode=Mode.CounterMode,
        ...     length=32,
        ...     rlen=4,
        ...     llen=4,
        ...     location=CounterLocation.BeforeFixed,
        ...     label=label,
        ...     context=context,
        ...     fixed=None,
        ... )
        >>> key = kdf.derive(b"input key")
        >>> kdf = KBKDFHMAC(
        ...     algorithm=hashes.SHA256(),
        ...     mode=Mode.CounterMode,
        ...     length=32,
        ...     rlen=4,
        ...     llen=4,
        ...     location=CounterLocation.BeforeFixed,
        ...     label=label,
        ...     context=context,
        ...     fixed=None,
        ... )
        >>> kdf.verify(b"input key", key)

    :param algorithm: An instance of
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.

    :param mode: The desired mode of the PRF. A value from the
      :class:`~cryptography.hazmat.primitives.kdf.kbkdf.Mode` enum.

    :param int length: The desired length of the derived key in bytes.

    :param int rlen: An integer that indicates the length of the binary
        representation of the counter in bytes.

    :param int llen: An integer that indicates the binary
        representation of the ``length`` in bytes.

    :param location: The desired location of the counter. A value from the
      :class:`~cryptography.hazmat.primitives.kdf.kbkdf.CounterLocation` enum.

    :param bytes label: Application specific label information. If ``None``
        is explicitly passed an empty byte string will be used.

    :param bytes context: Application specific context information. If ``None``
        is explicitly passed an empty byte string will be used.

    :param bytes fixed: Instead of specifying ``label`` and ``context`` you
        may supply your own fixed data. If ``fixed`` is specified, ``label``
        and ``context`` is ignored.

    :param int break_location: A keyword-only argument. An integer that
        indicates the bytes offset where counter bytes are to be located.
        Required when ``location`` is
        :attr:`~cryptography.hazmat.primitives.kdf.kbkdf.CounterLocation.MiddleFixed`.

    :raises TypeError: This exception is raised if ``label`` or ``context``
        is not ``bytes``. Also raised if ``rlen``, ``llen``, or
        ``break_location`` is not ``int``.

    :raises ValueError: This exception is raised if ``rlen`` or ``llen``
        is greater than 4 or less than 1. This exception is also raised if
        you specify a ``label`` or ``context`` and ``fixed``. This exception
        is also raised if you specify ``break_location`` and ``location`` is not
        :attr:`~cryptography.hazmat.primitives.kdf.kbkdf.CounterLocation.MiddleFixed`.

    .. method:: derive(key_material)

        :param key_material: The input key material.
        :type key_material: :term:`bytes-like`
        :return bytes: The derived key.
        :raises TypeError: This exception is raised if ``key_material`` is
                            not ``bytes``.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive` or
                                                          :meth:`verify` is
                                                          called more than
                                                          once.

        Derives a new key from the input key material.

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

.. class:: KBKDFCMAC(algorithm, mode, length, rlen, llen, location,\
           label, context, fixed)

    .. versionadded:: 35.0.0

    KBKDF (Key Based Key Derivation Function) is defined by the
    `NIST SP 800-108`_ document, to be used to derive additional
    keys from a key that has been established through an automated
    key-establishment scheme.

    .. warning::

        KBKDFCMAC should not be used for password storage.

    .. doctest::

        >>> from cryptography.hazmat.primitives.ciphers import algorithms
        >>> from cryptography.hazmat.primitives.kdf.kbkdf import (
        ...    CounterLocation, KBKDFCMAC, Mode
        ... )
        >>> label = b"KBKDF CMAC Label"
        >>> context = b"KBKDF CMAC Context"
        >>> kdf = KBKDFCMAC(
        ...     algorithm=algorithms.AES,
        ...     mode=Mode.CounterMode,
        ...     length=32,
        ...     rlen=4,
        ...     llen=4,
        ...     location=CounterLocation.BeforeFixed,
        ...     label=label,
        ...     context=context,
        ...     fixed=None,
        ... )
        >>> key = kdf.derive(b"32 bytes long input key material")
        >>> kdf = KBKDFCMAC(
        ...     algorithm=algorithms.AES,
        ...     mode=Mode.CounterMode,
        ...     length=32,
        ...     rlen=4,
        ...     llen=4,
        ...     location=CounterLocation.BeforeFixed,
        ...     label=label,
        ...     context=context,
        ...     fixed=None,
        ... )
        >>> kdf.verify(b"32 bytes long input key material", key)

    :param algorithm: A class implementing a block cipher algorithm being a
        subclass of
        :class:`~cryptography.hazmat.primitives.ciphers.CipherAlgorithm` and
        :class:`~cryptography.hazmat.primitives.ciphers.BlockCipherAlgorithm`.

    :param mode: The desired mode of the PRF. A value from the
      :class:`~cryptography.hazmat.primitives.kdf.kbkdf.Mode` enum.

    :param int length: The desired length of the derived key in bytes.

    :param int rlen: An integer that indicates the length of the binary
        representation of the counter in bytes.

    :param int llen: An integer that indicates the binary
        representation of the ``length`` in bytes.

    :param location: The desired location of the counter. A value from the
      :class:`~cryptography.hazmat.primitives.kdf.kbkdf.CounterLocation` enum.

    :param bytes label: Application specific label information. If ``None``
        is explicitly passed an empty byte string will be used.

    :param bytes context: Application specific context information. If ``None``
        is explicitly passed an empty byte string will be used.

    :param bytes fixed: Instead of specifying ``label`` and ``context`` you
        may supply your own fixed data. If ``fixed`` is specified, ``label``
        and ``context`` is ignored.

    :param int break_location: A keyword-only argument. An integer that
        indicates the bytes offset where counter bytes are to be located.
        Required when ``location`` is
        :attr:`~cryptography.hazmat.primitives.kdf.kbkdf.CounterLocation.MiddleFixed`.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised
        if ``algorithm`` is not a subclass of
        :class:`~cryptography.hazmat.primitives.ciphers.CipherAlgorithm` and
        :class:`~cryptography.hazmat.primitives.ciphers.BlockCipherAlgorithm`.

    :raises TypeError: This exception is raised if ``label`` or ``context``
        is not ``bytes``, ``rlen``, ``llen``, or ``break_location`` is not
        ``int``, ``mode`` is not
        :class:`~cryptography.hazmat.primitives.kdf.kbkdf.Mode` or ``location``
        is not
        :class:`~cryptography.hazmat.primitives.kdf.kbkdf.CounterLocation`.

    :raises ValueError: This exception is raised if ``rlen`` or ``llen``
        is greater than 4 or less than 1. This exception is also raised if
        you specify a ``label`` or ``context`` and ``fixed``. This exception
        is also raised if you specify ``break_location`` and ``location`` is not
        :attr:`~cryptography.hazmat.primitives.kdf.kbkdf.CounterLocation.MiddleFixed`.

    .. method:: derive(key_material)

        :param key_material: The input key material.
        :type key_material: :term:`bytes-like`
        :return bytes: The derived key.
        :raises TypeError: This exception is raised if ``key_material`` is
                            not ``bytes``.
        :raises ValueError: This exception is raised if ``key_material`` is
                            not a valid key for ``algorithm`` passed to
                            :class:`~cryptography.hazmat.primitives.kdf.kbkdf.KBKDFCMAC`
                            constructor.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive` or
                                                          :meth:`verify` is
                                                          called more than
                                                          once.

        Derives a new key from the input key material.

    .. method:: verify(key_material, expected_key)

        :param bytes key_material: The input key material. This is the same as
                                   ``key_material`` in :meth:`derive`.
        :param bytes expected_key: The expected result of deriving a new key,
                                   this is the same as the return value of
                                   :meth:`derive`.
        :raises cryptography.exceptions.InvalidKey: This is raised when the
                                                    derived key does not match
                                                    the expected key.
        :raises: Exceptions raised by :meth:`derive`.

        This checks whether deriving a new key from the supplied
        ``key_material`` generates the same key as the ``expected_key``, and
        raises an exception if they do not match.

.. class:: Mode

    An enumeration for the key based key derivative modes.

    .. attribute:: CounterMode

        The output of the PRF is computed with a counter
        as the iteration variable.

.. class:: CounterLocation

    An enumeration for the key based key derivative counter location.

    .. attribute:: BeforeFixed

        The counter iteration variable will be concatenated before
        the fixed input data.

    .. attribute:: AfterFixed

        The counter iteration variable will be concatenated after
        the fixed input data.

    .. attribute:: MiddleFixed

        .. versionadded:: 38.0.0

        The counter iteration variable will be concatenated in the middle
        of the fixed input data.


X963KDF
-------

.. currentmodule:: cryptography.hazmat.primitives.kdf.x963kdf

.. class:: X963KDF(algorithm, length, otherinfo)

    .. versionadded:: 1.1

    X963KDF (ANSI X9.63 Key Derivation Function) is defined by ANSI
    in the `ANSI X9.63:2001`_ document, to be used to derive keys for use
    after a Key Exchange negotiation operation.

    SECG in `SEC 1 v2.0`_ recommends that
    :class:`~cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHash` be
    used for new projects. This KDF should only be used for backwards
    compatibility with pre-existing protocols.


    .. warning::

        X963KDF should not be used for password storage.

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.primitives import hashes
        >>> from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
        >>> sharedinfo = b"ANSI X9.63 Example"
        >>> xkdf = X963KDF(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     sharedinfo=sharedinfo,
        ... )
        >>> key = xkdf.derive(b"input key")
        >>> xkdf = X963KDF(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     sharedinfo=sharedinfo,
        ... )
        >>> xkdf.verify(b"input key", key)

    :param algorithm: An instance of
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`.

    :param int length: The desired length of the derived key in bytes.
        Maximum is ``hashlen * (2^32 -1)``.

    :param bytes sharedinfo: Application specific context information.
        If ``None`` is explicitly passed an empty byte string will be used.

    :raises TypeError: This exception is raised if ``sharedinfo`` is not
        ``bytes``.

    .. method:: derive(key_material)

        :param key_material: The input key material.
        :type key_material: :term:`bytes-like`
        :return bytes: The derived key.
        :raises TypeError: This exception is raised if ``key_material`` is
                            not ``bytes``.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive` or
                                                          :meth:`verify` is
                                                          called more than
                                                          once.

        Derives a new key from the input key material.

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


Interface
~~~~~~~~~

.. currentmodule:: cryptography.hazmat.primitives.kdf

.. class:: KeyDerivationFunction

    .. versionadded:: 0.2

    .. method:: derive(key_material)

        :param bytes key_material: The input key material. Depending on what
                                   key derivation function you are using this
                                   could be either random bytes, or a user
                                   supplied password.
        :return: The new key.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive` or
                                                          :meth:`verify` is
                                                          called more than
                                                          once.

        This generates and returns a new key from the supplied key material.

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
        something like checking whether a user's password attempt matches the
        stored derived key.


.. [#nist] See `NIST SP 800-132`_.

.. _`NIST SP 800-132`: https://csrc.nist.gov/pubs/sp/800/132/final
.. _`NIST SP 800-108`: https://csrc.nist.gov/pubs/sp/800/108/r1/final
.. _`NIST SP 800-56Ar3`: https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
.. _`ANSI X9.63:2001`: https://webstore.ansi.org
.. _`SEC 1 v2.0`: https://www.secg.org/sec1-v2.pdf
.. _`more detailed description`: https://security.stackexchange.com/a/3993/43116
.. _`PBKDF2`: https://en.wikipedia.org/wiki/PBKDF2
.. _`key stretching`: https://en.wikipedia.org/wiki/Key_stretching
.. _`HKDF`: https://en.wikipedia.org/wiki/HKDF
.. _`HKDF paper`: https://eprint.iacr.org/2010/264
.. _`here`: https://stackoverflow.com/a/30308723/1170681
.. _`recommends`: https://datatracker.ietf.org/doc/html/rfc7914#section-2
.. _`The scrypt paper`: https://www.tarsnap.com/scrypt/scrypt.pdf
.. _`understanding HKDF`: https://soatok.blog/2021/11/17/understanding-hkdf/
.. _`parameter choice`: https://datatracker.ietf.org/doc/html/rfc9106#section-4
