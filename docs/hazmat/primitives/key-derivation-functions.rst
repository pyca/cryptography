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


PBKDF2
------

.. currentmodule:: cryptography.hazmat.primitives.kdf.pbkdf2

.. class:: PBKDF2HMAC(algorithm, length, salt, iterations, backend=None)

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
        ...     iterations=100000,
        ... )
        >>> key = kdf.derive(b"my great password")
        >>> # verify
        >>> kdf = PBKDF2HMAC(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     salt=salt,
        ...     iterations=100000,
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
    :param backend: An optional instance of
        :class:`~cryptography.hazmat.backends.interfaces.PBKDF2HMACBackend`.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if the
        provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.PBKDF2HMACBackend`

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

.. class:: Scrypt(salt, length, n, r, p, backend=None)

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
    :param backend: An optional instance of
        :class:`~cryptography.hazmat.backends.interfaces.ScryptBackend`.

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

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if the
        provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.ScryptBackend`

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

.. class:: ConcatKDFHash(algorithm, length, otherinfo, backend=None)

    .. versionadded:: 1.0

    ConcatKDFHash (Concatenation Key Derivation Function) is defined by the
    NIST Special Publication `NIST SP 800-56Ar2`_ document, to be used to
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

    :param backend: An optional instance of
        :class:`~cryptography.hazmat.backends.interfaces.HashBackend`.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised
        if the provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.HashBackend`

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


.. class:: ConcatKDFHMAC(algorithm, length, salt, otherinfo, backend=None)

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

    :param backend: An optional instance of
        :class:`~cryptography.hazmat.backends.interfaces.HMACBackend`.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if the
        provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.HMACBackend`

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

.. class:: HKDF(algorithm, length, salt, info, backend=None)

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
        bytes will be used.

    :param bytes info: Application specific context information.  If ``None``
        is explicitly passed an empty byte string will be used.

    :param backend: An optional instance of
        :class:`~cryptography.hazmat.backends.interfaces.HMACBackend`.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if the
        provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.HMACBackend`

    :raises TypeError: This exception is raised if ``salt`` or ``info`` is not
                       ``bytes``.

    .. method:: derive(key_material)

        :param key_material: The input key material.
        :type key_material: :term:`bytes-like`
        :return bytes: The derived key.
        :raises TypeError: This exception is raised if ``key_material`` is not
                           ``bytes``.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive` or
                                                          :meth:`verify` is
                                                          called more than
                                                          once.

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


.. class:: HKDFExpand(algorithm, length, info, backend=None)

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

    :param backend: An optional instance of
        :class:`~cryptography.hazmat.backends.interfaces.HMACBackend`.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if the
        provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.HMACBackend`
    :raises TypeError: This exception is raised if ``info`` is not ``bytes``.

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
            a ``unicode`` object

        This checks whether deriving a new key from the supplied
        ``key_material`` generates the same key as the ``expected_key``, and
        raises an exception if they do not match.


KBKDF
-----

.. currentmodule:: cryptography.hazmat.primitives.kdf.kbkdf

.. class:: KBKDFHMAC(algorithm, mode, length, rlen, llen, location,\
           label, context, fixed, backend=None)

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

    :param backend: An optional instance of
        :class:`~cryptography.hazmat.backends.interfaces.HMACBackend`.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised
        if the provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.HMACBackend`

    :raises TypeError: This exception is raised if ``label`` or ``context``
        is not ``bytes``. Also raised if ``rlen`` or ``llen`` is not ``int``.

    :raises ValueError: This exception is raised if ``rlen`` or ``llen``
        is greater than 4 or less than 1. This exception is also raised if
        you specify a ``label`` or ``context`` and ``fixed``.

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


X963KDF
-------

.. currentmodule:: cryptography.hazmat.primitives.kdf.x963kdf

.. class:: X963KDF(algorithm, length, otherinfo, backend=None)

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

    :param backend: An optional instance of
        :class:`~cryptography.hazmat.backends.interfaces.HashBackend`.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised
        if the provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.HashBackend`

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

.. _`NIST SP 800-132`: https://csrc.nist.gov/publications/detail/sp/800-132/final
.. _`NIST SP 800-108`: https://csrc.nist.gov/publications/detail/sp/800-108/final
.. _`NIST SP 800-56Ar2`: https://csrc.nist.gov/publications/detail/sp/800-56a/rev-2/final
.. _`ANSI X9.63:2001`: https://webstore.ansi.org
.. _`SEC 1 v2.0`: https://www.secg.org/sec1-v2.pdf
.. _`more detailed description`: https://security.stackexchange.com/a/3993/43116
.. _`PBKDF2`: https://en.wikipedia.org/wiki/PBKDF2
.. _`key stretching`: https://en.wikipedia.org/wiki/Key_stretching
.. _`HKDF`: https://en.wikipedia.org/wiki/HKDF
.. _`HKDF paper`: https://eprint.iacr.org/2010/264
.. _`here`: https://stackoverflow.com/a/30308723/1170681
.. _`recommends`: https://tools.ietf.org/html/rfc7914#section-2
.. _`The scrypt paper`: https://www.tarsnap.com/scrypt/scrypt.pdf
