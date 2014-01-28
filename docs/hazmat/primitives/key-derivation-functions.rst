.. hazmat::

Key Derivation Functions
========================

.. currentmodule:: cryptography.hazmat.primitives.kdf

Key derivation functions derive key material from information such as passwords
using a pseudo-random function (PRF).

.. class:: PBKDF2(algorithm, length, salt, iterations, backend):

    .. doctest::

        >>> from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        >>> from cryptography.hazmat.backends import default_backend
        >>> backend = default_backend()
        >>> salt = os.urandom(16)
        >>> # derive
        >>> kdf = PBKDF2(hashes.SHA1(), 20, salt, 10000, backend)
        >>> key = kdf.derive(b"my great password")
        >>> # verify
        >>> kdf = PBKDF2(hashes.SHA1(), 20, salt, 10000, backend)
        >>> kdf.verify(b"my great password", key)
        None

        :param algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
            provider.

        :param int length: The desired length of the derived key. Maximum is
        2\ :sup:`31` - 1.

        :param bytes salt: A salt. `NIST SP 800-132`_ recommends 128-bits or
            longer.

        :param int iterations: The number of iterations to perform of the hash
            function.

.. _`NIST SP 800-132`: http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf
