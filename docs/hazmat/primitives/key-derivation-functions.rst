.. hazmat::

Key Derivation Functions
========================

.. currentmodule:: cryptography.hazmat.primitives.kdf

Key derivation functions derive key material from information such as passwords
using a pseudo-random function (PRF).

.. class:: PBKDF2HMAC(algorithm, length, salt, iterations, backend):

    .. versionadded:: 0.2

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
        ...     iterations=50000,
        ...     backend=backend
        ... )
        >>> key = kdf.derive(b"my great password")
        >>> # verify
        >>> kdf = PBKDF2HMAC(
        ...     algorithm=hashes.SHA256(),
        ...     length=32,
        ...     salt=salt,
        ...     iterations=50000,
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
        function. See OWASP's `Password Storage Cheat Sheet`_ for more
        detailed recommendations.
    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.CipherBackend`
        provider.

.. _`NIST SP 800-132`: http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf
.. _`Password Storage Cheat Sheet`: https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
