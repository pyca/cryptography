.. hazmat::


Decrepit Symmetric algorithms
=============================

.. module:: cryptography.hazmat.decrepit.ciphers.algorithms

This module contains decrepit symmetric encryption algorithms. These
are algorithms that should not be used unless necessary for backwards
compatibility or interoperability with legacy systems. Their use is
**strongly discouraged**.

These algorithms require you to use a :class:`~cryptography.hazmat.primitives.ciphers.Cipher`
object along with the appropriate :mod:`~cryptography.hazmat.primitives.ciphers.modes`.

.. class:: ARC4(key)

    .. versionadded:: 43.0.0

    ARC4 (Alleged RC4) is a stream cipher with serious weaknesses in its
    initial stream output. Its use is strongly discouraged. ARC4 does not use
    mode constructions.

    :param key: The secret key. This must be kept secret. Either ``40``,
        ``56``, ``64``, ``80``, ``128``, ``192``, or ``256`` :term:`bits` in
        length.
    :type key: :term:`bytes-like`

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
        >>> from cryptography.hazmat.primitives.ciphers import Cipher, modes
        >>> key = os.urandom(16)
        >>> algorithm = ARC4(key)
        >>> cipher = Cipher(algorithm, mode=None)
        >>> encryptor = cipher.encryptor()
        >>> ct = encryptor.update(b"a secret message")
        >>> decryptor = cipher.decryptor()
        >>> decryptor.update(ct)
        b'a secret message'

.. class:: TripleDES(key)

    .. versionadded:: 43.0.0

    Triple DES (Data Encryption Standard), sometimes referred to as 3DES, is a
    block cipher standardized by NIST. Triple DES has known crypto-analytic
    flaws, however none of them currently enable a practical attack.
    Nonetheless, Triple DES is not recommended for new applications because it
    is incredibly slow; old applications should consider moving away from it.

    :param key: The secret key. This must be kept secret. Either ``64``,
        ``128``, or ``192`` :term:`bits` long. DES only uses ``56``, ``112``,
        or ``168`` bits of the key as there is a parity byte in each component
        of the key.  Some writing refers to there being up to three separate
        keys that are each ``56`` bits long, they can simply be concatenated
        to produce the full key.
    :type key: :term:`bytes-like`

.. class:: CAST5(key)

    .. versionadded:: 43.0.0

    CAST5 (also known as CAST-128) is a block cipher approved for use in the
    Canadian government by the `Communications Security Establishment`_. It is
    a variable key length cipher and supports keys from 40-128 :term:`bits` in
    length.

    :param key: The secret key, This must be kept secret. 40 to 128
        :term:`bits` in length in increments of 8 bits.
    :type key: :term:`bytes-like`

    .. doctest::

        >>> import os
        >>> from cryptography.hazmat.decrepit.ciphers.algorithms import CAST5
        >>> from cryptography.hazmat.primitives.ciphers import Cipher, modes
        >>> key = os.urandom(16)
        >>> iv = os.urandom(8)
        >>> algorithm = CAST5(key)
        >>> cipher = Cipher(algorithm, modes.CBC(iv))
        >>> encryptor = cipher.encryptor()
        >>> ct = encryptor.update(b"a secret message")
        >>> decryptor = cipher.decryptor()
        >>> decryptor.update(ct)
        b'a secret message'

.. class:: SEED(key)

    .. versionadded:: 43.0.0

    SEED is a block cipher developed by the Korea Information Security Agency
    (KISA). It is defined in :rfc:`4269` and is used broadly throughout South
    Korean industry, but rarely found elsewhere.

    :param key: The secret key. This must be kept secret. ``128``
        :term:`bits` in length.
    :type key: :term:`bytes-like`


.. class:: Blowfish(key)

    .. versionadded:: 43.0.0

    Blowfish is a block cipher developed by Bruce Schneier. It is known to be
    susceptible to attacks when using weak keys. The author has recommended
    that users of Blowfish move to newer algorithms.

    :param key: The secret key. This must be kept secret. 32 to 448
        :term:`bits` in length in increments of 8 bits.
    :type key: :term:`bytes-like`

.. class:: IDEA(key)

    .. versionadded:: 43.0.0

    IDEA (`International Data Encryption Algorithm`_) is a block cipher created
    in 1991. It is an optional component of the `OpenPGP`_ standard. This cipher
    is susceptible to attacks when using weak keys. It is recommended that you
    do not use this cipher for new applications.

    :param key: The secret key. This must be kept secret. ``128``
        :term:`bits` in length.
    :type key: :term:`bytes-like`



.. _`Communications Security Establishment`: https://www.cse-cst.gc.ca
.. _`International Data Encryption Algorithm`: https://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm
.. _`OpenPGP`: https://www.openpgp.org/
