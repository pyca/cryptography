.. hazmat::

Interfaces
==========


``cryptography`` uses `Abstract Base Classes`_ as interfaces to describe the
properties and methods of most primitive constructs. Backends may also use
this information to influence their operation. Interfaces should also be used
to document argument and return types.

.. _`Abstract Base Classes`: http://docs.python.org/3.2/library/abc.html


Symmetric Ciphers
~~~~~~~~~~~~~~~~~

.. currentmodule:: cryptography.hazmat.primitives.interfaces


.. class:: CipherAlgorithm

    A named symmetric encryption algorithm.

    .. attribute:: name

        :type: str

        The standard name for the mode, for example, "AES", "Camellia", or
        "Blowfish".

    .. attribute:: key_size

        :type: int

        The number of bits in the key being used.


.. class:: BlockCipherAlgorithm

    A block cipher algorithm.

    .. attribute:: block_size

        :type: int

        The number of bits in a block.


Cipher Modes
------------

Interfaces used by the symmetric cipher modes described in
:ref:`Symmetric Encryption Modes <symmetric-encryption-modes>`.

.. class:: Mode

    A named cipher mode.

    .. attribute:: name

        :type: str

        This should be the standard shorthand name for the mode, for example
        Cipher-Block Chaining mode is "CBC".

        The name may be used by a backend to influence the operation of a
        cipher in conjunction with the algorithm's name.

    .. method:: validate_for_algorithm(algorithm)

        :param CipherAlgorithm algorithm:

        Checks that the combination of this mode with the provided algorithm
        meets any necessary invariants. This should raise an exception if they
        are not met.

        For example, the :class:`~cryptography.hazmat.primitives.modes.CBC`
        mode uses this method to check that the provided initialization
        vector's length matches the block size of the algorithm.


.. class:: ModeWithInitializationVector

    A cipher mode with an initialization vector.

    .. attribute:: initialization_vector

        :type: bytes

        Exact requirements of the initialization are described by the
        documentation of individual modes.


.. class:: ModeWithNonce

    A cipher mode with a nonce.

    .. attribute:: nonce

        :type: bytes

        Exact requirements of the nonce are described by the documentation of
        individual modes.

Asymmetric Interfaces
~~~~~~~~~~~~~~~~~~~~~

.. class:: RSAPrivateKey

    An `RSA`_ private key.

    .. attribute:: public_key

        :type: :class:`~cryptography.hazmat.primitives.interfaces.RSAPublicKey`

        An RSA public key object corresponding to the values of the private key.

    .. attribute:: modulus

        :type: int

        The public modulus. Alias for ``n``.

    .. attribute:: public_exponent

        :type: int

        The public exponent. Alias for ``e``.

    .. attribute:: key_length

        :type: int

        The bit length of the modulus.

    .. attribute:: p

        :type: int

        ``p``, one of the two primes composing ``n``.

    .. attribute:: q

        :type: int

        ``q``, one of the two primes composing ``n``.

    .. attribute:: d

        :type: int

        The private exponent.

    .. attribute:: n

        :type: int

        The public modulus.

    .. attribute:: e

        :type: int

        The public exponent.


.. class:: RSAPublicKey

    An `RSA`_ public key.

    .. attribute:: modulus

        :type: int

        The public modulus. Alias for ``n``.

    .. attribute:: key_length

        :type: int

        The bit length of the modulus.

    .. attribute:: public_exponent

        :type: int

        The public exponent. Alias for ``e``.

    .. attribute:: n

        :type: int

        The public modulus.

    .. attribute:: e

        :type: int

        The public exponent.

.. _`RSA`: http://en.wikipedia.org/wiki/RSA_(cryptosystem)
