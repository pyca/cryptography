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

    .. versionadded:: 0.2

    An `RSA`_ private key.

    .. method:: public_key()

        :return: :class:`~cryptography.hazmat.primitives.interfaces.RSAPublicKey`

        An RSA public key object corresponding to the values of the private key.

    .. attribute:: modulus

        :type: int

        The public modulus.

    .. attribute:: public_exponent

        :type: int

        The public exponent.

    .. attribute:: key_length

        :type: int

        The bit length of the modulus.

    .. attribute:: p

        :type: int

        ``p``, one of the two primes composing the :attr:`modulus`.

    .. attribute:: q

        :type: int

        ``q``, one of the two primes composing the :attr:`modulus`.

    .. attribute:: d

        :type: int

        The private exponent.

    .. attribute:: n

        :type: int

        The public modulus. Alias for :attr:`modulus`.

    .. attribute:: e

        :type: int

        The public exponent. Alias for :attr:`public_exponent`.


.. class:: RSAPublicKey

    .. versionadded:: 0.2

    An `RSA`_ public key.

    .. attribute:: modulus

        :type: int

        The public modulus.

    .. attribute:: key_length

        :type: int

        The bit length of the modulus.

    .. attribute:: public_exponent

        :type: int

        The public exponent.

    .. attribute:: n

        :type: int

        The public modulus. Alias for :attr:`modulus`.

    .. attribute:: e

        :type: int

        The public exponent. Alias for :attr:`public_exponent`.


Key Derivation Functions
~~~~~~~~~~~~~~~~~~~~~~~~

.. class:: KeyDerivationFunction

    .. method:: derive(key_material)

        :param key_material bytes: The input key material. Depending on what
                                   key derivation function you are using this
                                   could be either random material, or a user
                                   supplied password.
        :return: The new key.

        This generates and returns a new key from the supplied key material.

    .. method:: verify(key_material, expected_key)

        :param key_material bytes: The input key material. This is the same as
                                   ``key_material`` in :meth:`derive`.
        :param expected_key bytes: The expected result of deriving a new key,
                                   this is the same as the return value of
                                   :meth:`derive`.
        :raises cryptography.exceptions.InvalidKey: This is raised when the
                                                    derived key does not match
                                                    the expected key.

        This checks whether deriving a new key from the supplied
        ``key_material`` generates the same key as the ``expected_key``, and
        raises an exception if they do not match. This can be used for
        something like checking whether a user's password attempt matches the
        stored derived key.

.. _`RSA`: http://en.wikipedia.org/wiki/RSA_(cryptosystem)
