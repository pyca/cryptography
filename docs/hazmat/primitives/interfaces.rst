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
