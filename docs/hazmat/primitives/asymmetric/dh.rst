.. hazmat::

Diffie-Hellman key exchange
===========================

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.dh


Numbers
~~~~~~~

.. class:: DHPrivateNumbers(x, public_numbers)

    .. versionadded:: 0.8

    The collection of integers that make up a Diffie-Hellman private key.

    .. attribute:: public_numbers

        :type: :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicNumbers`

        The :class:`DHPublicNumbers` which makes up the DH public
        key associated with this DH private key.

    .. attribute:: x

        :type: int

        The private value.


.. class:: DHPublicNumbers(parameters, y)

    .. versionadded:: 0.8

    The collection of integers that make up a Diffie-Hellman public key.

     .. attribute:: parameter_numbers

        :type: :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameterNumbers`

        The parameters for this DH group.

    .. attribute:: y

        :type: int

        The public value.


.. class:: DHParameterNumbers(p, g)

    .. versionadded:: 0.8

    The collection of integers that define a Diffie-Hellman group.

    .. attribute:: p

        :type: int

        The prime modulus value.

    .. attribute:: g

        :type: int

        The generator value.


Key interfaces
~~~~~~~~~~~~~~

.. class:: DHParameters

    .. versionadded:: 0.9


    .. method:: generate_private_key()

        .. versionadded:: 0.9

        Generate a DH private key. This method can be used to generate many
        new private keys from a single set of parameters.

        :return: A
            :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey`
            provider.


.. class:: DHParametersWithSerialization

    .. versionadded:: 0.9

    Inherits from :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters`.

    .. method:: parameter_numbers()

        Return the numbers that make up this set of parameters.

        :return: A :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameterNumbers`.


.. class:: DHPrivateKey

    .. versionadded:: 0.9

    .. attribute:: key_size

        The bit length of the prime modulus.

    .. method:: public_key()

        Return the public key associated with this private key.

        :return: A :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey`.

    .. method:: parameters()

        Return the parameters associated with this private key.

        :return: A :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters`.


.. class:: DHPrivateKeyWithSerialization

    .. versionadded:: 0.9

    Inherits from :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey`.

    .. method:: private_numbers()

        Return the numbers that make up this private key.

        :return: A :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateNumbers`.


.. class:: DHPublicKey

    .. versionadded:: 0.9

    .. attribute:: key_size

        The bit length of the prime modulus.

    .. method:: parameters()

        Return the parameters associated with this private key.

        :return: A :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters`.


.. class:: DHPublicKeyWithSerialization

    .. versionadded:: 0.9

    Inherits from :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey`.

    .. method:: public_numbers()

        Return the numbers that make up this public key.

        :return: A :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicNumbers`.
