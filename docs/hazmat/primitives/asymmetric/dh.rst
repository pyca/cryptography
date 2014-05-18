.. hazmat::

Diffie-Hellman key exchange
===========================

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.dh


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
