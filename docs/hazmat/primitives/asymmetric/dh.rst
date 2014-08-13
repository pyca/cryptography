.. hazmat::

Diffie-Hellman Key Exchange
===========================

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.dh


.. class:: DHPrivateNumbers(private_value, public_numbers)

    .. versionadded:: 0.6

    The collection of integers that make up a Diffie-Hellman private key.

    .. attribute:: public_numbers

        :type: :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicNumbers`

        The :class:`DHPublicNumbers` which makes up the DH public
        key associated with this DH private key.

    .. attribute:: private_value

        :type: int

        The private value.


.. class:: DHPublicNumbers(parameters, public_value)

    .. versionadded:: 0.6

    The collection of integers that make up a Diffie-Hellman public key.

     .. attribute:: parameters

        :type: :class:`~cryptography.hazmat.primitives.dh.DHParameters`

        The parameters for this DH group.

    .. attribute:: public_value

        :type: int

        The public value.


.. class:: DHParameters(modulus, generator)

    .. versionadded:: 0.6

    The collection of integers that define a Diffie-Hellman group.

    .. attribute:: modulus

        :type: int

        The prime modulus value.

    .. attribute:: generator

        :type: int

        The generator value.
