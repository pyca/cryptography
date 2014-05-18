.. hazmat::

Elliptic Curve
==============

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.ec


.. class:: EllipticCurvePrivateNumbers(private_value, public_numbers)

    .. versionadded:: 0.5

    The collection of integers that make up an EC private key.

    .. attribute:: public_numbers

        :type: :class:`~cryptography.hazmat.primitives.ec.EllipticCurvePublicNumbers`

        The :class:`EllipticCurvePublicNumbers` which makes up the EC public
        key associated with this EC private key.

    .. attribute:: private_value

        :type: int

        The private value.


.. class:: EllipticCurvePublicNumbers(x, y, curve)

    .. versionadded:: 0.5

    The collection of integers that make up an EC public key.

     .. attribute:: curve

        :type: :class:`~cryptography.hazmat.primitives.interfaces.EllipticCurve`

        The elliptic curve for this key.

    .. attribute:: x

        :type: int

        The affine x component of the public point used for verifying.

    .. attribute:: y

        :type: int

        The affine y component of the public point used for verifying.
