.. hazmat::

DSA
===

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.dsa

`DSA`_ is a `public-key`_ algorithm for signing messages.

.. class:: DSAParameters(modulus, subgroup_order, generator)

    .. versionadded:: 0.4

    DSA Parameters are required for generating a DSA private key.

    This class conforms to the
    :class:`~cryptography.hazmat.primitives.interfaces.DSAParameters`
    interface.

    :raises TypeError: This is raised when the arguments are not all integers.

    :raises ValueError: This is raised when the values of ``modulus``,
                        ``subgroup_order``, or ``generator`` do
                        not match the bounds specified in `FIPS 186-4`_.


.. class:: DSAPrivateKey(modulus, subgroup_order, generator, x, y)

    .. versionadded:: 0.4

    A DSA private key is required for signing messages.

    This class conforms to the
    :class:`~cryptography.hazmat.primitives.interfaces.DSAPrivateKey`
    interface.

    :raises TypeError: This is raised when the arguments are not all integers.

    :raises ValueError: This is raised when the values of ``modulus``,
                        ``subgroup_order``, or ``generator`` do
                        not match the bounds specified in `FIPS 186-4`_.


.. class:: DSAPublicKey(modulus, subgroup_order, generator, y)

    .. versionadded:: 0.4

    A DSA public key is required for verifying messages.

    Normally you do not need to directly construct public keys because you'll
    be loading them from a file, generating them automatically or receiving
    them from a 3rd party.

    This class conforms to the
    :class:`~cryptography.hazmat.primitives.interfaces.DSAPublicKey`
    interface.

    :raises TypeError: This is raised when the arguments are not all integers.

    :raises ValueError: This is raised when the values of ``modulus``,
                        ``subgroup_order``,``generator``, or ``y`` 
                        do not match the bounds specified in `FIPS 186-4`_.


.. _`DSA`: https://en.wikipedia.org/wiki/Digital_Signature_Algorithm 
.. _`public-key`: https://en.wikipedia.org/wiki/Public-key_cryptography
.. _`FIPS 186-4`: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf 

