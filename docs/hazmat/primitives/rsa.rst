.. hazmat::

RSA
===

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.rsa

`RSA`_ is a `public-key`_ algorithm for encrypting and signing messages.

.. class:: RSAPrivateKey(p, q, private_exponent, public_exponent, modulus)
    
    .. versionadded:: 0.2

    An RSA private key is required for decryption and signing of messages.

    Normally you do not need to directly construct private keys because you'll
    be loading them from a file or generating them automatically.

    This class conforms to the
    :class:`~cryptography.hazmat.primitives.interfaces.RSAPrivateKey`
    interface.

    :raises TypeError: This is raised when the arguments are not all integers. 

    :raises ValueError: This is raised when the values of `private_exponent`,
                        `public_exponent` or `modulus` do not match the bounds
                        specified in `RFC 3447`_

.. class:: RSAPublicKey(public_exponent, modulus)
    
    .. versionadded:: 0.2

    An RSA public key is required for encryption and verification of messages.

    Normally you do not need to directly construct public keys because you'll
    be loading them from a file, generating them automatically or receiving
    them from a 3rd party.

    This class conforms to the
    :class:`~cryptography.hazmat.primitives.interfaces.RSAPublicKey`
    interface.

    :raises TypeError: This is raised when the arguments are not all integers. 

    :raises ValueError: This is raised when the values of `public_exponent` or
                        `modulus` do not match the bounds specified in
                        `RFC 3447`_

.. _`RSA`: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
.. _`public-key`: https://en.wikipedia.org/wiki/Public-key_cryptography
.. _`RFC 3447`: https://tools.ietf.org/html/rfc3447
