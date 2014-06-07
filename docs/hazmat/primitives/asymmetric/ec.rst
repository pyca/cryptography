.. hazmat::

Elliptic Curve Cryptography
===========================

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.ec


.. method:: generate_private_key(curve, backend):

    .. versionadded:: 0.5

    Generate a new private key on ``curve`` for use with ``backend``.

    :param backend: A
        :class:`~cryptography.hazmat.primtives.interfaces.EllipticCurve`
        provider.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.EllipticCurveBackend`
        provider.

    :returns: A new instance of a
        :class:`~cryptography.hazmat.primtivies.interfaces.EllipticCurvePrivateKey`
        provider.


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

    .. method:: private_key(backend)

        Convert a collection of numbers into a private key suitable for doing
        actual cryptographic operations.

        :param backend: A
            :class:`~cryptography.hazmat.backends.interfaces.EllipticCurveBackend`
            provider.

        :returns: A new instance of a
            :class:`~cryptography.hazmat.primtivies.interfaces.EllipticCurvePrivateKey`
            provider.


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

    .. method:: public_key(backend)

        Convert a collection of numbers into a public key suitable for doing
        actual cryptographic operations.

        :param backend: A
            :class:`~cryptography.hazmat.backends.interfaces.EllipticCurveBackend`
            provider.

        :returns: A new instance of a
            :class:`~cryptography.hazmat.primtivies.interfaces.EllipticCurvePublicKey`
            provider.


Elliptic Curve Signature Algorithms
-----------------------------------

.. class:: ECDSA(algorithm)
    .. versionadded:: 0.5

    The ECDSA signature algorithm first standardized in NIST publication
    `FIPS 186-3`_, and later in `FIPS 186-4`_.

    :param algorithm: An instance of a
        :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
        provider.

    .. code-block:: pycon

        >>> from cryptography.hazmat.backends import default_backend
        >>> from cryptography.hazmat.primitives import hashes
        >>> from cryptography.hazmat.primitives.asymmetric import ec
        >>> private_key = ec.generate_private_key(
        ...     ec.SECT283K1(), default_backend()
        ... )
        >>> signer = private_key.signer(ec.ECDSA(hashes.SHA256()))
        >>> signer.update(b"this is some data I'd like")
        >>> signer.update(b" to sign")
        >>> signature = signer.finalize()

Elliptic Curves
---------------

All named curves are providers of
:class:`~cryptography.hazmat.primtives.interfaces.EllipticCurve`.

There is `some concern`_ that the non-Koblitz NIST curves (identified by names
that start with "B" or "P") may have been intentionally weakened by their
generation process.


.. class:: SECT571K1
    .. versionadded:: 0.5

    SECG curve ``sect571k1``. Also called NIST K-571.


.. class:: SECT409K1
    .. versionadded:: 0.5

    SECG curve ``sect409k1``. Also called NIST K-409.


.. class:: SECT283K1
    .. versionadded:: 0.5

    SECG curve ``sect283k1``. Also called NIST K-283.


.. class:: SECT233K1
    .. versionadded:: 0.5

    SECG curve ``sect233k1``. Also called NIST K-233.


.. class:: SECT163K1
    .. versionadded:: 0.5

    SECG curve ``sect163k1``. Also called NIST K-163.


.. class:: SECT571R1
    .. versionadded:: 0.5

    SECG curve ``sect571r1``. Also called NIST B-571.


.. class:: SECT409R1
    .. versionadded:: 0.5

    SECG curve ``sect409r1``. Also called NIST B-409.


.. class:: SECT283R1
    .. versionadded:: 0.5

    SECG curve ``sect283r1``. Also called NIST B-283.


.. class:: SECT233R1
    .. versionadded:: 0.5

    SECG curve ``sect233r1``. Also called NIST B-233.


.. class:: SECT163R2
    .. versionadded:: 0.5

    SECG curve ``sect163r2``. Also called NIST B-163.


.. class:: SECP521R1
    .. versionadded:: 0.5

    SECG curve ``secp521r1``. Also called NIST P-521.


.. class:: SECP384R1
    .. versionadded:: 0.5

    SECG curve ``secp384r1``. Also called NIST P-384.


.. class:: SECP256R1
    .. versionadded:: 0.5

    SECG curve ``secp256r1``. Also called NIST P-256.


.. class:: SECT224R1
    .. versionadded:: 0.5

    SECG curve ``secp224r1``. Also called NIST P-224.


.. class:: SECP192R1
    .. versionadded:: 0.5

    SECG curve ``secp192r1``. Also called NIST P-192.



.. _`FIPS 186-3`: http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
.. _`FIPS 186-4`: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
.. _`some concern`: https://crypto.stackexchange.com/questions/10263/should-we-trust-the-nist-recommended-ecc-parameters
