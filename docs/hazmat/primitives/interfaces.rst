.. hazmat::

Interfaces
==========


``cryptography`` uses `Abstract Base Classes`_ as interfaces to describe the
properties and methods of most primitive constructs. Backends may also use
this information to influence their operation. Interfaces should also be used
to document argument and return types.

.. _`Abstract Base Classes`: http://docs.python.org/3.2/library/abc.html


Symmetric ciphers
-----------------

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


Cipher modes
~~~~~~~~~~~~

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

Asymmetric interfaces
---------------------

.. class:: AsymmetricSignatureContext

    .. versionadded:: 0.2

    .. method:: update(data)

        :param bytes data: The data you want to sign.

    .. method:: finalize()

        :return bytes signature: The signature.


.. class:: AsymmetricVerificationContext

    .. versionadded:: 0.2

    .. method:: update(data)

        :param bytes data: The data you wish to verify using the signature.

    .. method:: verify()

        :raises cryptography.exceptions.InvalidSignature: If the signature does
            not validate.


.. class:: AsymmetricPadding

    .. versionadded:: 0.2

    .. attribute:: name


RSA
~~~

.. class:: RSAPrivateKey

    .. versionadded:: 0.2

    An `RSA`_ private key.

    .. method:: signer(padding, algorithm)

        .. versionadded:: 0.3

        Sign data which can be verified later by others using the public key.

        :param padding: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.AsymmetricPadding`
            provider.

        :param algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
            provider.

        :returns:
            :class:`~cryptography.hazmat.primitives.interfaces.AsymmetricSignatureContext`

    .. method:: decrypt(ciphertext, padding)

        .. versionadded:: 0.4

        Decrypt data that was encrypted via the public key.

        :param bytes ciphertext: The ciphertext to decrypt.

        :param padding: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.AsymmetricPadding`
            provider.

        :return bytes: Decrypted data.

    .. method:: public_key()

        :return: :class:`~cryptography.hazmat.primitives.interfaces.RSAPublicKey`

        An RSA public key object corresponding to the values of the private key.

    .. attribute:: key_size

        :type: int

        The bit length of the modulus.

.. class:: RSAPrivateKeyWithNumbers

    .. versionadded:: 0.5

    Extends :class:`RSAPrivateKey`.

    .. method:: private_numbers()

        Create a
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateNumbers`
        object.

        :returns: An
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateNumbers`
            instance.


.. class:: RSAPublicKey

    .. versionadded:: 0.2

    An `RSA`_ public key.

    .. method:: verifier(signature, padding, algorithm)

        .. versionadded:: 0.3

        Verify data was signed by the private key associated with this public
        key.

        :param bytes signature: The signature to verify.

        :param padding: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.AsymmetricPadding`
            provider.

        :param algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
            provider.

        :returns:
            :class:`~cryptography.hazmat.primitives.interfaces.AsymmetricVerificationContext`

    .. method:: encrypt(plaintext, padding)

        .. versionadded:: 0.4

        Encrypt data with the public key.

        :param bytes plaintext: The plaintext to encrypt.

        :param padding: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.AsymmetricPadding`
            provider.

        :return bytes: Encrypted data.

    .. attribute:: key_size

        :type: int

        The bit length of the modulus.


.. class:: RSAPublicKeyWithNumbers

    .. versionadded:: 0.5

    Extends :class:`RSAPublicKey`.

    .. method:: public_numbers()

        Create a
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers`
        object.

        :returns: An
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers`
            instance.


DSA
~~~

.. class:: DSAParameters

    .. versionadded:: 0.3

    `DSA`_ parameters.

    .. method:: generate_private_key()

        .. versionadded:: 0.5

        Generate a DSA private key. This method can be used to generate many
        new private keys from a single set of parameters.

        :return: A
            :class:`~cryptography.hazmat.primitives.interfaces.DSAPrivateKey`
            provider.


.. class:: DSAParametersWithNumbers

    .. versionadded:: 0.5

    Extends :class:`DSAParameters`.

    .. method:: parameter_numbers()

        Create a
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameterNumbers`
        object.

        :returns: A
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameterNumbers`
            instance.


.. class:: DSAPrivateKey

    .. versionadded:: 0.3

    A `DSA`_ private key.

    .. method:: public_key()

        :return: :class:`~cryptography.hazmat.primitives.interfaces.DSAPublicKey`

        An DSA public key object corresponding to the values of the private key.

    .. method:: parameters()

        :return: :class:`~cryptography.hazmat.primitives.interfaces.DSAParameters`

        The DSAParameters object associated with this private key.

    .. method:: signer(algorithm, backend)

        .. versionadded:: 0.4

        Sign data which can be verified later by others using the public key.

        :param algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
            provider.

        :param backend: A
            :class:`~cryptography.hazmat.backends.interfaces.DSABackend`
            provider.

        :returns:
            :class:`~cryptography.hazmat.primitives.interfaces.AsymmetricSignatureContext`

    .. attribute:: key_size

        :type: int

        The bit length of the modulus.


.. class:: DSAPrivateKeyWithNumbers

    .. versionadded:: 0.5

    Extends :class:`DSAPrivateKey`.

    .. method:: private_numbers()

        Create a
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateNumbers`
        object.

        :returns: A
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateNumbers`
            instance.


.. class:: DSAPublicKey

    .. versionadded:: 0.3

    A `DSA`_ public key.

    .. attribute:: key_size

        :type: int

        The bit length of the modulus.

    .. method:: parameters()

        :return: :class:`~cryptography.hazmat.primitives.interfaces.DSAParameters`

        The DSAParameters object associated with this public key.

    .. method:: verifier(signature, algorithm, backend)

        .. versionadded:: 0.4

        Verify data was signed by the private key associated with this public
        key.

        :param bytes signature: The signature to verify. DER encoded as
            specified in :rfc:`6979`.

        :param algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`
            provider.

        :param backend: A
            :class:`~cryptography.hazmat.backends.interfaces.DSABackend`
            provider.

        :returns:
            :class:`~cryptography.hazmat.primitives.interfaces.AsymmetricVerificationContext`


.. class:: DSAPublicKeyWithNumbers

    .. versionadded:: 0.5

    Extends :class:`DSAPublicKey`.

    .. method:: public_numbers()

        Create a
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicNumbers`
        object.

        :returns: A
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicNumbers`
            instance.


.. class:: EllipticCurve

    .. versionadded:: 0.5

    A named elliptic curve.

    .. attribute:: name

        :type: string

        The name of the curve. Usually the name used for the ASN.1 OID such as
        ``secp256k1``.

    .. attribute:: key_size

        :type: int

        The bit length of the curve's base point.


Elliptic Curve
~~~~~~~~~~~~~~

.. class:: EllipticCurveSignatureAlgorithm

    .. versionadded:: 0.5

    A signature algorithm for use with elliptic curve keys.

    .. attribute:: algorithm

        :type: :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm`

        The digest algorithm to be used with the signature scheme.


.. class:: EllipticCurvePrivateKey

    .. versionadded:: 0.5

    An elliptic curve private key for use with an algorithm such as `ECDSA`_ or
    `EdDSA`_.

    .. classmethod:: signer(signature_algorithm)
        Sign data which can be verified later by others using the public key.

        :param signature_algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.EllipticCurveSignatureAlgorithm`
            provider.

        :returns:
            :class:`~cryptography.hazmat.primitives.interfaces.AsymmetricSignatureContext`


        :type: :class:`~cryptography.hazmat.primitives.interfaces.EllipticCurve`

        The elliptic curve for this key.

    .. method:: public_key()

        :return: :class:`~cryptography.hazmat.primitives.interfaces.EllipticCurvePublicKey`

        The EllipticCurvePublicKey object for this private key.


.. class:: EllipticCurvePrivateKeyWithNumbers

    .. versionadded:: 0.6

    Extends :class:`EllipticCurvePrivateKey`.

    .. method:: private_numbers()

        Create a
        :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateNumbers`
        object.

        :returns: An
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateNumbers`
            instance.


.. class:: EllipticCurvePublicKey

    .. versionadded:: 0.5

    An elliptic curve public key.

    .. classmethod:: verifier(signature, signature_algorithm)
        Verify data was signed by the private key associated with this public
        key.

        :param bytes signature: The signature to verify.

        :param signature_algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.interfaces.EllipticCurveSignatureAlgorithm`
            provider.

        :returns:
            :class:`~cryptography.hazmat.primitives.interfaces.AsymmetricSignatureContext`

     .. attribute:: curve

        :type: :class:`~cryptography.hazmat.primitives.interfaces.EllipticCurve`

        The elliptic curve for this key.


.. class:: EllipticCurvePublicKeyWithNumbers

    .. versionadded:: 0.6

    Extends :class:`EllipticCurvePublicKey`.

    .. method:: public_numbers()

        Create a
        :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers`
        object.

        :returns: An
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers`
            instance.


Hash algorithms
---------------

.. class:: HashAlgorithm

    .. attribute:: name

        :type: str

        The standard name for the hash algorithm, for example: ``"sha256"`` or
        ``"whirlpool"``.

    .. attribute:: digest_size

        :type: int

        The size of the resulting digest in bytes.

    .. attribute:: block_size

        :type: int

        The internal block size of the hash algorithm in bytes.


.. class:: HashContext

    .. attribute:: algorithm

        A :class:`~cryptography.hazmat.primitives.interfaces.HashAlgorithm` that
        will be used by this context.

    .. method:: update(data)

        :param data bytes: The data you want to hash.

    .. method:: finalize()

        :return: The final digest as bytes.

    .. method:: copy()

        :return: A :class:`~cryptography.hazmat.primitives.interfaces.HashContext`
             that is a copy of the current context.


Key derivation functions
------------------------

.. class:: KeyDerivationFunction

    .. versionadded:: 0.2

    .. method:: derive(key_material)

        :param key_material bytes: The input key material. Depending on what
                                   key derivation function you are using this
                                   could be either random material, or a user
                                   supplied password.
        :return: The new key.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive` or
                                                          :meth:`verify` is
                                                          called more than
                                                          once.

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
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive` or
                                                          :meth:`verify` is
                                                          called more than
                                                          once.

        This checks whether deriving a new key from the supplied
        ``key_material`` generates the same key as the ``expected_key``, and
        raises an exception if they do not match. This can be used for
        something like checking whether a user's password attempt matches the
        stored derived key.


`Message Authentication Code`_
------------------------------

.. class:: CMACContext

    `CMACContext` has been deprecated in favor of `MACContext`.

    .. versionadded:: 0.4

    .. method:: update(data)

        :param data bytes: The data you want to authenticate.

    .. method:: finalize()

        :return: The message authentication code.

    .. method:: copy()

        :return: A :class:`~cryptography.hazmat.primitives.interfaces.CMACContext`
            that is a copy of the current context.

.. class:: MACContext

    .. versionadded:: 0.7

    .. method:: update(data)

        :param data bytes: The data you want to authenticate.

    .. method:: finalize()

        :return: The message authentication code.

    .. method:: copy()

        :return: A :class:`~cryptography.hazmat.primitives.interfaces.MACContext`
            that is a copy of the current context.

    .. method:: verify()

        :param signature bytes: The signature to verify.

        :raises cryptography.exceptions.InvalidSignature: This is raised when
            the provided signature does not match the expected signature.

.. _`RSA`: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
.. _`Chinese remainder theorem`: https://en.wikipedia.org/wiki/Chinese_remainder_theorem
.. _`DSA`: https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
.. _`CMAC`: https://en.wikipedia.org/wiki/CMAC
.. _`ECDSA`: http://en.wikipedia.org/wiki/ECDSA
.. _`EdDSA`: http://en.wikipedia.org/wiki/EdDSA
