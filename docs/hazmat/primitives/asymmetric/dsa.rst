.. hazmat::

DSA
===

.. module:: cryptography.hazmat.primitives.asymmetric.dsa

`DSA`_ is a `public-key`_ algorithm for signing messages.

Generation
~~~~~~~~~~

.. function:: generate_private_key(key_size, backend)

    .. versionadded:: 0.5

    Generate a DSA private key from the given key size. This function will
    generate a new set of parameters and key in one step.

    :param int key_size: The length of the modulus in bits. It should be
        either 1024, 2048 or 3072. For keys generated in 2015 this should
        be `at least 2048`_ (See page 41).  Note that some applications
        (such as SSH) have not yet gained support for larger key sizes
        specified in FIPS 186-3 and are still restricted to only the
        1024-bit keys specified in FIPS 186-2.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.DSABackend`
        provider.

    :return: A :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`
        provider.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if
        the provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.DSABackend`

.. function:: generate_parameters(key_size, backend)

    .. versionadded:: 0.5

    Generate DSA parameters using the provided ``backend``.

    :param int key_size: The length of the modulus in bits. It should be
        either 1024, 2048 or 3072. For keys generated in 2015 this should
        be `at least 2048`_ (See page 41).  Note that some applications
        (such as SSH) have not yet gained support for larger key sizes
        specified in FIPS 186-3 and are still restricted to only the
        1024-bit keys specified in FIPS 186-2.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.DSABackend`
        provider.

    :return: A :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters`
        provider.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if
        the provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.DSABackend`

Signing
~~~~~~~

Using a :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`
provider which can be created like this:

.. doctest::

    >>> from cryptography.hazmat.backends import default_backend
    >>> from cryptography.hazmat.primitives import hashes
    >>> from cryptography.hazmat.primitives.asymmetric import dsa
    >>> private_key = dsa.generate_private_key(
    ...     key_size=1024,
    ...     backend=default_backend()
    ... )
    >>> data = b"this is some data I'd like to sign"

Signing using a :class:`cryptography.hazmat.primitives.hashes.HashContext` (preferred method):

.. doctest::

    >>> digester = hashes.Hash(hashes.SHA256(), backend=default_backend())
    >>> digester.update(data)
    >>> signature = private_key.sign(digester)

One-line signing:

.. doctest::

    >>> signature = private_key.sign(data, hashes.SHA256())

Signing a precomputed digest:

.. warning::

    Only use this for digests, do NOT sign raw data. The data will get truncated
    to the size of DSA's "q" parameter, which is just a few bytes.

.. doctest::

    >>> digester = hashes.Hash(hashes.SHA256(), backend=default_backend())
    >>> digester.update(data)
    >>> digest = digester.finalize()
    >>> signature = private_key.sign(digest, already_hashed=True)

Specifying the per-message key k:

.. warning::

    Only do this when you really understand what you're doing. The slightest mistake will compromise
    your private key! Any signature calculated with below code compromises your private key!

.. doctest::

    >>> msg_key = private_key.create_per_message_key(31337)  # DO NOT DO THAT!
    >>> digester = hashes.Hash(hashes.SHA256(), backend=default_backend())
    >>> digester.update(data)
    >>> signature = private_key.sign(digester, per_msg_key=msg_key)

Legacy signing:

.. doctest::

    >>> signer = private_key.signer(hashes.SHA256())
    >>> signer.update(data)
    >>> signature = signer.finalize()

The ``signature`` is a ``bytes`` object, whose contents is DER encoded as
described in :rfc:`3279`. This can be decoded using
:func:`~cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature`.

Verification
~~~~~~~~~~~~

Verification is performed using a
:class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey` provider.
You can get a public key object with
:func:`~cryptography.hazmat.primitives.serialization.load_pem_public_key`,
:func:`~cryptography.hazmat.primitives.serialization.load_der_public_key`,
:meth:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicNumbers.public_key`
, or
:meth:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey.public_key`.

.. doctest::

    >>> public_key = private_key.public_key()
    >>> data = b"this is some data I'd like to sign"

Verifying using a :class:`cryptography.hazmat.primitives.hashes.HashContext` (preferred method):

.. doctest::

    >>> digester = hashes.Hash(hashes.SHA256(), backend=default_backend())
    >>> digester.update(data)
    >>> public_key.verify(signature, digester)

One-line verification:

.. doctest::

    >>> public_key.verify(signature, data, hashes.SHA256())

Verifying a precomputed digest:

.. doctest::

    >>> digester = hashes.Hash(hashes.SHA256(), backend=default_backend())
    >>> digester.update(data)
    >>> digest = digester.finalize()
    >>> public_key.verify(signature, digest, already_hashed=True)

Legacy verification:

.. doctest::

    >>> verifier = public_key.verifier(signature, hashes.SHA256())
    >>> verifier.update(data)
    >>> verifier.verify()

``verifier()`` takes the signature in the same format as is returned by
``signer.finalize()``.

``verify()`` will raise an :class:`~cryptography.exceptions.InvalidSignature`
exception if the signature isn't valid.

Numbers
~~~~~~~

.. class:: DSAParameterNumbers(p, q, g)

    .. versionadded:: 0.5

    The collection of integers that make up a set of DSA parameters.

    .. attribute:: p

        :type: int

        The public modulus.

    .. attribute:: q

        :type: int

        The sub-group order.

    .. attribute:: g

        :type: int

        The generator.

    .. method:: parameters(backend)

        :param backend: A
            :class:`~cryptography.hazmat.backends.interfaces.DSABackend`
            provider.

        :returns: A new instance of a
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters`
            provider.

.. class:: DSAPublicNumbers(y, parameter_numbers)

    .. versionadded:: 0.5

    The collection of integers that make up a DSA public key.

    .. attribute:: y

        :type: int

        The public value ``y``.

    .. attribute:: parameter_numbers

        :type: :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameterNumbers`

        The :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameterNumbers`
        associated with the public key.

    .. method:: public_key(backend)

        :param backend: A
            :class:`~cryptography.hazmat.backends.interfaces.DSABackend`
            provider.

        :returns: A new instance of a
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`
            provider.

.. class:: DSAPrivateNumbers(x, public_numbers)

    .. versionadded:: 0.5

    The collection of integers that make up a DSA private key.

    .. warning::

        Revealing the value of ``x`` will compromise the security of any
        cryptographic operations performed.

    .. attribute:: x

        :type: int

        The private value ``x``.

    .. attribute:: public_numbers

        :type: :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicNumbers`

        The :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicNumbers`
        associated with the private key.

    .. method:: private_key(backend)

        :param backend: A
            :class:`~cryptography.hazmat.backends.interfaces.DSABackend`
            provider.

        :returns: A new instance of a
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`
            provider.

Key interfaces
~~~~~~~~~~~~~~

.. class:: DSAParameters

    .. versionadded:: 0.3

    `DSA`_ parameters.

    .. method:: generate_private_key()

        .. versionadded:: 0.5

        Generate a DSA private key. This method can be used to generate many
        new private keys from a single set of parameters.

        :return: A
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`
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

        :return: :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`

        An DSA public key object corresponding to the values of the private key.

    .. method:: parameters()

        :return: :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters`

        The DSAParameters object associated with this private key.

    .. method:: sign(message, hash_algorithm, \*, already_hashed, per_msg_key)

        .. versionadded:: 1.XXX

        Sign data which can be verified later by others using the public key.
        The signature is formatted as DER-encoded bytes, as specified in
        :rfc:`3279`.

        :param message: The message to sign. Either an instance of a
            :class:`~cryptography.hazmat.primitives.hashes.HashContext`
            provider or a digest as bytes or the message as bytes.

        :param hash_algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            provider. Used only if message is a bytes object and already_hashed
            is False.

        :param bool already_hashed: Set this to True if and only if message is already
            the output of a hash function.

        :param per_msg_key: Per message key parameter as returned by :meth:`create_per_message_key`.

        :return: Serialized signature.
        :rtype: bytes

        :raises ValueError: This is raised when a signature cannot be computed, e.g. a provided per_msg_key is
            unusable for this message.

    .. method:: create_per_message_key(k)

        .. versionadded:: 1.XXX

        Create a new per message key, with a specified or random *k*. This computes the inverse of *k* and *r*
        to speed up a subsequent signing operation. Use of this function may compromise your private key!

        :param int k: The *k* parameter to use.

        :return: Inverse of *k* and *r*
        :rtype: XXX

        :raises ValueError: This is raised if *k* is unsuitable because the computed *r* is zero.

    .. method:: calculate_k(signature, message, hash_algorithm, \*, already_hashed)

        .. versionadded:: 1.XXX

        Given a signature and a message, use the private key to calculate the *k* value which was originally
        used to sign the message. Never disclose the result, as this will compromise your key immediately!

        See :meth:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey.verify` for parameters.

        :return: int

    .. method:: signer(algorithm, backend)

        .. versionadded:: 0.4

        Sign data which can be verified later by others using the public key.
        The signature is formatted as DER-encoded bytes, as specified in
        :rfc:`3279`.

        :param algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            provider.

        :param backend: A
            :class:`~cryptography.hazmat.backends.interfaces.DSABackend`
            provider.

        :returns:
            :class:`~cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext`

    .. attribute:: key_size

        :type: int

        The bit length of the modulus.


.. class:: DSAPrivateKeyWithSerialization

    .. versionadded:: 0.8

    Extends :class:`DSAPrivateKey`.

    .. method:: private_numbers()

        Create a
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateNumbers`
        object.

        :returns: A
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateNumbers`
            instance.

    .. method:: private_bytes(encoding, format, encryption_algorithm)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM` or
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`),
        format (
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL`
        or
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8`)
        and encryption algorithm (such as
        :class:`~cryptography.hazmat.primitives.serialization.BestAvailableEncryption`
        or :class:`~cryptography.hazmat.primitives.serialization.NoEncryption`)
        are chosen to define the exact serialization.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.PrivateFormat`
            enum.

        :param encryption_algorithm: An instance of an object conforming to the
            :class:`~cryptography.hazmat.primitives.serialization.KeySerializationEncryption`
            interface.

        :return bytes: Serialized key.


.. class:: DSAPublicKey

    .. versionadded:: 0.3

    A `DSA`_ public key.

    .. attribute:: key_size

        :type: int

        The bit length of the modulus.

    .. method:: parameters()

        :return: :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters`

        The DSAParameters object associated with this public key.

    .. method:: verify(signature, message, hash_algorithm, \*, already_hashed)

        .. versionadded:: 1.XXX

        Verify data was signed by the private key associated with this public
        Key.

        :param bytes signature: The signature to verify. DER encoded as
            specified in :rfc:`3279`.

        :param message: The message to sign. Either an instance of a
            :class:`~cryptography.hazmat.primitives.hashes.HashContext`
            provider or a digest as bytes or the message as bytes.

        :param hash_algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            provider. Used only if message is a bytes object and already_hashed
            is False.

        :param bool already_hashed: Set this to True if and only if message is already
            the output of a hash function.

        :raises cryptography.exceptions.InvalidSignature: This is raised when
            the provided signature does not match the expected signature.

    .. method:: verifier(signature, algorithm, backend)

        .. versionadded:: 0.4

        Verify data was signed by the private key associated with this public
        key.

        :param bytes signature: The signature to verify. DER encoded as
            specified in :rfc:`3279`.

        :param algorithm: An instance of a
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            provider.

        :param backend: A
            :class:`~cryptography.hazmat.backends.interfaces.DSABackend`
            provider.

        :returns:
            :class:`~cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext`

    .. method:: public_numbers()

        Create a
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicNumbers`
        object.

        :returns: A
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicNumbers`
            instance.

    .. method:: public_bytes(encoding, format)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM` or
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`) and
        format (
        :attr:`~cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo`)
        are chosen to define the exact serialization.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.PublicFormat` enum.

        :return bytes: Serialized key.


.. class:: DSAPublicKeyWithSerialization

    .. versionadded:: 0.8

    Alias for :class:`DSAPublicKey`.


.. _`DSA`: https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
.. _`public-key`: https://en.wikipedia.org/wiki/Public-key_cryptography
.. _`FIPS 186-4`: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
.. _`at least 2048`: http://www.ecrypt.eu.org/ecrypt2/documents/D.SPA.20.pdf
