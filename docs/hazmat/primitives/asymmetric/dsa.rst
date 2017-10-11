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

    :param int key_size: The length of the modulus in :term:`bits`. It should
        be either 1024, 2048 or 3072. For keys generated in 2015 this should
        be `at least 2048`_ (See page 41).  Note that some applications
        (such as SSH) have not yet gained support for larger key sizes
        specified in FIPS 186-3 and are still restricted to only the
        1024-bit keys specified in FIPS 186-2.

    :param backend: An instance of
        :class:`~cryptography.hazmat.backends.interfaces.DSABackend`.

    :return: An instance of
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if
        the provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.DSABackend`

.. function:: generate_parameters(key_size, backend)

    .. versionadded:: 0.5

    Generate DSA parameters using the provided ``backend``.

    :param int key_size: The length of :attr:`~DSAParameterNumbers.q`. It
        should be either 1024, 2048 or 3072. For keys generated in 2015 this
        should be `at least 2048`_ (See page 41).  Note that some applications
        (such as SSH) have not yet gained support for larger key sizes
        specified in FIPS 186-3 and are still restricted to only the
        1024-bit keys specified in FIPS 186-2.

    :param backend: An instance of
        :class:`~cryptography.hazmat.backends.interfaces.DSABackend`.

    :return: An instance of
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters`.

    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if
        the provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.DSABackend`

Signing
~~~~~~~

Using a :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`
instance.

.. doctest::

    >>> from cryptography.hazmat.backends import default_backend
    >>> from cryptography.hazmat.primitives import hashes
    >>> from cryptography.hazmat.primitives.asymmetric import dsa
    >>> private_key = dsa.generate_private_key(
    ...     key_size=1024,
    ...     backend=default_backend()
    ... )
    >>> data = b"this is some data I'd like to sign"
    >>> signature = private_key.sign(
    ...     data,
    ...     hashes.SHA256()
    ... )

The ``signature`` is a ``bytes`` object, whose contents is DER encoded as
described in :rfc:`3279`. This can be decoded using
:func:`~cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature`.

If your data is too large to be passed in a single call, you can hash it
separately and pass that value using
:class:`~cryptography.hazmat.primitives.asymmetric.utils.Prehashed`.

.. doctest::

    >>> from cryptography.hazmat.primitives.asymmetric import utils
    >>> chosen_hash = hashes.SHA256()
    >>> hasher = hashes.Hash(chosen_hash, default_backend())
    >>> hasher.update(b"data & ")
    >>> hasher.update(b"more data")
    >>> digest = hasher.finalize()
    >>> sig = private_key.sign(
    ...     digest,
    ...     utils.Prehashed(chosen_hash)
    ... )

Verification
~~~~~~~~~~~~

Verification is performed using a
:class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey` instance.
You can get a public key object with
:func:`~cryptography.hazmat.primitives.serialization.load_pem_public_key`,
:func:`~cryptography.hazmat.primitives.serialization.load_der_public_key`,
:meth:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicNumbers.public_key`
, or
:meth:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey.public_key`.

.. doctest::

    >>> public_key = private_key.public_key()
    >>> public_key.verify(
    ...     signature,
    ...     data,
    ...     hashes.SHA256()
    ... )

``verify()`` takes the signature in the same format as is returned by
``sign()``.

``verify()`` will raise an :class:`~cryptography.exceptions.InvalidSignature`
exception if the signature isn't valid.

If your data is too large to be passed in a single call, you can hash it
separately and pass that value using
:class:`~cryptography.hazmat.primitives.asymmetric.utils.Prehashed`.

.. doctest::

    >>> chosen_hash = hashes.SHA256()
    >>> hasher = hashes.Hash(chosen_hash, default_backend())
    >>> hasher.update(b"data & ")
    >>> hasher.update(b"more data")
    >>> digest = hasher.finalize()
    >>> public_key.verify(
    ...     sig,
    ...     digest,
    ...     utils.Prehashed(chosen_hash)
    ... )

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

        :param backend: An instance of
            :class:`~cryptography.hazmat.backends.interfaces.DSABackend`.

        :returns: A new instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters`.

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

        :param backend: An instance of
            :class:`~cryptography.hazmat.backends.interfaces.DSABackend`.

        :returns: A new instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`.

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

        :param backend: An instance of
            :class:`~cryptography.hazmat.backends.interfaces.DSABackend`.

        :returns: A new instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`.

Key interfaces
~~~~~~~~~~~~~~

.. class:: DSAParameters

    .. versionadded:: 0.3

    `DSA`_ parameters.

    .. method:: generate_private_key()

        .. versionadded:: 0.5

        Generate a DSA private key. This method can be used to generate many
        new private keys from a single set of parameters.

        :return: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`.


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

    A `DSA`_ private key. A DSA private key that is not an
    :term:`opaque key` also implements :class:`DSAPrivateKeyWithSerialization`
    to provide serialization methods.

    .. method:: public_key()

        :return: :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`

        An DSA public key object corresponding to the values of the private key.

    .. method:: parameters()

        :return: :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters`

        The DSAParameters object associated with this private key.

    .. attribute:: key_size

        :type: int

        The bit length of :attr:`~DSAParameterNumbers.q`.

    .. method:: sign(data, algorithm)

        .. versionadded:: 1.5
        .. versionchanged:: 1.6
            :class:`~cryptography.hazmat.primitives.asymmetric.utils.Prehashed`
            can now be used as an ``algorithm``.

        Sign one block of data which can be verified later by others using the
        public key.

        :param bytes data: The message string to sign.

        :param algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` or
            :class:`~cryptography.hazmat.primitives.asymmetric.utils.Prehashed`
            if the ``data`` you want to sign has already been hashed.

        :return bytes: Signature.


.. class:: DSAPrivateKeyWithSerialization

    .. versionadded:: 0.8

    This interface contains additional methods relating to serialization.
    Any object with this interface also has all the methods from
    :class:`DSAPrivateKey`.

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

        The bit length of :attr:`~DSAParameterNumbers.q`.

    .. method:: parameters()

        :return: :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters`

        The DSAParameters object associated with this public key.

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

    .. method:: verify(signature, data, algorithm)

        .. versionadded:: 1.5
        .. versionchanged:: 1.6
            :class:`~cryptography.hazmat.primitives.asymmetric.utils.Prehashed`
            can now be used as an ``algorithm``.

        Verify one block of data was signed by the private key
        associated with this public key.

        :param bytes signature: The signature to verify.

        :param bytes data: The message string that was signed.

        :param algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` or
            :class:`~cryptography.hazmat.primitives.asymmetric.utils.Prehashed`
            if the ``data`` you want to sign has already been hashed.

        :raises cryptography.exceptions.InvalidSignature: If the signature does
            not validate.


.. class:: DSAPublicKeyWithSerialization

    .. versionadded:: 0.8

    Alias for :class:`DSAPublicKey`.


.. _`DSA`: https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
.. _`public-key`: https://en.wikipedia.org/wiki/Public-key_cryptography
.. _`FIPS 186-4`: https://csrc.nist.gov/publications/detail/fips/186/4/final
.. _`at least 2048`: http://www.ecrypt.eu.org/ecrypt2/documents/D.SPA.20.pdf
