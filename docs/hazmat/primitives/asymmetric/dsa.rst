.. hazmat::

DSA
===

.. module:: cryptography.hazmat.primitives.asymmetric.dsa

.. note::

    DSA is a **legacy algorithm** and should generally be avoided in favor of
    choices like
    :doc:`EdDSA using curve25519</hazmat/primitives/asymmetric/ed25519>` or
    :doc:`ECDSA</hazmat/primitives/asymmetric/ec>`.

`DSA`_ is a `public-key`_ algorithm for signing messages.

Generation
~~~~~~~~~~

.. function:: generate_private_key(key_size)

    .. versionadded:: 0.5

    .. versionchanged:: 3.0

        Added support for 4096-bit keys for some legacy applications that
        continue to use DSA despite the wider cryptographic community's
        `ongoing protestations`_.

    Generate a DSA private key from the given key size. This function will
    generate a new set of parameters and key in one step.

    :param int key_size: The length of the modulus in :term:`bits`. It should
        be either 1024, 2048, 3072, or 4096. For keys generated in 2015 this
        should be `at least 2048`_ (See page 41).

    :return: An instance of
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`.

.. function:: generate_parameters(key_size)

    .. versionadded:: 0.5

    .. versionchanged:: 3.0

        Added support for 4096-bit keys for some legacy applications that
        continue to use DSA despite the wider cryptographic community's
        `ongoing protestations`_.

    Generate DSA parameters.

    :param int key_size: The length of :attr:`~DSAParameterNumbers.p`. It
        should be either 1024, 2048, 3072, or 4096. For keys generated in 2015
        this should be `at least 2048`_ (See page 41).

    :return: An instance of
        :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters`.

Signing
~~~~~~~

Using a :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`
instance.

.. doctest::

    >>> from cryptography.hazmat.primitives import hashes
    >>> from cryptography.hazmat.primitives.asymmetric import dsa
    >>> private_key = dsa.generate_private_key(
    ...     key_size=1024,
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
    >>> hasher = hashes.Hash(chosen_hash)
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
    >>> hasher = hashes.Hash(chosen_hash)
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

    .. method:: parameters()

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

    .. method:: public_key()

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

    .. method:: private_key()

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

    .. attribute:: key_size

        :type: int

        The bit length of :attr:`~DSAParameterNumbers.p`.

    .. method:: sign(data, algorithm)

        .. versionadded:: 1.5
        .. versionchanged:: 1.6
            :class:`~cryptography.hazmat.primitives.asymmetric.utils.Prehashed`
            can now be used as an ``algorithm``.

        Sign one block of data which can be verified later by others using the
        public key.

        :param data: The message string to sign.
        :type data: :term:`bytes-like`

        :param algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` or
            :class:`~cryptography.hazmat.primitives.asymmetric.utils.Prehashed`
            if the ``data`` you want to sign has already been hashed.

        :return bytes: Signature.

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
        :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL`,
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

        The bit length of :attr:`~DSAParameterNumbers.p`.

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

        :param signature: The signature to verify.
        :type signature: :term:`bytes-like`

        :param data: The message string that was signed.
        :type data: :term:`bytes-like`

        :param algorithm: An instance of
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` or
            :class:`~cryptography.hazmat.primitives.asymmetric.utils.Prehashed`
            if the ``data`` you want to sign has already been hashed.

        :returns: None
        :raises cryptography.exceptions.InvalidSignature: If the signature does
            not validate.


.. _`DSA`: https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
.. _`public-key`: https://en.wikipedia.org/wiki/Public-key_cryptography
.. _`FIPS 186-4`: https://csrc.nist.gov/publications/detail/fips/186/4/final
.. _`at least 2048`: https://www.cosic.esat.kuleuven.be/ecrypt/ecrypt2/documents/D.SPA.20.pdf
.. _`ongoing protestations`: https://words.filippo.io/dispatches/dsa/
