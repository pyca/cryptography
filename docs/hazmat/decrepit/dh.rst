.. hazmat::

Decrepit Diffie-Hellman key exchange
====================================

.. module:: cryptography.hazmat.decrepit.asymmetric.dh

.. testsetup::

    import base64

    parameters_pem_data = b"""
    -----BEGIN DH PARAMETERS-----
    MIGHAoGBALsrWt44U1ojqTy88o0wfjysBE51V6Vtarjm2+5BslQK/RtlndHde3gx
    +ccNs+InANszcuJFI8AHt4743kGRzy5XSlul4q4dDJENOHoyqYxueFuFVJELEwLQ
    XrX/McKw+hS6GPVQnw6tZhgGo9apdNdYgeLQeQded8Bum8jqzP3rAgEC
    -----END DH PARAMETERS-----
    """.strip()

    parameters_der_data = base64.b64decode(
        b"MIGHAoGBALsrWt44U1ojqTy88o0wfjysBE51V6Vtarjm2+5BslQK/RtlndHde3gx+ccNs+In"
        b"ANsz\ncuJFI8AHt4743kGRzy5XSlul4q4dDJENOHoyqYxueFuFVJELEwLQXrX/McKw+hS6GP"
        b"VQnw6tZhgG\no9apdNdYgeLQeQded8Bum8jqzP3rAgEC"
    )

This module contains Diffie-Hellman key exchange over finite fields (FFDH).
FFDH should not be used unless necessary for backwards compatibility or
interoperability with legacy systems. Its use is **strongly discouraged**;
use :class:`~cryptography.hazmat.primitives.asymmetric.ec.ECDH` or
:class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey`
instead where possible.

`Diffie-Hellman key exchange`_ (D–H) is a method that allows two parties
to jointly agree on a shared secret using an insecure channel.


Exchange Algorithm
~~~~~~~~~~~~~~~~~~

For most applications the ``shared_key`` should be passed to a key
derivation function. This allows mixing of additional information into the
key, derivation of multiple keys, and destroys any structure that may be
present.

.. warning::

    This example does not give `forward secrecy`_ and is only provided as a
    demonstration of the basic Diffie-Hellman construction. For real world
    applications always use the ephemeral form described after this example.

.. code-block:: pycon

    >>> from cryptography.hazmat.primitives import hashes
    >>> from cryptography.hazmat.decrepit.asymmetric import dh
    >>> from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    >>> # Generate some parameters. These can be reused.
    >>> parameters = dh.generate_parameters(generator=2, key_size=2048)
    >>> # Generate a private key for use in the exchange.
    >>> server_private_key = parameters.generate_private_key()
    >>> # In a real handshake the peer is a remote client. For this
    >>> # example we'll generate another local private key though. Note that in
    >>> # a DH handshake both peers must agree on a common set of parameters.
    >>> peer_private_key = parameters.generate_private_key()
    >>> shared_key = server_private_key.exchange(peer_private_key.public_key())
    >>> # Perform key derivation.
    >>> derived_key = HKDF(
    ...     algorithm=hashes.SHA256(),
    ...     length=32,
    ...     salt=None,
    ...     info=b'handshake data',
    ... ).derive(shared_key)
    >>> # And now we can demonstrate that the handshake performed in the
    >>> # opposite direction gives the same final value
    >>> same_shared_key = peer_private_key.exchange(
    ...     server_private_key.public_key()
    ... )
    >>> same_derived_key = HKDF(
    ...     algorithm=hashes.SHA256(),
    ...     length=32,
    ...     salt=None,
    ...     info=b'handshake data',
    ... ).derive(same_shared_key)
    >>> derived_key == same_derived_key

DHE (or EDH), the ephemeral form of this exchange, is **strongly
preferred** over simple DH and provides `forward secrecy`_ when used.  You must
generate a new private key using :func:`~DHParameters.generate_private_key` for
each :meth:`~DHPrivateKey.exchange` when performing an DHE key exchange. An
example of the ephemeral form:

.. code-block:: pycon

    >>> from cryptography.hazmat.primitives import hashes
    >>> from cryptography.hazmat.decrepit.asymmetric import dh
    >>> from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    >>> # Generate some parameters. These can be reused.
    >>> parameters = dh.generate_parameters(generator=2, key_size=2048)
    >>> # Generate a private key for use in the exchange.
    >>> private_key = parameters.generate_private_key()
    >>> # In a real handshake the peer_public_key will be received from the
    >>> # other party. For this example we'll generate another private key and
    >>> # get a public key from that. Note that in a DH handshake both peers
    >>> # must agree on a common set of parameters.
    >>> peer_public_key = parameters.generate_private_key().public_key()
    >>> shared_key = private_key.exchange(peer_public_key)
    >>> # Perform key derivation.
    >>> derived_key = HKDF(
    ...     algorithm=hashes.SHA256(),
    ...     length=32,
    ...     salt=None,
    ...     info=b'handshake data',
    ... ).derive(shared_key)
    >>> # For the next handshake we MUST generate another private key, but
    >>> # we can reuse the parameters.
    >>> private_key_2 = parameters.generate_private_key()
    >>> peer_public_key_2 = parameters.generate_private_key().public_key()
    >>> shared_key_2 = private_key_2.exchange(peer_public_key_2)
    >>> derived_key_2 = HKDF(
    ...     algorithm=hashes.SHA256(),
    ...     length=32,
    ...     salt=None,
    ...     info=b'handshake data',
    ... ).derive(shared_key_2)

To assemble a :class:`~DHParameters` and a :class:`~DHPublicKey` from
primitive integers, you must first create the
:class:`~DHParameterNumbers` and :class:`~DHPublicNumbers` objects. For
example, if **p**, **g**, and **y** are :class:`int` objects received from a
peer::

    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters()
    peer_public_numbers = dh.DHPublicNumbers(y, pn)
    peer_public_key = peer_public_numbers.public_key()


Group parameters
~~~~~~~~~~~~~~~~

.. function:: generate_parameters(generator, key_size)

    .. versionadded:: 51.0.0

    Generate a new DH parameter group.

    :param generator: The :class:`int` to use as a generator. Must be
        2 or 5.

    :param key_size: The bit length of the prime modulus to generate.

    :returns: DH parameters as a new instance of
        :class:`~cryptography.hazmat.decrepit.asymmetric.dh.DHParameters`.

    :raises ValueError: If ``key_size`` is not at least 512.


.. class:: DHParameters

    .. versionadded:: 51.0.0

    .. method:: generate_private_key()

        Generate a DH private key. This method can be used to generate many
        new private keys from a single set of parameters.

        :return: An instance of
            :class:`~cryptography.hazmat.decrepit.asymmetric.dh.DHPrivateKey`.

    .. method:: parameter_numbers()

        Return the numbers that make up this set of parameters.

        :return: A :class:`~cryptography.hazmat.decrepit.asymmetric.dh.DHParameterNumbers`.

    .. method:: parameter_bytes(encoding, format)

        Allows serialization of the parameters to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM` or
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`) and
        format (
        :attr:`~cryptography.hazmat.primitives.serialization.ParameterFormat.PKCS3`)
        are chosen to define the exact serialization.

        :param encoding: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.Encoding` enum.

        :param format: A value from the
            :class:`~cryptography.hazmat.primitives.serialization.ParameterFormat`
            enum. At the moment only ``PKCS3`` is supported.

        :return bytes: Serialized parameters.

Parameter serialization
~~~~~~~~~~~~~~~~~~~~~~~

.. function:: load_pem_parameters(data)

    .. versionadded:: 51.0.0

    Deserialize parameters from PEM encoded data.

    .. doctest::

        >>> from cryptography.hazmat.decrepit.asymmetric import dh
        >>> parameters = dh.load_pem_parameters(parameters_pem_data)
        >>> isinstance(parameters, dh.DHParameters)
        True

    :param bytes data: The PEM encoded parameters data.

    :returns: An instance of :class:`DHParameters`.

    :raises ValueError: If the PEM data's structure could not be decoded
        successfully.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized
        parameters type is not supported by the OpenSSL version
        ``cryptography`` is using.

.. function:: load_der_parameters(data)

    .. versionadded:: 51.0.0

    Deserialize parameters from DER encoded data.

    .. doctest::

        >>> from cryptography.hazmat.decrepit.asymmetric import dh
        >>> parameters = dh.load_der_parameters(parameters_der_data)
        >>> isinstance(parameters, dh.DHParameters)
        True

    :param bytes data: The DER encoded parameters data.

    :returns: An instance of :class:`DHParameters`.

    :raises ValueError: If the DER data's structure could not be decoded
        successfully.

    :raises cryptography.exceptions.UnsupportedAlgorithm: If the serialized
        parameters type is not supported by the OpenSSL version
        ``cryptography`` is using.


Key interfaces
~~~~~~~~~~~~~~

.. class:: DHPrivateKey

    .. versionadded:: 51.0.0

    .. attribute:: key_size

        The bit length of the prime modulus.

    .. method:: public_key()

        Return the public key associated with this private key.

        :return: A :class:`~cryptography.hazmat.decrepit.asymmetric.dh.DHPublicKey`.

    .. method:: parameters()

        Return the parameters associated with this private key.

        :return: A :class:`~cryptography.hazmat.decrepit.asymmetric.dh.DHParameters`.

    .. method:: exchange(peer_public_key)

        :param DHPublicKey peer_public_key: The public key for
            the peer.

        :return bytes: The agreed key. The bytes are ordered in 'big' endian.

    .. method:: private_numbers()

        Return the numbers that make up this private key.

        :return: A :class:`~cryptography.hazmat.decrepit.asymmetric.dh.DHPrivateNumbers`.

    .. method:: private_bytes(encoding, format, encryption_algorithm)

        Allows serialization of the key to bytes. Encoding (
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM` or
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`),
        format (
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


.. class:: DHPublicKey

    .. versionadded:: 51.0.0

    .. attribute:: key_size

        The bit length of the prime modulus.

    .. method:: parameters()

        Return the parameters associated with this private key.

        :return: A :class:`~cryptography.hazmat.decrepit.asymmetric.dh.DHParameters`.

    .. method:: public_numbers()

        Return the numbers that make up this public key.

        :return: A :class:`~cryptography.hazmat.decrepit.asymmetric.dh.DHPublicNumbers`.

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

Numbers
~~~~~~~

.. class:: DHParameterNumbers(p, g, q=None)

    .. versionadded:: 51.0.0

    The collection of integers that define a Diffie-Hellman group.

    .. attribute:: p

        :type: int

        The prime modulus value.

    .. attribute:: g

        :type: int

        The generator value. Must be 2 or greater.

    .. attribute:: q

        :type: int

        p subgroup order value.

    .. method:: parameters()

        :returns: A new instance of :class:`DHParameters`.

        :raises ValueError: If the parameters are invalid.

.. class:: DHPrivateNumbers(x, public_numbers)

    .. versionadded:: 51.0.0

    The collection of integers that make up a Diffie-Hellman private key.

    .. attribute:: public_numbers

        :type: :class:`~cryptography.hazmat.decrepit.asymmetric.dh.DHPublicNumbers`

        The :class:`DHPublicNumbers` which makes up the DH public
        key associated with this DH private key.

    .. attribute:: x

        :type: int

        The private value.

    .. method:: private_key()

        :returns: A new instance of :class:`DHPrivateKey`.


.. class:: DHPublicNumbers(y, parameter_numbers)

    .. versionadded:: 51.0.0

    The collection of integers that make up a Diffie-Hellman public key.

     .. attribute:: parameter_numbers

        :type: :class:`~cryptography.hazmat.decrepit.asymmetric.dh.DHParameterNumbers`

        The parameters for this DH group.

    .. attribute:: y

        :type: int

        The public value.

    .. method:: public_key()

        :returns: A new instance of :class:`DHPublicKey`.


.. _`Diffie-Hellman key exchange`: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
.. _`forward secrecy`: https://en.wikipedia.org/wiki/Forward_secrecy
