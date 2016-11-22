.. hazmat::

Diffie-Hellman key exchange
===========================

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.dh


`Diffie-Hellman key exchange`_ (D–H) is a method that allows two parties
to jointly agree on a shared secret using an insecure channel.


Exchange Algorithm
~~~~~~~~~~~~~~~~~~

For most applications the ``shared_key`` should be passed to a key
derivation function.

.. code-block:: pycon

    >>> from cryptography.hazmat.backends import default_backend
    >>> from cryptography.hazmat.primitives.asymmetric import dh
    >>> parameters = dh.generate_parameters(generator=2, key_size=2048,
    ...                                     backend=default_backend())
    >>> private_key = parameters.generate_private_key()
    >>> peer_public_key = parameters.generate_private_key().public_key()
    >>> shared_key = private_key.exchange(peer_public_key)

DHE (or EDH), the ephemeral form of this exchange, is **strongly
preferred** over simple DH and provides `forward secrecy`_ when used.
You must generate a new private key using :func:`~DHParameters.generate_private_key` for
each :meth:`~DHPrivateKeyWithSerialization.exchange` when performing an DHE key
exchange.

To assemble a :class:`~DHParameters` and a :class:`~DHPublicKey` from
primitive integers, you must first create the
:class:`~DHParameterNumbers` and :class:`~DHPublicNumbers` objects. For
example if **p**, **g**, and **y** are :class:`int` objects received from a
peer::

    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(default_backend())
    peer_public_numbers = dh.DHPublicNumbers(y, pn)
    peer_public_key = peer_public_numbers.public_key(default_backend())


See also the :class:`~cryptography.hazmat.backends.interfaces.DHBackend`
API for additional functionality.

Group parameters
~~~~~~~~~~~~~~~~

.. function:: generate_parameters(generator, key_size, backend)

    .. versionadded:: 0.9

    Generate a new DH parameter group for use with ``backend``.

    :param generator: The :class:`int` to use as a generator. Must be
        2 or 5.

    :param key_size: The bit length of the prime modulus to generate.

    :param backend: A
        :class:`~cryptography.hazmat.backends.interfaces.DHBackend`
        instance.

    :returns: DH parameters as a new instance of
        :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters`.

    :raises ValueError: If ``key_size`` is not at least 512.


.. class:: DHParameters

    .. versionadded:: 0.9


    .. method:: generate_private_key()

        .. versionadded:: 0.9

        Generate a DH private key. This method can be used to generate many
        new private keys from a single set of parameters.

        :return: An instance of
            :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey`.


.. class:: DHParametersWithSerialization

    .. versionadded:: 0.9

    Inherits from :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters`.

    .. method:: parameter_numbers()

        Return the numbers that make up this set of parameters.

        :return: A :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameterNumbers`.


Key interfaces
~~~~~~~~~~~~~~

.. class:: DHPrivateKey

    .. versionadded:: 0.9

    .. attribute:: key_size

        The bit length of the prime modulus.

    .. method:: public_key()

        Return the public key associated with this private key.

        :return: A :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey`.

    .. method:: parameters()

        Return the parameters associated with this private key.

        :return: A :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters`.


.. class:: DHPrivateKeyWithSerialization

    .. versionadded:: 0.9

    Inherits from :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey`.

    .. method:: private_numbers()

        Return the numbers that make up this private key.

        :return: A :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateNumbers`.

    .. method:: exchange(peer_public_key)

        .. versionadded:: 1.7

        :param DHPublicKeyWithSerialization peer_public_key: The public key for the
            peer.

        :return bytes: The agreed key. The bytes are ordered in 'big' endian.


.. class:: DHPublicKey

    .. versionadded:: 0.9

    .. attribute:: key_size

        The bit length of the prime modulus.

    .. method:: parameters()

        Return the parameters associated with this private key.

        :return: A :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters`.


.. class:: DHPublicKeyWithSerialization

    .. versionadded:: 0.9

    Inherits from :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey`.

    .. method:: public_numbers()

        Return the numbers that make up this public key.

        :return: A :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicNumbers`.


Numbers
~~~~~~~

.. class:: DHParameterNumbers(p, g)

    .. versionadded:: 0.8

    The collection of integers that define a Diffie-Hellman group.

    .. attribute:: p

        :type: int

        The prime modulus value.

    .. attribute:: g

        :type: int

        The generator value. Must be 2 or 5.

.. class:: DHPrivateNumbers(x, public_numbers)

    .. versionadded:: 0.8

    The collection of integers that make up a Diffie-Hellman private key.

    .. attribute:: public_numbers

        :type: :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicNumbers`

        The :class:`DHPublicNumbers` which makes up the DH public
        key associated with this DH private key.

    .. attribute:: x

        :type: int

        The private value.


.. class:: DHPublicNumbers(y, parameter_numbers)

    .. versionadded:: 0.8

    The collection of integers that make up a Diffie-Hellman public key.

     .. attribute:: parameter_numbers

        :type: :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameterNumbers`

        The parameters for this DH group.

    .. attribute:: y

        :type: int

        The public value.


.. _`Diffie-Hellman key exchange`: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
.. _`forward secrecy`: https://en.wikipedia.org/wiki/Forward_secrecy
