.. hazmat::

Key Exchange agreements
=======================

.. module:: cryptography.hazmat.primitives.asymmetric.keyex

Key exchange agreements are cryptographic operations, like Diffie-Hellman
key exchanges, that allow two parties to use their public-private key pairs
to establish a shared secret key over an insecure channel. Usually the
negotiated key is further derived before using it for symmetric operations.

Interfaces
~~~~~~~~~~

.. class:: KeyExchangeFunction(private_key)

    .. versionadded:: 1.1

    :attribute private_key: A private key (for example
        :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`)

    :method public_key(): Returns the public key associated with the
        private_key attribute

    .. method:: compute_key(peer_public_key, kdf)

        :param peer_public_key: The peer public key, the type depends on the
            crypto system used, for example :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
        :param kdf: A Key Derivation function of type
            :class:`~cryptography.hazmat.primitives.kdf.KeyDerivationFunction`
