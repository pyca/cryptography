.. hazmat::

Key Exchange agreements
=======================

.. module:: cryptography.hazmat.primitives.asymmetric.key_exchange

Key exchange agreements are cryptographic operations, like Diffie-Hellman
key exchanges, that allow two parties to use their public-private key pairs
to establish a shared secret key over an insecure channel. Usually the
negotiated key is further derived before using it for symmetric operations.

Interfaces
~~~~~~~~~~

.. class:: KeyExchangeContext

    .. versionadded:: 1.1

    .. method:: agree(public_key)

        :param public_key: The peer public key, the type depends on the
            crypto system used, for example :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
