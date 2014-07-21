.. hazmat::

.. module:: cryptography.hazmat.primitives.asymmetric

Signature Interfaces
====================

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


Key exchange interfaces
=======================

.. class:: KeyExchangeContext

    .. versionadded:: 0.8

    .. method:: agree(public_value)

        :return bytes: The agreed key.
