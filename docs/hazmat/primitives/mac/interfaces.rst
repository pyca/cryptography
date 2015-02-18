.. hazmat::

Interfaces
==========
.. module:: cryptography.hazmat.primitives.mac

.. class:: MACContext

    .. versionadded:: 0.7

    .. method:: update(data)

        :param bytes data: The data you want to authenticate.

    .. method:: finalize()

        :return: The message authentication code.

    .. method:: copy()

        :return: A :class:`MACContext` that is a copy of the current context.

    .. method:: verify(signature)

        :param bytes signature: The signature to verify.

        :raises cryptography.exceptions.InvalidSignature: This is raised when
            the provided signature does not match the expected signature.
