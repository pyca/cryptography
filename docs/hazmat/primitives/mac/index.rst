.. hazmat::

Message authentication codes
============================

While cryptography supports both the CMAC and HMAC algorithms, we strongly
recommend that HMAC should be used unless you have a good reason otherwise.

For more information on why HMAC is preferred, see `Use cases for CMAC vs.
HMAC?`_

HMAC and CMAC both use the ``MACContext`` interface:

.. currentmodule:: cryptography.hazmat.primitives.mac

.. class:: MACContext

    .. versionadded:: 0.7

    .. method:: update(data)

        :param bytes data: The data you want to authenticate.

    .. method:: finalize()

        :return: The message authentication code.

    .. method:: copy()

        :return: A
            :class:`~cryptography.hazmat.primitives.mac.MACContext` that
            is a copy of the current context.

    .. method:: verify(signature)

        :param bytes signature: The signature to verify.

        :raises cryptography.exceptions.InvalidSignature: This is raised when
            the provided signature does not match the expected signature.



.. _`CMAC`: https://en.wikipedia.org/wiki/CMAC
.. _`Use cases for CMAC vs. HMAC?`: https://crypto.stackexchange.com/questions/15721/use-cases-for-cmac-vs-hmac

.. toctree::
    :maxdepth: 1

    cmac
    hmac
