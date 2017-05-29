.. hazmat::

Cipher-based message authentication code (CMAC)
===============================================

.. currentmodule:: cryptography.hazmat.primitives.cmac

.. testsetup::

    import binascii
    key = binascii.unhexlify(b"0" * 32)

`Cipher-based message authentication codes`_ (or CMACs) are a tool for
calculating message authentication codes using a block cipher coupled with a
secret key. You can use an CMAC to verify both the integrity and authenticity
of a message.

A subset of CMAC with the AES-128 algorithm is described in :rfc:`4493`.

.. class:: CMAC(algorithm, backend)

    .. versionadded:: 0.4

    CMAC objects take a
    :class:`~cryptography.hazmat.primitives.ciphers.BlockCipherAlgorithm` instance.

    .. doctest::

        >>> from cryptography.hazmat.backends import default_backend
        >>> from cryptography.hazmat.primitives import cmac
        >>> from cryptography.hazmat.primitives.ciphers import algorithms
        >>> c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
        >>> c.update(b"message to authenticate")
        >>> c.finalize()
        'CT\x1d\xc8\x0e\x15\xbe4e\xdb\xb6\x84\xca\xd9Xk'

    If the backend doesn't support the requested ``algorithm`` an
    :class:`~cryptography.exceptions.UnsupportedAlgorithm` exception will be
    raised.

    If ``algorithm`` isn't a
    :class:`~cryptography.hazmat.primitives.ciphers.BlockCipherAlgorithm`
    instance then ``TypeError`` will be raised.

    To check that a given signature is correct use the :meth:`verify` method.
    You will receive an exception if the signature is wrong:

    .. doctest::

        >>> c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
        >>> c.update(b"message to authenticate")
        >>> c.verify(b"an incorrect signature")
        Traceback (most recent call last):
        ...
        cryptography.exceptions.InvalidSignature: Signature did not match digest.

    :param algorithm: An instance of
        :class:`~cryptography.hazmat.primitives.ciphers.BlockCipherAlgorithm`.
    :param backend: An instance of
        :class:`~cryptography.hazmat.backends.interfaces.CMACBackend`.
    :raises TypeError: This is raised if the provided ``algorithm`` is not an instance of
        :class:`~cryptography.hazmat.primitives.ciphers.BlockCipherAlgorithm`
    :raises cryptography.exceptions.UnsupportedAlgorithm: This is raised if the
        provided ``backend`` does not implement
        :class:`~cryptography.hazmat.backends.interfaces.CMACBackend`

    .. method:: update(data)

        :param bytes data: The bytes to hash and authenticate.
        :raises cryptography.exceptions.AlreadyFinalized: See :meth:`finalize`
        :raises TypeError: This exception is raised if ``data`` is not ``bytes``.

    .. method:: copy()

        Copy this :class:`CMAC` instance, usually so that we may call
        :meth:`finalize` to get an intermediate value while we continue
        to call :meth:`update` on the original instance.

        :return: A new instance of :class:`CMAC` that can be updated
            and finalized independently of the original instance.
        :raises cryptography.exceptions.AlreadyFinalized: See :meth:`finalize`

    .. method:: verify(signature)

        Finalize the current context and securely compare the MAC to
        ``signature``.

        :param bytes signature: The bytes to compare the current CMAC
                against.
        :raises cryptography.exceptions.AlreadyFinalized: See :meth:`finalize`
        :raises cryptography.exceptions.InvalidSignature: If signature does not
                                                                  match digest
        :raises TypeError: This exception is raised if ``signature`` is not
                           ``bytes``.

        .. method:: finalize()

        Finalize the current context and return the message authentication code
        as bytes.

        After ``finalize`` has been called this object can no longer be used
        and :meth:`update`, :meth:`copy`, :meth:`verify` and :meth:`finalize`
        will raise an :class:`~cryptography.exceptions.AlreadyFinalized`
        exception.

        :return bytes: The message authentication code as bytes.
        :raises cryptography.exceptions.AlreadyFinalized:


.. _`Cipher-based message authentication codes`: https://en.wikipedia.org/wiki/CMAC
