.. hazmat::

.. module:: cryptography.hazmat.primitives.interfaces

Interfaces
==========


``cryptography`` uses `Abstract Base Classes`_ as interfaces to describe the
properties and methods of most primitive constructs. Backends may also use
this information to influence their operation. Interfaces should also be used
to document argument and return types.

.. _`Abstract Base Classes`: https://docs.python.org/3/library/abc.html


Asymmetric interfaces
---------------------

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


.. class:: AsymmetricPadding

    .. versionadded:: 0.2

    .. attribute:: name

DSA
~~~

In 0.8 the DSA key interfaces were moved to the
:mod:`cryptography.hazmat.primitives.asymmetric.dsa` module.


RSA
~~~

In 0.8 the RSA key interfaces were moved to the
:mod:`cryptography.hazmat.primitives.asymmetric.rsa` module.


Elliptic Curve
~~~~~~~~~~~~~~

In 0.8 the EC key interfaces were moved to the
:mod:`cryptography.hazmat.primitives.asymmetric.ec` module.


Key derivation functions
------------------------

.. class:: KeyDerivationFunction

    .. versionadded:: 0.2

    .. method:: derive(key_material)

        :param bytes key_material: The input key material. Depending on what
                                   key derivation function you are using this
                                   could be either random bytes, or a user
                                   supplied password.
        :return: The new key.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive` or
                                                          :meth:`verify` is
                                                          called more than
                                                          once.

        This generates and returns a new key from the supplied key material.

    .. method:: verify(key_material, expected_key)

        :param bytes key_material: The input key material. This is the same as
                                   ``key_material`` in :meth:`derive`.
        :param bytes expected_key: The expected result of deriving a new key,
                                   this is the same as the return value of
                                   :meth:`derive`.
        :raises cryptography.exceptions.InvalidKey: This is raised when the
                                                    derived key does not match
                                                    the expected key.
        :raises cryptography.exceptions.AlreadyFinalized: This is raised when
                                                          :meth:`derive` or
                                                          :meth:`verify` is
                                                          called more than
                                                          once.

        This checks whether deriving a new key from the supplied
        ``key_material`` generates the same key as the ``expected_key``, and
        raises an exception if they do not match. This can be used for
        something like checking whether a user's password attempt matches the
        stored derived key.


`Message Authentication Code`_
------------------------------

.. class:: CMACContext

    :class:`CMACContext` has been deprecated in favor of :class:`MACContext`.

    .. versionadded:: 0.4

    .. method:: update(data)

        :param bytes data: The data you want to authenticate.

    .. method:: finalize()

        :return: The message authentication code.

    .. method:: copy()

        :return: A :class:`~cryptography.hazmat.primitives.interfaces.CMACContext`
            that is a copy of the current context.

.. class:: MACContext

    .. versionadded:: 0.7

    .. method:: update(data)

        :param bytes data: The data you want to authenticate.

    .. method:: finalize()

        :return: The message authentication code.

    .. method:: copy()

        :return: A
            :class:`~cryptography.hazmat.primitives.interfaces.MACContext` that
            is a copy of the current context.

    .. method:: verify(signature)

        :param bytes signature: The signature to verify.

        :raises cryptography.exceptions.InvalidSignature: This is raised when
            the provided signature does not match the expected signature.


.. _`CMAC`: https://en.wikipedia.org/wiki/CMAC
