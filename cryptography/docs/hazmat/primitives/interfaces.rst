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

In 0.8 the asymmetric signature and verification interfaces were moved to the
:mod:`cryptography.hazmat.primitives.asymmetric` module.

In 0.8 the asymmetric padding interface was moved to the
:mod:`cryptography.hazmat.primitives.asymmetric.padding` module.

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

In 0.8 the key derivation function interface was moved to the
:mod:`cryptography.hazmat.primitives.kdf` module.


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
