.. hazmat::

Diffie-Hellman key exchange
===========================

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.dh

.. warning::

    Diffie-Hellman over finite fields (FFDH) has been deprecated and moved to
    the :doc:`/hazmat/decrepit/index` module. If you need to continue using it
    then update your code to use
    :mod:`cryptography.hazmat.decrepit.asymmetric.dh`. Starting in 53.0.0 it
    will only be available from that module. Users should migrate to a more
    modern key exchange algorithm such as
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.ECDH` or
    :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey`
    where possible.

The classes and functions previously documented here, ``generate_parameters``,
``DHParameters``, ``DHPrivateKey``, ``DHPublicKey``, ``DHParameterNumbers``,
``DHPrivateNumbers``, and ``DHPublicNumbers``, are documented in
:doc:`/hazmat/decrepit/dh`. Accessing any of them through this module emits a
``CryptographyDeprecationWarning``.
