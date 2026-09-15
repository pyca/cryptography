.. hazmat::

Diffie-Hellman key exchange
===========================

.. currentmodule:: cryptography.hazmat.primitives.asymmetric.dh

.. warning::

    Diffie-Hellman over finite fields (FFDH) has been deprecated and moved to
    the :doc:`/hazmat/decrepit/index` module as
    :mod:`cryptography.hazmat.decrepit.asymmetric.dh`. If you need to
    continue using it then update your code to use the new module path.
    Starting in 53.0.0 it will only be available from that module. Users
    should migrate to a more modern key exchange algorithm such as
    :class:`~cryptography.hazmat.primitives.asymmetric.ec.ECDH`,
    :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey`,
    or :class:`~cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey`
    where possible.

``generate_parameters``, ``DHParameters``, ``DHPrivateKey``, ``DHPublicKey``,
``DHParameterNumbers``, ``DHPrivateNumbers``, and ``DHPublicNumbers`` are
documented in :doc:`/hazmat/decrepit/dh`. Accessing any of them through this
module emits a ``CryptographyDeprecationWarning``.
