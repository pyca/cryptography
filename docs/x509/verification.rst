X.509 verification
==================

.. currentmodule:: cryptography.x509.verification

Support for X.509 certificate verification, also known as path validation,
chain building, etc.

.. note::
    This module is a work in progress, and does not yet contain a fully usable
    X.509 path validation implementation.

.. class:: Store(certs)

    .. versionadded:: 42.0.0

    A Store is an opaque set of public keys and subject identifiers that are
    considered trusted *a priori*. Stores are typically created from the host
    OS's root of trust, from a well-known source such as a browser CA bundle,
    or from a small set of manually pre-trusted entities.

    :param certs: A list of one or more :class:`~cryptography.x509.Certificate`
        instances.
