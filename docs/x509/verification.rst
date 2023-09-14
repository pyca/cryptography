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

.. class:: Subject

    .. versionadded:: 42.0.0

    Type alias: A union of all subject types supported:
    :class:`cryptography.x509.general_name.DNSName`,
    :class:`cryptography.x509.general_name.IPAddress`.


.. class:: PolicyBuilder

    .. versionadded:: 42.0.0

    A PolicyBuilder provides a builder-style interface for constructing a
    :class:`Policy`.

    .. classmethod:: webpki

        Creates a new :class:`PolicyBuilder` with defaults for the Web PKI,
        i.e. client verification of web server TLS certificates.

    .. method:: subject(new_subject)

        Sets the policy's subject name.

        :param new_subject: The :class:`Subject` to use in the policy

        :returns: A new instance of :class:`PolicyBuilder`

    .. method:: time(new_time)

        Sets the policy's verification time.

        :param new_time: The :class:`datetime.datetime` to use in the policy

        :returns: A new instance of :class:`PolicyBuilder`

    .. method:: build

        Constructs a :class:`Policy` from this :class:`PolicyBuilder`.

        :returns: An instance of :class:`Policy`.

        :raises ValueError: If any component of the policy is malformed.
