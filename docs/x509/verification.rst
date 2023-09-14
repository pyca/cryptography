X.509 verification
==================

.. currentmodule:: cryptography.x509.verification

Support for X.509 certificate verification, also known as path validation,
chain building, etc.

.. note::
    This module is a work in progress, and does not yet contain a fully usable
    X.509 path validation implementation.

.. class:: Subject

    .. versionadded:: 42.0.0

    Type alias: A union of all subject types supported:
    :class:`cryptography.x509.general_name.DNSName`,
    :class:`cryptography.x509.general_name.IPAddress`.

.. class:: Profile

    .. versionadded:: 42.0.0

    An enumeration of different X.509 certificate "profiles."

    A profile is essentially a set of X.509 extension, algorithm, etc.
    policies that are enforced during path validation.

    .. attribute:: RFC5280

        The certificate profile defined in `RFC 5280`_.

    .. attribute:: WebPKI

        The certificate profile defined in the
        `CA/B Forum's Basic Requirements`_.


.. class:: Policy

    .. versionadded:: 42.0.0

    A Policy contains and describes various pieces of configurable path
    validation logic, such as which subject to expect, how deep prospective
    validation chains may go, which signature algorithms are allowed, and
    so forth.

    Policies cannot be constructed directly; :class:`PolicyBuilder` must be
    used.

    .. attribute:: subject

        :type: :class:`Subject`

        The policy's subject.

    .. attribute:: validation_time

        :type: :class:`datetime.datetime`

        The policy's validation time.

.. class:: PolicyBuilder

    .. versionadded:: 42.0.0

    A PolicyBuilder provides a builder-style interface for constructing a
    Verifier.

    .. method:: time(new_time)

        Sets the policy's verification time.

        :param new_time: The :class:`datetime.datetime` to use in the policy

        :returns: A new instance of :class:`PolicyBuilder`

    .. method:: build_server_verifier(subject)

        Builds a verifier for verifying server certificates.

        :param subject: A :class:`Subject` to use in the policy

        :raises NotImplementedError: This API is not implemented yet.

.. class:: Store(certs)

    .. versionadded:: 42.0.0

    A Store is an opaque set of public keys and subject identifiers that are
    considered trusted *a priori*. Stores are typically created from the host
    OS's root of trust, from a well-known source such as a browser CA bundle,
    or from a small set of manually pre-trusted entities.

    :param certs: A list of one or more :class:`cryptography.x509.Certificate`
        instances.
