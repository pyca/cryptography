X.509 verification
==================

.. currentmodule:: cryptography.x509.verification

Support for X.509 certificate verification, also known as path validation,
chain building, etc.

.. note::
    This module is a work in progress, and does not yet contain a fully usable
    X.509 path validation implementation. These APIs should be considered
    experimental and not yet subject to our backwards compatibility policy.

.. class:: Store(certs)

    .. versionadded:: 42.0.0

    A Store is an opaque set of public keys and subject identifiers that are
    considered trusted *a priori*. Stores are typically created from the host
    OS's root of trust, from a well-known source such as a browser CA bundle,
    or from a small set of manually pre-trusted entities.

    :param certs: A list of one or more :class:`cryptography.x509.Certificate`
        instances.

.. class:: Subject

    .. versionadded:: 42.0.0

    Type alias: A union of all subject types supported:
    :class:`cryptography.x509.general_name.DNSName`,
    :class:`cryptography.x509.general_name.IPAddress`.

.. class:: ServerVerifier

    .. versionadded:: 42.0.0

    A ServerVerifier verifies server certificates.

    It contains and describes various pieces of configurable path
    validation logic, such as which subject to expect, how deep prospective
    validation chains may go, which signature algorithms are allowed, and
    so forth.

    ServerVerifier instances cannot be constructed directly;
    :class:`PolicyBuilder` must be used.

    .. attribute:: subject

        :type: :class:`Subject`

        The verifier's subject.

    .. attribute:: validation_time

        :type: :class:`datetime.datetime`

        The verifier's validation time.

    .. method:: verify(leaf, intermediates, store)

        Performs path validation on ``leaf``, returning a valid path
        if one exists.

        :param leaf: The leaf :class:`~cryptography.x509.Certificate` to validate
        :param intermediates: A :class:`list` of intermediate :class:`~cryptography.x509.Certificate` to attempt to use
        :param store: A :class:`Store` of trusted certificates

        :returns: A list containing a valid chain from ``leaf`` to a member of ``store``.

        :raises ValueError: If a valid chain cannot be constructed

.. class:: PolicyBuilder

    .. versionadded:: 42.0.0

    A PolicyBuilder provides a builder-style interface for constructing a
    Verifier.

    .. method:: time(new_time)

        Sets the verifier's verification time.

        If not called explicitly, this is set to :meth:`datetime.datetime.now`
        when :meth:`build_server_verifier` is called.

        :param new_time: The :class:`datetime.datetime` to use in the verifier

        :returns: A new instance of :class:`PolicyBuilder`

    .. method:: build_server_verifier(subject)

        Builds a verifier for verifying server certificates.

        :param subject: A :class:`Subject` to use in the verifier

        :returns: An instance of :class:`ServerVerifier`
