X.509 Verification
==================

.. currentmodule:: cryptography.x509.verification

.. module:: cryptography.x509.verification

Support for X.509 certificate verification, also known as path validation
or chain building.

.. note::
    While usable, these APIs should be considered unstable and not yet
    subject to our backwards compatibility policy.

Example usage, with `certifi <https://pypi.org/project/certifi/>`_ providing
the root of trust:

.. testsetup::

    from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_certificates
    from datetime import datetime

    peer = load_pem_x509_certificate(b"""
    -----BEGIN CERTIFICATE-----
    MIIDgTCCAwegAwIBAgISBJUzlK20QGqPf5xI0aoE8OIBMAoGCCqGSM49BAMDMDIx
    CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF
    MTAeFw0yMzExMjIyMDUyNDBaFw0yNDAyMjAyMDUyMzlaMBoxGDAWBgNVBAMTD2Ny
    eXB0b2dyYXBoeS5pbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAh2A0yuOByJ
    lxK3ps5vbSOT6ZmvAlflGLn8kEseeodIAockm0ISTb/NGSpu/SY4ITefAOSaulKn
    BzDgmqjGRKujggITMIICDzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYB
    BQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFJu7f03HjjwJ
    MU6rfwDBzxySTrs5MB8GA1UdIwQYMBaAFFrz7Sv8NsI3eblSMOpUb89Vyy6sMFUG
    CCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0cDovL2UxLm8ubGVuY3Iub3Jn
    MCIGCCsGAQUFBzAChhZodHRwOi8vZTEuaS5sZW5jci5vcmcvMBoGA1UdEQQTMBGC
    D2NyeXB0b2dyYXBoeS5pbzATBgNVHSAEDDAKMAgGBmeBDAECATCCAQYGCisGAQQB
    1nkCBAIEgfcEgfQA8gB3AEiw42vapkc0D+VqAvqdMOscUgHLVt0sgdm7v6s52IRz
    AAABi/kFXv4AAAQDAEgwRgIhAI9uF526YzU/DEfpmWRA28fn9gryrWMUCXQnEejQ
    K/trAiEA12ePSql3sGJ/QgXc6ceQB/XAdwzwDB+2CHr6T14vvvUAdwDuzdBk1dsa
    zsVct520zROiModGfLzs3sNRSFlGcR+1mwAAAYv5BV8kAAAEAwBIMEYCIQD1mqTn
    b1hOpZWAUlwVM4EJLYA9HtlOvF70bfrGHpAX4gIhAI8pktDxrUwfTXPuA+eMFPbC
    QraG6dMkB+HOmTz+hgKyMAoGCCqGSM49BAMDA2gAMGUCMQC+PwiHciKMaJyRJkGa
    KFjT/1ICAUsCm8o5h4Xxm0LoOCJVggaXeamDEYnPWbxGETgCME5TJzLIDuF3z6vX
    1SLZDdvHEHLKfOL8/h8KctkjLQ8OJycxwIc+zK+xexVoIuxRhA==
    -----END CERTIFICATE-----
    """
    )

    untrusted_intermediates = load_pem_x509_certificates(b"""
    -----BEGIN CERTIFICATE-----
    MIICxjCCAk2gAwIBAgIRALO93/inhFu86QOgQTWzSkUwCgYIKoZIzj0EAwMwTzEL
    MAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNo
    IEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDIwHhcNMjAwOTA0MDAwMDAwWhcN
    MjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5j
    cnlwdDELMAkGA1UEAxMCRTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQkXC2iKv0c
    S6Zdl3MnMayyoGli72XoprDwrEuf/xwLcA/TmC9N/A8AmzfwdAVXMpcuBe8qQyWj
    +240JxP2T35p0wKZXuskR5LBJJvmsSGPwSSB/GjMH2m6WPUZIvd0xhajggEIMIIB
    BDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMB
    MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFFrz7Sv8NsI3eblSMOpUb89V
    yy6sMB8GA1UdIwQYMBaAFHxClq7eS0g7+pL4nozPbYupcjeVMDIGCCsGAQUFBwEB
    BCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gyLmkubGVuY3Iub3JnLzAnBgNVHR8E
    IDAeMBygGqAYhhZodHRwOi8veDIuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYG
    Z4EMAQIBMA0GCysGAQQBgt8TAQEBMAoGCCqGSM49BAMDA2cAMGQCMHt01VITjWH+
    Dbo/AwCd89eYhNlXLr3pD5xcSAQh8suzYHKOl9YST8pE9kLJ03uGqQIwWrGxtO3q
    YJkgsTgDyj2gJrjubi1K9sZmHzOa25JK1fUpE8ZwYii6I4zPPS/Lgul/
    -----END CERTIFICATE-----
    """)

    verification_time = datetime.fromisoformat("2024-01-12T00:00:00Z")

.. doctest::

    >>> from cryptography.x509 import Certificate, DNSName, load_pem_x509_certificates
    >>> from cryptography.x509.verification import PolicyBuilder, Store
    >>> import certifi
    >>> from datetime import datetime
    >>> with open(certifi.where(), "rb") as pems:
    ...    store = Store(load_pem_x509_certificates(pems.read()))
    >>> builder = PolicyBuilder().store(store)
    >>> # See the documentation on `time` below for more details. If
    >>> # significant time passes between creating a verifier and performing a
    >>> # verification, you may encounter issues with certificate expiration.
    >>> builder = builder.time(verification_time)
    >>> verifier = builder.build_server_verifier(DNSName("cryptography.io"))
    >>> # NOTE: peer and untrusted_intermediates are Certificate and
    >>> #       list[Certificate] respectively, and should be loaded from the
    >>> #       application context that needs them verified, such as a
    >>> #       TLS socket.
    >>> chain = verifier.verify(peer, untrusted_intermediates)

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

.. class:: VerifiedClient

    .. versionadded:: 43.0.0

    .. versionchanged:: 44.0.0
        Renamed `subjects` to :attr:`sans`. 
        Made `sans` optional, added :attr:`subject`.

    .. attribute:: subject

        :type: :class:`~cryptography.x509.Name`

        The subject presented in the verified client's certificate.

    .. attribute:: sans

        :type: list of :class:`~cryptography.x509.GeneralName` or None

        The subjects presented in the verified client's Subject Alternative Name
        extension or `None` if the extension is not present.

    .. attribute:: chain

        :type: A list of :class:`~cryptography.x509.Certificate`, in leaf-first order

        The chain of certificates that forms the valid chain to the client
        certificate.


.. class:: ClientVerifier

    .. versionadded:: 43.0.0
    .. versionchanged:: 44.0.0
        Added :attr:`eku`.

    A ClientVerifier verifies client certificates.

    It contains and describes various pieces of configurable path
    validation logic, such as how deep prospective validation chains may go,
    which signature algorithms are allowed, and so forth.

    ClientVerifier instances cannot be constructed directly;
    :class:`PolicyBuilder` must be used.

    .. attribute:: validation_time

        :type: :class:`datetime.datetime`

        The verifier's validation time.

    .. attribute:: max_chain_depth

        :type: :class:`int`

        The verifier's maximum intermediate CA chain depth.

    .. attribute:: store

        :type: :class:`Store`

        The verifier's trust store.
    
    .. attribute:: eku

        :type: :class:`~cryptography.x509.ObjectIdentifier` or None

        The value of the Extended Key Usage extension required by this verifier
        If the verifier was built using :meth:`PolicyBuilder.build_client_verifier`,
        this will always be :attr:`~cryptography.x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH`. 
        
        :note: 
            See :meth:`CustomPolicyBuilder.eku` documentation for how verification is affected 
            when changing the required EKU or using a custom extension policy.

    .. method:: verify(leaf, intermediates)

        Performs path validation on ``leaf``, returning a valid path
        if one exists. The path is returned in leaf-first order:
        the first member is ``leaf``, followed by the intermediates used
        (if any), followed by a member of the ``store``.

        :param leaf: The leaf :class:`~cryptography.x509.Certificate` to validate
        :param intermediates: A :class:`list` of intermediate :class:`~cryptography.x509.Certificate` to attempt to use

        :returns:
            A new instance of :class:`VerifiedClient`

        :raises VerificationError: If a valid chain cannot be constructed

        :raises UnsupportedGeneralNameType: If a valid chain exists, but contains an unsupported general name type

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

    .. attribute:: max_chain_depth

        :type: :class:`int`

        The verifier's maximum intermediate CA chain depth.

    .. attribute:: store

        :type: :class:`Store`

        The verifier's trust store.

    .. attribute:: eku

        :type: :class:`~cryptography.x509.ObjectIdentifier`

        The value of the Extended Key Usage extension required by this verifier
        If the verifier was built using :meth:`PolicyBuilder.build_server_verifier`,
        this will always be :attr:`~cryptography.x509.oid.ExtendedKeyUsageOID.SERVER_AUTH`.
        
        :note:
            See :meth:`CustomPolicyBuilder.eku` documentation for how verification is affected 
            when changing the required EKU or using a custom extension policy.

    .. method:: verify(leaf, intermediates)

        Performs path validation on ``leaf``, returning a valid path
        if one exists. The path is returned in leaf-first order:
        the first member is ``leaf``, followed by the intermediates used
        (if any), followed by a member of the ``store``.

        :param leaf: The leaf :class:`~cryptography.x509.Certificate` to validate
        :param intermediates: A :class:`list` of intermediate :class:`~cryptography.x509.Certificate` to attempt to use

        :returns: A list containing a valid chain from ``leaf`` to a member of :class:`ServerVerifier.store`.

        :raises VerificationError: If a valid chain cannot be constructed

.. class:: VerificationError

    .. versionadded:: 42.0.0

    The error raised when path validation fails.

.. class:: PolicyBuilder

    .. versionadded:: 42.0.0

    A PolicyBuilder provides a builder-style interface for constructing a
    Verifier.

    .. method:: time(new_time)

        Sets the verifier's verification time.

        If not called explicitly, this is set to :meth:`datetime.datetime.now`
        when :meth:`build_server_verifier` or :meth:`build_client_verifier`
        is called.

        :param new_time: The :class:`datetime.datetime` to use in the verifier

        :returns: A new instance of :class:`PolicyBuilder`

    .. method:: store(new_store)

        Sets the verifier's trust store.

        :param new_store: The :class:`Store` to use in the verifier

        :returns: A new instance of :class:`PolicyBuilder`

    .. method:: max_chain_depth(new_max_chain_depth)

        Sets the verifier's maximum chain building depth.

        This depth behaves tracks the length of the intermediate CA
        chain: a maximum depth of zero means that the leaf must be directly
        issued by a member of the store, a depth of one means no more than
        one intermediate CA, and so forth. Note that self-issued intermediates
        don't count against the chain depth, per RFC 5280.

        :param new_max_chain_depth: The maximum depth to allow in the verifier

        :returns: A new instance of :class:`PolicyBuilder`

    .. method:: build_server_verifier(subject)

        Builds a verifier for verifying server certificates.

        :param subject: A :class:`Subject` to use in the verifier

        :returns: An instance of :class:`ServerVerifier`

    .. method:: build_client_verifier()

        .. versionadded:: 43.0.0

        Builds a verifier for verifying client certificates.

        .. warning::

            This API is not suitable for website (i.e. server) certificate
            verification. You **must** use :meth:`build_server_verifier`
            for server verification.

        :returns: An instance of :class:`ClientVerifier`

.. class:: CustomPolicyBuilder

    .. versionadded:: 44.0.0

    A CustomPolicyBuilder provides a builder-style interface for constructing a
    Verifier, but provides additional control over the verification policy compared to :class:`PolicyBuilder`.

    .. method:: time(new_time)

        Sets the verifier's verification time.

        If not called explicitly, this is set to :meth:`datetime.datetime.now`
        when :meth:`build_server_verifier` or :meth:`build_client_verifier`
        is called.

        :param new_time: The :class:`datetime.datetime` to use in the verifier

        :returns: A new instance of :class:`PolicyBuilder`

    .. method:: store(new_store)

        Sets the verifier's trust store.

        :param new_store: The :class:`Store` to use in the verifier

        :returns: A new instance of :class:`PolicyBuilder`

    .. method:: max_chain_depth(new_max_chain_depth)

        Sets the verifier's maximum chain building depth.

        This depth behaves tracks the length of the intermediate CA
        chain: a maximum depth of zero means that the leaf must be directly
        issued by a member of the store, a depth of one means no more than
        one intermediate CA, and so forth. Note that self-issued intermediates
        don't count against the chain depth, per RFC 5280.

        :param new_max_chain_depth: The maximum depth to allow in the verifier

        :returns: A new instance of :class:`PolicyBuilder`

    .. method:: eku(new_eku)

        Sets the Extended Key Usage required by the verifier's policy.

        If this method is not called, the EKU defaults to :attr:`~cryptography.x509.oid.ExtendedKeyUsageOID.SERVER_AUTH` 
        if :meth:`build_server_verifier` is called, and :attr:`~cryptography.x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH` if
        :meth:`build_client_verifier` is called. 

        When using the default extension policies, only certificates
        with the Extended Key Usage extension containing the specified value
        will be accepted. To accept more than one EKU or any EKU, use an extension policy
        with a custom validator. The EKU set via this method is accessible to custom extension validator
        callbacks via the `policy` argument.

        :param ~cryptography.x509.ObjectIdentifier new_eku:

        :returns: A new instance of :class:`PolicyBuilder`

    .. method:: build_server_verifier(subject)

        Builds a verifier for verifying server certificates.

        :param subject: A :class:`Subject` to use in the verifier

        :returns: An instance of :class:`ServerVerifier`

    .. method:: build_client_verifier()

        Builds a verifier for verifying client certificates.

        .. warning::

            This API is not suitable for website (i.e. server) certificate
            verification. You **must** use :meth:`build_server_verifier`
            for server verification.

        :returns: An instance of :class:`ClientVerifier`
