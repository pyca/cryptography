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

    .. versionchanged:: 45.0.0
        Made ``subjects`` optional with the addition of custom extension policies.

    .. attribute:: subjects

        :type: list of :class:`~cryptography.x509.GeneralName` or None

        The subjects presented in the verified client's Subject Alternative Name
        extension or ``None`` if the extension is not present.

    .. attribute:: chain

        :type: A list of :class:`~cryptography.x509.Certificate`, in leaf-first order

        The chain of certificates that forms the valid chain to the client
        certificate.


.. class:: ClientVerifier

    .. versionadded:: 43.0.0

    .. versionchanged:: 45.0.0
        ``verification_time`` and ``max_chain_depth`` were deprecated and will be 
        removed in version 46.0.0.
        The new ``policy`` property should be used to access these values instead.

    A ClientVerifier verifies client certificates.

    It contains and describes various pieces of configurable path
    validation logic, such as how deep prospective validation chains may go,
    which signature algorithms are allowed, and so forth.

    ClientVerifier instances cannot be constructed directly;
    :class:`PolicyBuilder` must be used.

    .. attribute:: policy

        :type: :class:`Policy`

        The policy used by the verifier. Can be used to access verification time, maximum chain depth, etc.

    .. attribute:: store

        :type: :class:`Store`

        The verifier's trust store.

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

    .. versionchanged:: 45.0.0
        ``subject``, ``verification_time`` and ``max_chain_depth`` were deprecated and will be 
        removed in version 46.0.0.
        The new ``policy`` property should be used to access these values instead.


    A ServerVerifier verifies server certificates.

    It contains and describes various pieces of configurable path
    validation logic, such as which subject to expect, how deep prospective
    validation chains may go, which signature algorithms are allowed, and
    so forth.

    ServerVerifier instances cannot be constructed directly;
    :class:`PolicyBuilder` must be used.

    .. attribute:: policy

        :type: :class:`Policy`

        The policy used by the verifier. Can be used to access verification time, maximum chain depth, etc.

    .. attribute:: store

        :type: :class:`Store`

        The verifier's trust store.

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

    .. versionchanged:: 45.0.0
        Added the ``extension_policies`` method. 
        Removed the ``new_`` prefix from all parameter names.

    A PolicyBuilder provides a builder-style interface for constructing a
    Verifier.

    .. method:: time(time)

        Sets the verifier's verification time.

        If not called explicitly, this is set to :meth:`datetime.datetime.now`
        when :meth:`build_server_verifier` or :meth:`build_client_verifier`
        is called.

        :param time: The :class:`datetime.datetime` to use in the verifier

        :returns: A new instance of :class:`PolicyBuilder`

    .. method:: store(store)

        Sets the verifier's trust store.

        :param store: The :class:`Store` to use in the verifier

        :returns: A new instance of :class:`PolicyBuilder`

    .. method:: max_chain_depth(max_chain_depth)

        Sets the verifier's maximum chain building depth.

        This depth behaves tracks the length of the intermediate CA
        chain: a maximum depth of zero means that the leaf must be directly
        issued by a member of the store, a depth of one means no more than
        one intermediate CA, and so forth. Note that self-issued intermediates
        don't count against the chain depth, per RFC 5280.

        :param max_chain_depth: The maximum depth to allow in the verifier

        :returns: A new instance of :class:`PolicyBuilder`

    .. method:: extension_policies(*, ee_policy, ca_policy)

        .. versionadded:: 45.0.0

        Sets the EE and CA extension policies for the verifier.
        The default policies used are those returned by :meth:`ExtensionPolicy.webpki_defaults_ee`
        and :meth:`ExtensionPolicy.webpki_defaults_ca`.

        .. warning::
            If the PolicyBuilder will be used to build a :class:`ServerVerifier`, the EE extension policy
            `must require` the :class:`~cryptography.x509.SubjectAlternativeName` extension to be present.
            All CA extension policies `must require` the :class:`~cryptography.x509.BasicConstraints` 
            extension to be present.

        :param ExtensionPolicy ca_policy: The CA extension policy to use.
        :param ExtensionPolicy ee_policy: The EE extension policy to use. 

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

.. class:: ExtensionPolicy

    .. versionadded:: 45.0.0

    ExtensionPolicy provides a set of static methods to construct predefined
    extension policies, and a builder-style interface for modifying them.

    .. note:: Calling any of the builder methods (:meth:`require_not_present`, :meth:`may_be_present`, or :meth:`require_present`)
        multiple times with the same extension type will raise an exception.

    .. note:: Currently only the following extension types are supported in the ExtensionPolicy API:
        :class:`~cryptography.x509.AuthorityInformationAccess`,
        :class:`~cryptography.x509.AuthorityKeyIdentifier`,
        :class:`~cryptography.x509.SubjectKeyIdentifier`,
        :class:`~cryptography.x509.KeyUsage`,
        :class:`~cryptography.x509.SubjectAlternativeName`,
        :class:`~cryptography.x509.BasicConstraints`,
        :class:`~cryptography.x509.NameConstraints`,
        :class:`~cryptography.x509.ExtendedKeyUsage`.

    .. staticmethod:: permit_all()

        Creates an ExtensionPolicy that does not put any constraints on a certificate's extensions. 
        This can serve as a base for a fully custom extension policy.

        :returns: An instance of :class:`ExtensionPolicy`

    .. staticmethod:: webpki_defaults_ca()

        Creates an ExtensionPolicy for CA certificates,
        based on CA/B Forum guidelines.

        This is the default CA extension policy used by :class:`PolicyBuilder`.

        :returns: An instance of :class:`ExtensionPolicy`

    .. staticmethod:: webpki_defaults_ee()

        Creates an ExtensionPolicy for EE certificates,
        based on CA/B Forum guidelines.

        This is the default EE extension policy used by :class:`PolicyBuilder`.

        :returns: An instance of :class:`ExtensionPolicy`

    .. method:: require_not_present(extension_type)

        Specifies that the extension identified by `extension_type` must not be present (must be absent).

        :param type[ExtensionType] extension_type: The extension_type of the extension that must not be present.

        :returns: An instance of :class:`ExtensionPolicy`

    .. method:: may_be_present(extension_type, criticality, validator_cb)

        Specifies that the extension identified by `extension_type` is optional.
        If it is present, it must conform to the given criticality constraint. 
        An optional validator callback may be provided.

        If a validator callback is provided, the callback will be invoked 
        when :meth:`ClientVerifier.verify` or :meth:`ServerVerifier.verify` is called on a verifier 
        that uses the extension policy. For details on the callback signature, see :type:`MaybeExtensionValidatorCallback`.

        :param type[ExtensionType] extension_type: A concrete class derived from :type:`~cryptography.x509.ExtensionType`
            indicating which extension may be present.
        :param Criticality criticality: The criticality of the extension
        :param validator_cb: An optional Python callback to validate the extension value. 
            Must accept extensions of type `extension_type`.
        :type validator_cb: :type:`MaybeExtensionValidatorCallback` or None

        :returns: An instance of :class:`ExtensionPolicy`

    .. method:: require_present(extension_type, criticality, validator_cb)

        Specifies that the extension identified by `extension_type`` must be present
        and conform to the given criticality constraint. An optional validator callback may be provided.

        If a validator callback is provided, the callback will be invoked 
        when :meth:`ClientVerifier.verify` or :meth:`ServerVerifier.verify` is called on a verifier 
        that uses the extension policy. For details on the callback signature, see :type:`PresentExtensionValidatorCallback`.

        :param type[ExtensionType] extension_type: A concrete class derived from :type:`~cryptography.x509.ExtensionType`
            indicating which extension is required to be present.
        :param Criticality criticality: The criticality of the extension
        :param validator_cb: An optional Python callback to validate the extension value.
            Must accept extensions of type `extension_type`.
        :type validator_cb: :type:`PresentExtensionValidatorCallback` or None

        :returns: An instance of :class:`ExtensionPolicy`

.. class:: Criticality

    .. versionadded:: 45.0.0

    An enumeration of criticality constraints for certificate extensions.

    .. attribute:: CRITICAL

        The extension must be marked as critical.

    .. attribute:: AGNOSTIC
            
        The extension may be marked either as critical or non-critical.

    .. attribute:: NON_CRITICAL

        The extension must not be marked as critical.

.. class:: Policy

    .. versionadded:: 45.0.0

    Represents a policy for certificate verification. Passed to extension validator callbacks and 
    accessible via :class:`ClientVerifier` and :class:`ServerVerifier`.

    .. attribute:: max_chain_depth

        The maximum chain depth (as described in :meth:`PolicyBuilder.max_chain_depth`).

        :type: int

    .. attribute:: subject

        The subject used during verification. 
        Will be None if the verifier is a :class:`ClientVerifier`.

        :type: x509.verification.Subject or None

    .. attribute:: validation_time

        The validation time.

        :type: datetime.datetime

    .. attribute:: extended_key_usage

        The Extended Key Usage required by the policy.

        :type: x509.ObjectIdentifier

    .. attribute:: minimum_rsa_modulus

        The minimum RSA modulus size required by the policy.

        :type: int

.. type:: MaybeExtensionValidatorCallback
    :canonical: Callable[[Policy, Certificate, Optional[ExtensionType]], None]
    
    .. versionadded:: 45.0.0


    A Python callback that validates an extension that may or may not be present.
    If the extension is not present, the callback will be invoked with `ext` set to `None`.

    To fail the validation, the callback must raise an exception.

    :param Policy policy: The verification policy.
    :param Certificate certificate: The certificate being verified.
    :param ExtensionType or None extension: The extension value or `None` if the extension is not present.
    
    :returns: An extension validator callback must return `None`.
              If the validation fails, the validator must raise an exception.

.. type:: PresentExtensionValidatorCallback
    :canonical: Callable[[Policy, Certificate, ExtensionType], None]

    .. versionadded:: 45.0.0


    A Python callback that validates an extension that must be present.

    To fail the validation, the callback must raise an exception.

    :param Policy policy: The verification policy.
    :param Certificate certificate: The certificate being verified.
    :param ExtensionType extension: The extension value.

    :returns: An extension validator callback must return `None`.
              If the validation fails, the validator must raise an exception.
