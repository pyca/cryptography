OCSP
====

.. currentmodule:: cryptography.x509.ocsp

.. testsetup::

    import base64
    pem_cert = b"""
    -----BEGIN CERTIFICATE-----
    MIIFvTCCBKWgAwIBAgICPyAwDQYJKoZIhvcNAQELBQAwRzELMAkGA1UEBhMCVVMx
    FjAUBgNVBAoTDUdlb1RydXN0IEluYy4xIDAeBgNVBAMTF1JhcGlkU1NMIFNIQTI1
    NiBDQSAtIEczMB4XDTE0MTAxNTEyMDkzMloXDTE4MTExNjAxMTUwM1owgZcxEzAR
    BgNVBAsTCkdUNDg3NDI5NjUxMTAvBgNVBAsTKFNlZSB3d3cucmFwaWRzc2wuY29t
    L3Jlc291cmNlcy9jcHMgKGMpMTQxLzAtBgNVBAsTJkRvbWFpbiBDb250cm9sIFZh
    bGlkYXRlZCAtIFJhcGlkU1NMKFIpMRwwGgYDVQQDExN3d3cuY3J5cHRvZ3JhcGh5
    LmlvMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAom/FebKJIot7Sp3s
    itG1sicpe3thCssjI+g1JDAS7I3GLVNmbms1DOdIIqwf01gZkzzXBN2+9sOnyRaR
    PPfCe1jTr3dk2y6rPE559vPa1nZQkhlzlhMhlPyjaT+S7g4Tio4qV2sCBZU01DZJ
    CaksfohN+5BNVWoJzTbOcrHOEJ+M8B484KlBCiSxqf9cyNQKru4W3bHaCVNVJ8eu
    6i6KyhzLa0L7yK3LXwwXVs583C0/vwFhccGWsFODqD/9xHUzsBIshE8HKjdjDi7Y
    3BFQzVUQFjBB50NSZfAA/jcdt1blxJouc7z9T8Oklh+V5DDBowgAsrT4b6Z2Fq6/
    r7D1GqivLK/ypUQmxq2WXWAUBb/Q6xHgxASxI4Br+CByIUQJsm8L2jzc7k+mF4hW
    ltAIUkbo8fGiVnat0505YJgxWEDKOLc4Gda6d/7GVd5AvKrz242bUqeaWo6e4MTx
    diku2Ma3rhdcr044Qvfh9hGyjqNjvhWY/I+VRWgihU7JrYvgwFdJqsQ5eiKT4OHi
    gsejvWwkZzDtiQ+aQTrzM1FsY2swJBJsLSX4ofohlVRlIJCn/ME+XErj553431Lu
    YQ5SzMd3nXzN78Vj6qzTfMUUY72UoT1/AcFiUMobgIqrrmwuNxfrkbVE2b6Bga74
    FsJX63prvrJ41kuHK/16RQBM7fcCAwEAAaOCAWAwggFcMB8GA1UdIwQYMBaAFMOc
    8/zTRgg0u85Gf6B8W/PiCMtZMFcGCCsGAQUFBwEBBEswSTAfBggrBgEFBQcwAYYT
    aHR0cDovL2d2LnN5bWNkLmNvbTAmBggrBgEFBQcwAoYaaHR0cDovL2d2LnN5bWNi
    LmNvbS9ndi5jcnQwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMB
    BggrBgEFBQcDAjAvBgNVHREEKDAmghN3d3cuY3J5cHRvZ3JhcGh5Lmlvgg9jcnlw
    dG9ncmFwaHkuaW8wKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL2d2LnN5bWNiLmNv
    bS9ndi5jcmwwDAYDVR0TAQH/BAIwADBFBgNVHSAEPjA8MDoGCmCGSAGG+EUBBzYw
    LDAqBggrBgEFBQcCARYeaHR0cHM6Ly93d3cucmFwaWRzc2wuY29tL2xlZ2FsMA0G
    CSqGSIb3DQEBCwUAA4IBAQAzIYO2jx7h17FBT74tJ2zbV9OKqGb7QF8y3wUtP4xc
    dH80vprI/Cfji8s86kr77aAvAqjDjaVjHn7UzebhSUivvRPmfzRgyWBacomnXTSt
    Xlt2dp2nDQuwGyK2vB7dMfKnQAkxwq1sYUXznB8i0IhhCAoXp01QGPKq51YoIlnF
    7DRMk6iEaL1SJbkIrLsCQyZFDf0xtfW9DqXugMMLoxeCsBhZJQzNyS2ryirrv9LH
    aK3+6IZjrcyy9bkpz/gzJucyhU+75c4My/mnRCrtItRbCQuiI5pd5poDowm+HH9i
    GVI9+0lAFwxOUnOnwsoI40iOoxjLMGB+CgFLKCGUcWxP
    -----END CERTIFICATE-----
    """
    pem_issuer = b"""
    -----BEGIN CERTIFICATE-----
    MIIEJTCCAw2gAwIBAgIDAjp3MA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNVBAYTAlVT
    MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
    YWwgQ0EwHhcNMTQwODI5MjEzOTMyWhcNMjIwNTIwMjEzOTMyWjBHMQswCQYDVQQG
    EwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEgMB4GA1UEAxMXUmFwaWRTU0wg
    U0hBMjU2IENBIC0gRzMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCv
    VJvZWF0eLFbG1eh/9H0WA//Qi1rkjqfdVC7UBMBdmJyNkA+8EGVf2prWRHzAn7Xp
    SowLBkMEu/SW4ib2YQGRZjEiwzQ0Xz8/kS9EX9zHFLYDn4ZLDqP/oIACg8PTH2lS
    1p1kD8mD5xvEcKyU58Okaiy9uJ5p2L4KjxZjWmhxgHsw3hUEv8zTvz5IBVV6s9cQ
    DAP8m/0Ip4yM26eO8R5j3LMBL3+vV8M8SKeDaCGnL+enP/C1DPz1hNFTvA5yT2AM
    QriYrRmIV9cE7Ie/fodOoyH5U/02mEiN1vi7SPIpyGTRzFRIU4uvt2UevykzKdkp
    YEj4/5G8V1jlNS67abZZAgMBAAGjggEdMIIBGTAfBgNVHSMEGDAWgBTAephojYn7
    qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUw5zz/NNGCDS7zkZ/oHxb8+IIy1kwEgYD
    VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwNQYDVR0fBC4wLDAqoCig
    JoYkaHR0cDovL2cuc3ltY2IuY29tL2NybHMvZ3RnbG9iYWwuY3JsMC4GCCsGAQUF
    BwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDovL2cuc3ltY2QuY29tMEwGA1UdIARF
    MEMwQQYKYIZIAYb4RQEHNjAzMDEGCCsGAQUFBwIBFiVodHRwOi8vd3d3Lmdlb3Ry
    dXN0LmNvbS9yZXNvdXJjZXMvY3BzMA0GCSqGSIb3DQEBCwUAA4IBAQCjWB7GQzKs
    rC+TeLfqrlRARy1+eI1Q9vhmrNZPc9ZE768LzFvB9E+aj0l+YK/CJ8cW8fuTgZCp
    fO9vfm5FlBaEvexJ8cQO9K8EWYOHDyw7l8NaEpt7BDV7o5UzCHuTcSJCs6nZb0+B
    kvwHtnm8hEqddwnxxYny8LScVKoSew26T++TGezvfU5ho452nFnPjJSxhJf3GrkH
    uLLGTxN5279PURt/aQ1RKsHWFf83UTRlUfQevjhq7A6rvz17OQV79PP7GqHQyH5O
    ZI3NjGFVkP46yl0lD/gdo0p0Vk8aVUBwdSWmMy66S6VdU5oNMOGNX2Esr8zvsJmh
    gP8L8mJMcCaY
    -----END CERTIFICATE-----
    """
    pem_responder_cert = b"""
    -----BEGIN CERTIFICATE-----
    MIIBPjCB5KADAgECAgQHW80VMAoGCCqGSM49BAMCMCcxCzAJBgNVBAYTAlVTMRgw
    FgYDVQQDDA9DcnlwdG9ncmFwaHkgQ0EwHhcNMTgxMDA3MTIzNTEwWhcNMjgxMDA0
    MTIzNTEwWjAnMQswCQYDVQQGEwJVUzEYMBYGA1UEAwwPQ3J5cHRvZ3JhcGh5IENB
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbQ2E0N/E3R0zEG+qa+yAFXBY6Fte
    QzyvFdq7EZHDktlyUllaVJBrbX1ItV0MlayFwwQPhZmuLPpQBzuVKyrUfTAKBggq
    hkjOPQQDAgNJADBGAiEAo0NQRmfPvhWQpSvJzV+2Ag441Zeckk+bib7swduQIjIC
    IQCqYD9pArB2SWfmhQCSZkNEATlsPIML8lvlSkbNcrmrqQ==
    -----END CERTIFICATE-----
    """
    pem_responder_key = b"""
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgO+vsRu8xDIVZE+xh
    s8ESqJqcpJlwmj8CtF8HPHxrDSGhRANCAARtDYTQ38TdHTMQb6pr7IAVcFjoW15D
    PK8V2rsRkcOS2XJSWVpUkGttfUi1XQyVrIXDBA+Fma4s+lAHO5UrKtR9
    -----END PRIVATE KEY-----
    """
    der_ocsp_req = (
        b"0V0T0R0P0N0\t\x06\x05+\x0e\x03\x02\x1a\x05\x00\x04\x148\xcaF\x8c"
        b"\x07D\x8d\xf4\x81\x96\xc7mmLpQ\x9e`\xa7\xbd\x04\x14yu\xbb\x84:\xcb"
        b",\xdez\t\xbe1\x1bC\xbc\x1c*MSX\x02\x15\x00\x98\xd9\xe5\xc0\xb4\xc3"
        b"sU-\xf7|]\x0f\x1e\xb5\x12\x8eIE\xf9"
    )
    der_ocsp_resp_unauth = b"0\x03\n\x01\x06"

OCSP (Online Certificate Status Protocol) is a method of checking the
revocation status of certificates. It is specified in :rfc:`6960`, as well
as other obsoleted RFCs.


Loading Requests
~~~~~~~~~~~~~~~~

.. function:: load_der_ocsp_request(data)

    .. versionadded:: 2.4

    Deserialize an OCSP request from DER encoded data.

    :param bytes data: The DER encoded OCSP request data.

    :returns: An instance of :class:`~cryptography.x509.ocsp.OCSPRequest`.

    .. doctest::

        >>> from cryptography.x509 import ocsp
        >>> ocsp_req = ocsp.load_der_ocsp_request(der_ocsp_req)
        >>> print(ocsp_req.serial_number)
        872625873161273451176241581705670534707360122361


Creating Requests
~~~~~~~~~~~~~~~~~

.. class:: OCSPRequestBuilder

    .. versionadded:: 2.4

    This class is used to create :class:`~cryptography.x509.ocsp.OCSPRequest`
    objects.


    .. method:: add_certificate(cert, issuer, algorithm)

        Adds a request using a certificate, issuer certificate, and hash
        algorithm. You can call this method or ``add_certificate_by_hash``
        only once.

        :param cert: The :class:`~cryptography.x509.Certificate` whose validity
            is being checked.

        :param issuer: The issuer :class:`~cryptography.x509.Certificate` of
            the certificate that is being checked.

        :param algorithm: A
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            instance. For OCSP only
            :class:`~cryptography.hazmat.primitives.hashes.SHA1`,
            :class:`~cryptography.hazmat.primitives.hashes.SHA224`,
            :class:`~cryptography.hazmat.primitives.hashes.SHA256`,
            :class:`~cryptography.hazmat.primitives.hashes.SHA384`, and
            :class:`~cryptography.hazmat.primitives.hashes.SHA512` are allowed.

    .. method:: add_certificate_by_hash(issuer_name_hash, issuer_key_hash, serial_number, algorithm)

        .. versionadded:: 39.0.0

        Adds a request using the issuer's name hash, key hash, the certificate
        serial number and hash algorithm. You can call this method or
        ``add_certificate`` only once.

        :param issuer_name_hash: The hash of the issuer's DER encoded name using the
            same hash algorithm as the one specified in the ``algorithm`` parameter.
        :type issuer_name_hash: bytes

        :param issuer_key_hash: The hash of the issuer's public key bit string
            DER encoding using the same hash algorithm as the one specified in
            the ``algorithm`` parameter.
        :type issuer_key_hash: bytes

        :param serial_number: The serial number of the certificate being checked.
        :type serial_number: int

        :param algorithm: A
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            instance. For OCSP only
            :class:`~cryptography.hazmat.primitives.hashes.SHA1`,
            :class:`~cryptography.hazmat.primitives.hashes.SHA224`,
            :class:`~cryptography.hazmat.primitives.hashes.SHA256`,
            :class:`~cryptography.hazmat.primitives.hashes.SHA384`, and
            :class:`~cryptography.hazmat.primitives.hashes.SHA512` are allowed.

    .. method:: add_extension(extval, critical)

        Adds an extension to the request.

        :param extval: An extension conforming to the
            :class:`~cryptography.x509.ExtensionType` interface.

        :param critical: Set to ``True`` if the extension must be understood and
             handled.

    .. method:: build()

        :returns: A new :class:`~cryptography.x509.ocsp.OCSPRequest`.

    .. doctest::

        >>> from cryptography.hazmat.primitives import serialization
        >>> from cryptography.hazmat.primitives.hashes import SHA256
        >>> from cryptography.x509 import load_pem_x509_certificate, ocsp
        >>> cert = load_pem_x509_certificate(pem_cert)
        >>> issuer = load_pem_x509_certificate(pem_issuer)
        >>> builder = ocsp.OCSPRequestBuilder()
        >>> # SHA256 is in this example because while RFC 5019 originally
        >>> # required SHA1 RFC 6960 updates that to SHA256.
        >>> # However, depending on your requirements you may need to use SHA1
        >>> # for compatibility reasons.
        >>> builder = builder.add_certificate(cert, issuer, SHA256())
        >>> req = builder.build()
        >>> base64.b64encode(req.public_bytes(serialization.Encoding.DER))
        b'MF8wXTBbMFkwVzANBglghkgBZQMEAgEFAAQgn3BowBaoh77h17ULfkX6781dUDPD82Taj8wO1jZWhZoEINxPgjoQth3w7q4AouKKerMxIMIuUG4EuWU2pZfwih52AgI/IA=='

Loading Responses
~~~~~~~~~~~~~~~~~

.. function:: load_der_ocsp_response(data)

    .. versionadded:: 2.4

    Deserialize an OCSP response from DER encoded data.

    :param bytes data: The DER encoded OCSP response data.

    :returns: An instance of :class:`~cryptography.x509.ocsp.OCSPResponse`.

    .. doctest::

        >>> from cryptography.x509 import ocsp
        >>> ocsp_resp = ocsp.load_der_ocsp_response(der_ocsp_resp_unauth)
        >>> print(ocsp_resp.response_status)
        OCSPResponseStatus.UNAUTHORIZED


Creating Responses
~~~~~~~~~~~~~~~~~~

.. class:: OCSPResponseBuilder

    .. versionadded:: 2.4

    This class is used to create :class:`~cryptography.x509.ocsp.OCSPResponse`
    objects. You cannot set ``produced_at`` on OCSP responses at this time.
    Instead the field is set to current UTC time when calling ``sign``. For
    unsuccessful statuses call the class method
    :meth:`~cryptography.x509.ocsp.OCSPResponseBuilder.build_unsuccessful`.

    .. method:: add_response(cert, issuer, algorithm, cert_status, this_update, next_update, revocation_time, revocation_reason)

        This method adds status information about the certificate that was
        requested to the response.

        :param cert: The :class:`~cryptography.x509.Certificate` whose validity
            is being checked.

        :param issuer: The issuer :class:`~cryptography.x509.Certificate` of
            the certificate that is being checked.

        :param algorithm: A
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            instance. For OCSP only
            :class:`~cryptography.hazmat.primitives.hashes.SHA1`,
            :class:`~cryptography.hazmat.primitives.hashes.SHA224`,
            :class:`~cryptography.hazmat.primitives.hashes.SHA256`,
            :class:`~cryptography.hazmat.primitives.hashes.SHA384`, and
            :class:`~cryptography.hazmat.primitives.hashes.SHA512` are allowed.

        :param cert_status: An item from the
            :class:`~cryptography.x509.ocsp.OCSPCertStatus` enumeration.

        :param this_update: A naïve :class:`datetime.datetime` object
            representing the most recent time in UTC at which the status being
            indicated is known by the responder to be correct.

        :param next_update: A naïve :class:`datetime.datetime` object or
            ``None``. The time in UTC at or before which newer information will
            be available about the status of the certificate.

        :param revocation_time: A naïve :class:`datetime.datetime` object or
            ``None`` if the ``cert`` is not revoked. The time in UTC at which
            the certificate was revoked.

        :param revocation_reason: An item from the
            :class:`~cryptography.x509.ReasonFlags` enumeration or ``None`` if
            the ``cert`` is not revoked.

    .. method:: certificates(certs)

        Add additional certificates that should be used to verify the
        signature on the response. This is typically used when the responder
        utilizes an OCSP delegate.

        :param list certs: A list of :class:`~cryptography.x509.Certificate`
            objects.

    .. method:: responder_id(encoding, responder_cert)

        Set the ``responderID`` on the OCSP response. This is the data a
        client will use to determine what certificate signed the response.

        :param responder_cert: The :class:`~cryptography.x509.Certificate`
            object for the certificate whose private key will sign the
            OCSP response. If the certificate and key do not match an
            error will be raised when calling ``sign``.
        :param encoding: Either
            :attr:`~cryptography.x509.ocsp.OCSPResponderEncoding.HASH` or
            :attr:`~cryptography.x509.ocsp.OCSPResponderEncoding.NAME`.

    .. method:: add_extension(extval, critical)

        Adds an extension to the response.

        :param extval: An extension conforming to the
            :class:`~cryptography.x509.ExtensionType` interface.

        :param critical: Set to ``True`` if the extension must be understood and
             handled.

    .. method:: sign(private_key, algorithm)

        Creates the OCSP response that can then be serialized and sent to
        clients. This method will create a
        :attr:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL` response.

        :param private_key: The
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`,
            :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`,
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`,
            :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey` or
            :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey`
            that will be used to sign the response.

        :param algorithm: The
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` that
            will be used to generate the signature.  This must be ``None`` if
            the ``private_key`` is an
            :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`
            or an
            :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey`
            and an instance of a
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            otherwise.

        :returns: A new :class:`~cryptography.x509.ocsp.OCSPResponse`.

    .. doctest::

        >>> import datetime
        >>> from cryptography.hazmat.primitives import hashes, serialization
        >>> from cryptography.x509 import load_pem_x509_certificate, ocsp
        >>> cert = load_pem_x509_certificate(pem_cert)
        >>> issuer = load_pem_x509_certificate(pem_issuer)
        >>> responder_cert = load_pem_x509_certificate(pem_responder_cert)
        >>> responder_key = serialization.load_pem_private_key(pem_responder_key, None)
        >>> builder = ocsp.OCSPResponseBuilder()
        >>> # SHA256 is in this example because while RFC 5019 originally
        >>> # required SHA1 RFC 6960 updates that to SHA256.
        >>> # However, depending on your requirements you may need to use SHA1
        >>> # for compatibility reasons.
        >>> builder = builder.add_response(
        ...     cert=cert, issuer=issuer, algorithm=hashes.SHA256(),
        ...     cert_status=ocsp.OCSPCertStatus.GOOD,
        ...     this_update=datetime.datetime.now(),
        ...     next_update=datetime.datetime.now(),
        ...     revocation_time=None, revocation_reason=None
        ... ).responder_id(
        ...     ocsp.OCSPResponderEncoding.HASH, responder_cert
        ... )
        >>> response = builder.sign(responder_key, hashes.SHA256())
        >>> response.certificate_status
        <OCSPCertStatus.GOOD: 0>

    .. classmethod:: build_unsuccessful(response_status)

        Creates an unsigned OCSP response which can then be serialized and
        sent to clients. ``build_unsuccessful`` may only be called with a
        :class:`~cryptography.x509.ocsp.OCSPResponseStatus` that is not
        ``SUCCESSFUL``. Since this is a class method note that no other
        methods can or should be called as unsuccessful statuses do not
        encode additional data.

        :returns: A new :class:`~cryptography.x509.ocsp.OCSPResponse`.

    .. doctest::

        >>> from cryptography.hazmat.primitives import hashes, serialization
        >>> from cryptography.x509 import load_pem_x509_certificate, ocsp
        >>> response = ocsp.OCSPResponseBuilder.build_unsuccessful(
        ...     ocsp.OCSPResponseStatus.UNAUTHORIZED
        ... )
        >>> response.response_status
        <OCSPResponseStatus.UNAUTHORIZED: 6>


Interfaces
~~~~~~~~~~

.. class:: OCSPRequest

    .. versionadded:: 2.4

    An ``OCSPRequest`` is an object containing information about a certificate
    whose status is being checked.

    .. attribute:: issuer_key_hash

        :type: bytes

        The hash of the certificate issuer's key. The hash algorithm used
        is defined by the ``hash_algorithm`` property.

    .. attribute:: issuer_name_hash

        :type: bytes

        The hash of the certificate issuer's name. The hash algorithm used
        is defined by the ``hash_algorithm`` property.

    .. attribute:: hash_algorithm

        :type: :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`

        The algorithm used to generate the ``issuer_key_hash`` and
        ``issuer_name_hash``.

    .. attribute:: serial_number

        :type: int

        The serial number of the certificate to check.

    .. attribute:: extensions

        :type: :class:`~cryptography.x509.Extensions`

        The extensions encoded in the request.

    .. method:: public_bytes(encoding)

        :param encoding: The encoding to use. Only
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`
            is supported.

        :return bytes: The serialized OCSP request.

.. class:: OCSPResponse

    .. versionadded:: 2.4

    An ``OCSPResponse`` is the data provided by an OCSP responder in response
    to an ``OCSPRequest``.

    .. attribute:: response_status

        :type: :class:`~cryptography.x509.ocsp.OCSPResponseStatus`

        The status of the response.

    .. attribute:: signature_algorithm_oid

        :type: :class:`~cryptography.x509.ObjectIdentifier`

        Returns the object identifier of the signature algorithm used
        to sign the response. This will be one of the OIDs from
        :class:`~cryptography.x509.oid.SignatureAlgorithmOID`.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL`.

    .. attribute:: signature_hash_algorithm

        .. versionadded:: 2.5

        :type: :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`

        Returns the
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` which
        was used in signing this response.  Can be ``None`` if signature
        did not use separate hash
        (:attr:`~cryptography.x509.oid.SignatureAlgorithmOID.ED25519`,
        :attr:`~cryptography.x509.oid.SignatureAlgorithmOID.ED448`).

    .. attribute:: signature

        :type: bytes

        The signature bytes.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL`.

    .. attribute:: tbs_response_bytes

        :type: bytes

        The DER encoded bytes payload that is hashed and then signed. This
        data may be used to validate the signature on the OCSP response.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL`.

    .. attribute:: certificates

        :type: list

        A list of zero or more :class:`~cryptography.x509.Certificate` objects
        used to help build a chain to verify the OCSP response. This situation
        occurs when the OCSP responder uses a delegate certificate.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL`.

    .. attribute:: responder_key_hash

        :type: bytes or None

        The responder's key hash or ``None`` if the response has a
        ``responder_name``.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL`.

    .. attribute:: responder_name

        :type: :class:`~cryptography.x509.Name` or None

        The responder's ``Name`` or ``None`` if the response has a
        ``responder_key_hash``.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL`.

    .. attribute:: produced_at

        :type: :class:`datetime.datetime`

        A naïve datetime representing the time when the response was produced.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL`.

    .. attribute:: certificate_status

        :type: :class:`~cryptography.x509.ocsp.OCSPCertStatus`

        The status of the certificate being checked.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL` or
            if multiple SINGLERESPs are present.

    .. attribute:: revocation_time

        :type: :class:`datetime.datetime` or None

        A naïve datetime representing the time when the certificate was revoked
        or ``None`` if the certificate has not been revoked.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL` or
            if multiple SINGLERESPs are present.

    .. attribute:: revocation_reason

        :type: :class:`~cryptography.x509.ReasonFlags` or None

        The reason the certificate was revoked or ``None`` if not specified or
        not revoked.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL` or
            if multiple SINGLERESPs are present.

    .. attribute:: this_update

        :type: :class:`datetime.datetime`

        A naïve datetime representing the most recent time at which the status
        being indicated is known by the responder to have been correct.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL` or
            if multiple SINGLERESPs are present.

    .. attribute:: next_update

        :type: :class:`datetime.datetime`

        A naïve datetime representing the time when newer information will
        be available.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL` or
            if multiple SINGLERESPs are present.

    .. attribute:: issuer_key_hash

        :type: bytes

        The hash of the certificate issuer's key. The hash algorithm used
        is defined by the ``hash_algorithm`` property.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL` or
            if multiple SINGLERESPs are present.

    .. attribute:: issuer_name_hash

        :type: bytes

        The hash of the certificate issuer's name. The hash algorithm used
        is defined by the ``hash_algorithm`` property.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL` or
            if multiple SINGLERESPs are present.

    .. attribute:: hash_algorithm

        :type: :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`

        The algorithm used to generate the ``issuer_key_hash`` and
        ``issuer_name_hash``.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL` or
            if multiple SINGLERESPs are present.

    .. attribute:: serial_number

        :type: int

        The serial number of the certificate that was checked.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL` or
            if multiple SINGLERESPs are present.

    .. attribute:: extensions

        :type: :class:`~cryptography.x509.Extensions`

        The extensions encoded in the response.

    .. attribute:: single_extensions

        .. versionadded:: 2.9

        :type: :class:`~cryptography.x509.Extensions`

        The single extensions encoded in the response.

    .. attribute:: responses

        .. versionadded:: 37.0.0

        :type: an iterator over :class:`~cryptography.x509.ocsp.OCSPSingleResponse`

        An iterator to access individual SINGLERESP structures.

    .. method:: public_bytes(encoding)

        :param encoding: The encoding to use. Only
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`
            is supported.

        :return bytes: The serialized OCSP response.

.. class:: OCSPResponseStatus

    .. versionadded:: 2.4

    An enumeration of response statuses.

    .. attribute:: SUCCESSFUL

        Represents a successful OCSP response.

    .. attribute:: MALFORMED_REQUEST

        May be returned by an OCSP responder that is unable to parse a
        given request.

    .. attribute:: INTERNAL_ERROR

        May be returned by an OCSP responder that is currently experiencing
        operational problems.

    .. attribute:: TRY_LATER

        May be returned by an OCSP responder that is overloaded.

    .. attribute:: SIG_REQUIRED

        May be returned by an OCSP responder that requires signed OCSP
        requests.

    .. attribute:: UNAUTHORIZED

        May be returned by an OCSP responder when queried for a certificate for
        which the responder is unaware or an issuer for which the responder is
        not authoritative.


.. class:: OCSPCertStatus

    .. versionadded:: 2.4

    An enumeration of certificate statuses in an OCSP response.

    .. attribute:: GOOD

        The value for a certificate that is not revoked.

    .. attribute:: REVOKED

        The certificate being checked is revoked.

    .. attribute:: UNKNOWN

        The certificate being checked is not known to the OCSP responder.

.. class:: OCSPResponderEncoding

    .. versionadded:: 2.4

    An enumeration of ``responderID`` encodings that can be passed to
    :meth:`~cryptography.x509.ocsp.OCSPResponseBuilder.responder_id`.

    .. attribute:: HASH

        Encode the hash of the public key whose corresponding private key
        signed the response.

    .. attribute:: NAME

        Encode the X.509 ``Name`` of the certificate whose private key signed
        the response.

.. class:: OCSPSingleResponse

    .. versionadded:: 37.0.0

    A class representing a single certificate response bundled into a
    larger OCSPResponse.  Accessed via OCSPResponse.responses.

    .. attribute:: certificate_status

        :type: :class:`~cryptography.x509.ocsp.OCSPCertStatus`

        The status of the certificate being checked.

    .. attribute:: revocation_time

        :type: :class:`datetime.datetime` or None

        A naïve datetime representing the time when the certificate was revoked
        or ``None`` if the certificate has not been revoked.

    .. attribute:: revocation_reason

        :type: :class:`~cryptography.x509.ReasonFlags` or None

        The reason the certificate was revoked or ``None`` if not specified or
        not revoked.

    .. attribute:: this_update

        :type: :class:`datetime.datetime`

        A naïve datetime representing the most recent time at which the status
        being indicated is known by the responder to have been correct.

    .. attribute:: next_update

        :type: :class:`datetime.datetime`

        A naïve datetime representing the time when newer information will
        be available.

    .. attribute:: issuer_key_hash

        :type: bytes

        The hash of the certificate issuer's key. The hash algorithm used
        is defined by the ``hash_algorithm`` property.

    .. attribute:: issuer_name_hash

        :type: bytes

        The hash of the certificate issuer's name. The hash algorithm used
        is defined by the ``hash_algorithm`` property.

    .. attribute:: hash_algorithm

        :type: :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`

        The algorithm used to generate the ``issuer_key_hash`` and
        ``issuer_name_hash``.

    .. attribute:: serial_number

        :type: int

        The serial number of the certificate that was checked.
