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
    der_ocsp_req = (
        b"0V0T0R0P0N0\t\x06\x05+\x0e\x03\x02\x1a\x05\x00\x04\x148\xcaF\x8c"
        b"\x07D\x8d\xf4\x81\x96\xc7mmLpQ\x9e`\xa7\xbd\x04\x14yu\xbb\x84:\xcb"
        b",\xdez\t\xbe1\x1bC\xbc\x1c*MSX\x02\x15\x00\x98\xd9\xe5\xc0\xb4\xc3"
        b"sU-\xf7|]\x0f\x1e\xb5\x12\x8eIE\xf9"
    )

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
        algorithm. This can only be called once.

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

    .. method:: build()

        :returns: A new :class:`~cryptography.x509.ocsp.OCSPRequest`.

    .. doctest::

        >>> from cryptography.hazmat.backends import default_backend
        >>> from cryptography.hazmat.primitives import serialization
        >>> from cryptography.hazmat.primitives.hashes import SHA1
        >>> from cryptography.x509 import load_pem_x509_certificate, ocsp
        >>> cert = load_pem_x509_certificate(pem_cert, default_backend())
        >>> issuer = load_pem_x509_certificate(pem_issuer, default_backend())
        >>> builder = ocsp.OCSPRequestBuilder()
        >>> # SHA1 is in this example because RFC 5019 mandates its use.
        >>> builder = builder.add_certificate(cert, issuer, SHA1())
        >>> req = builder.build()
        >>> base64.b64encode(req.public_bytes(serialization.Encoding.DER))
        b'MEMwQTA/MD0wOzAJBgUrDgMCGgUABBRAC0Z68eay0wmDug1gfn5ZN0gkxAQUw5zz/NNGCDS7zkZ/oHxb8+IIy1kCAj8g'


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

        :type: An instance of a
            :class:`~cryptography.hazmat.primitives.hashes.Hash`

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
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL`.

    .. attribute:: revocation_time

        :type: :class:`datetime.datetime` or None

        A naïve datetime representing the time when the certificate was revoked
        or ``None`` if the certificate has not been revoked.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL`.

    .. attribute:: revocation_reason

        :type: :class:`~cryptography.x509.ReasonFlags` or None

        The reason the certificate was revoked or ``None`` if not specified or
        not revoked.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL`.

    .. attribute:: this_update

        :type: :class:`datetime.datetime`

        A naïve datetime representing the most recent time at which the status
        being indicated is known by the responder to have been correct.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL`.

    .. attribute:: next_update

        :type: :class:`datetime.datetime`

        A naïve datetime representing the time when newer information will
        be available.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL`.

    .. attribute:: issuer_key_hash

        :type: bytes

        The hash of the certificate issuer's key. The hash algorithm used
        is defined by the ``hash_algorithm`` property.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL`.

    .. attribute:: issuer_name_hash

        :type: bytes

        The hash of the certificate issuer's name. The hash algorithm used
        is defined by the ``hash_algorithm`` property.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL`.

    .. attribute:: hash_algorithm

        :type: An instance of a
            :class:`~cryptography.hazmat.primitives.hashes.Hash`

        The algorithm used to generate the ``issuer_key_hash`` and
        ``issuer_name_hash``.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL`.

    .. attribute:: serial_number

        :type: int

        The serial number of the certificate that was checked.

        :raises ValueError: If ``response_status`` is not
            :class:`~cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL`.


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
