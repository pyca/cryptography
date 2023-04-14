X.509 Reference
===============

.. currentmodule:: cryptography.x509

.. testsetup::

    pem_crl_data = b"""
    -----BEGIN X509 CRL-----
    MIIBtDCBnQIBATANBgkqhkiG9w0BAQsFADAnMQswCQYDVQQGEwJVUzEYMBYGA1UE
    AwwPY3J5cHRvZ3JhcGh5LmlvGA8yMDE1MDEwMTAwMDAwMFoYDzIwMTYwMTAxMDAw
    MDAwWjA+MDwCAQAYDzIwMTUwMTAxMDAwMDAwWjAmMBgGA1UdGAQRGA8yMDE1MDEw
    MTAwMDAwMFowCgYDVR0VBAMKAQEwDQYJKoZIhvcNAQELBQADggEBABRA4ww50Lz5
    zk1j2+aluC4HPHqb7o06h4pTDcCGeXUKXIGeP5ntGGmIoxa26sNoLeOr8+5b43Gf
    yWraHertllOwaOpNFEe+YZFaE9femtoDbf+GLMvRx/0wDfd3KxPoXnXKMXb2d1w4
    RCLgmkYx6JyvS+5ciuLQVIKC+l7jwIUeZFLJMUJ8msM4pFYoGameeZmtjMbd/TNg
    cVBfmZxNMHuLladJxvSo2esARo0TYPhYsgrREKoHwhpzSxdynjn4bOVkILfguwsN
    qtEEMZFEv5Kb0GqRp2+Iagv2S6dg9JGvxVdsoGjaB6EbYSZ3Psx4aODasIn11uwo
    X4B9vUQNXqc=
    -----END X509 CRL-----
    """.strip()

    pem_req_data = b"""
    -----BEGIN CERTIFICATE REQUEST-----
    MIICcDCCAVgCAQAwDTELMAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IB
    DwAwggEKAoIBAQCb+ec0zYAYLzk/MDdDJYvzdvEO2ZUrBYM6z1r8NedwpJfxUWqC
    hvK1cpc9EbQeCwS1eooTIGoNveeCrwL+pWdmf1sh6gz7SsxdN/07nyhSM8M6Xkec
    +tGrjyi1H/N1afwWXox3WcvBNbxu3Df5RKLDb0yt9aqhmJylbl/tbvgJesXymwmp
    Rc1vXL0fOedUtuAJ3xQ15M0pgLF8qDn4lySJz25x76pMYPeN5/a7x+SR/jj81kep
    VaVpuh/2hePV5uwUX3uWoj5sAkrBCifi4NPge0Npd6KeKVvXytLOymH/4+WvV719
    wCO+MyrkhpdHSakJDTIaQIxsqVeVVKdPLAPJAgMBAAGgHjAcBgkqhkiG9w0BCQcx
    DwwNY2hhbGxlbmdlIG1lITANBgkqhkiG9w0BAQsFAAOCAQEAMmgeSa8szbjPFD/4
    vcPBr/vBEROFGgL8mX3o5pF9gpr7nRjhLKBkgJvlRm6Ma3Xvdfc/r5Hp2ZBTA7sZ
    ZYhyeezGfCQN/Qhda1v+sCwG58IjvGfCSS7Y5tGlEBQ4MDf0Q7PYPSxaNUEBH7vo
    +M7U+nFuNSmyWlt6SFBSkohZkWoVSGx3KsAO+SAHYZ7JtqsAS/dm7Dflp8KxeDg7
    wzGBDQRpGF4CpI1VQjGSJQXSEdD+J7mtvBEOD34abRfV6zOUGzOOo3NWE6wNpYgt
    0A7gVlzSYpdwqjBdvACfXR2r/mu+4KkAvYh8WwCiTcYgGjl2pT1bO4hEmcJ0RSWy
    /fGD8Q==
    -----END CERTIFICATE REQUEST-----
    """.strip()

    pem_data = b"""
    -----BEGIN CERTIFICATE-----
    MIIDfDCCAmSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf
    MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg
    QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowQDELMAkGA1UE
    BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExEDAOBgNVBAMT
    B0dvb2QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQWJpHYo37
    Xfb7oJSPe+WvfTlzIG21WQ7MyMbGtK/m8mejCzR6c+f/pJhEH/OcDSMsXq8h5kXa
    BGqWK+vSwD/Pzp5OYGptXmGPcthDtAwlrafkGOS4GqIJ8+k9XGKs+vQUXJKsOk47
    RuzD6PZupq4s16xaLVqYbUC26UcY08GpnoLNHJZS/EmXw1ZZ3d4YZjNlpIpWFNHn
    UGmdiGKXUPX/9H0fVjIAaQwjnGAbpgyCumWgzIwPpX+ElFOUr3z7BoVnFKhIXze+
    VmQGSWxZxvWDUN90Ul0tLEpLgk3OVxUB4VUGuf15OJOpgo1xibINPmWt14Vda2N9
    yrNKloJGZNqLAgMBAAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZ
    XahmMB0GA1UdDgQWBBRYAYQkG7wrUpRKPaUQchRR9a86yTAOBgNVHQ8BAf8EBAMC
    AQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJ
    KoZIhvcNAQELBQADggEBADWHlxbmdTXNwBL/llwhQqwnazK7CC2WsXBBqgNPWj7m
    tvQ+aLG8/50Qc2Sun7o2VnwF9D18UUe8Gj3uPUYH+oSI1vDdyKcjmMbKRU4rk0eo
    3UHNDXwqIVc9CQS9smyV+x1HCwL4TTrq+LXLKx/qVij0Yqk+UJfAtrg2jnYKXsCu
    FMBQQnWCGrwa1g1TphRp/RmYHnMynYFmZrXtzFz+U9XEA7C+gPq4kqDI/iVfIT1s
    6lBtdB50lrDVwl2oYfAvW/6sC2se2QleZidUmrziVNP4oEeXINokU6T6p//HM1FG
    QYw2jOvpKcKtWCSAnegEbgsGYzATKjmPJPJ0npHFqzM=
    -----END CERTIFICATE-----
    """.strip()

    cryptography_cert_pem = b"""
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
    """.strip()

    pem_issuer_public_key = b"""
    -----BEGIN RSA PUBLIC KEY-----
    MIICCgKCAgEAyYcqyuT6oQxpvg/VSn2Zc68wZ823D0VAJ2woramFx+2KPWB7B7Ot
    tVSNRfm0OxJOU3TFAoep54Z2wgOoz0zRmeW6/7gvIuBKp2TW0qZAt3l9sgpE29iw
    CsoZQlMrLKiDPzCC6Fptk+YPSST9sqwhWDKK1QvOg68DKRxTpEek1hBpC0XRsnuX
    fvJJQqP39vxzpA0PsicI/wrvWX3vO8z+j9+botPerbeamoeHCsc0xgTLyIygWysB
    rNskxlzC2U4Kw6mQhGghlLReo1rFsO2/hLTnvLs+Y1lQhnFeOKCx1WVXhzBIyO9B
    dVVH5Cinb5wBNKvxbevRf4icdWcwtknmgKf69xj7yvFjt/vft74BB1Y5ltLYFmEb
    0JBxm5MAJfW4YnMQr0AxdjOhjHq4MN7X4ZzwEpJaYJdRmvMsMGN88cyjYPxsaOG+
    dZ/E9MmTjh0gnTjyD4gmsvR/gtTR/XFJ2wkbnnL1RyxNi6j2UW8C7tpNv0TIuArx
    3SHGPZN0WsaKTxZPb0L/ob1WBT0mhiq1GzB431cXgbxyh8EdKk+xSptA3V+ca2V2
    NuXlJIJaOoPMj/qjDW4I/peKGnk9tLknJ0hpRzz11j77pJsV0dGoGKVHIR2oZqT5
    0ZJJb5DXNbiTnspKLNmBt0YlNiXtlCIPxVUkhL141FuCLc8h6FjD6E0CAwEAAQ==
    -----END RSA PUBLIC KEY-----
    """.strip()

    pem_data_to_check = b"""
    -----BEGIN CERTIFICATE-----
    MIIErjCCApagAwIBAgIUUrUZsZrrBmRD2hvRuspp+lPsZXcwDQYJKoZIhvcNAQEN
    BQAwETEPMA0GA1UEAwwGSXNzdWVyMB4XDTE4MTAwODEzNDg1NFoXDTE4MTAxODEz
    NDg1NFowETEPMA0GA1UEAwwGSXNzdWVyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
    MIICCgKCAgEAyYcqyuT6oQxpvg/VSn2Zc68wZ823D0VAJ2woramFx+2KPWB7B7Ot
    tVSNRfm0OxJOU3TFAoep54Z2wgOoz0zRmeW6/7gvIuBKp2TW0qZAt3l9sgpE29iw
    CsoZQlMrLKiDPzCC6Fptk+YPSST9sqwhWDKK1QvOg68DKRxTpEek1hBpC0XRsnuX
    fvJJQqP39vxzpA0PsicI/wrvWX3vO8z+j9+botPerbeamoeHCsc0xgTLyIygWysB
    rNskxlzC2U4Kw6mQhGghlLReo1rFsO2/hLTnvLs+Y1lQhnFeOKCx1WVXhzBIyO9B
    dVVH5Cinb5wBNKvxbevRf4icdWcwtknmgKf69xj7yvFjt/vft74BB1Y5ltLYFmEb
    0JBxm5MAJfW4YnMQr0AxdjOhjHq4MN7X4ZzwEpJaYJdRmvMsMGN88cyjYPxsaOG+
    dZ/E9MmTjh0gnTjyD4gmsvR/gtTR/XFJ2wkbnnL1RyxNi6j2UW8C7tpNv0TIuArx
    3SHGPZN0WsaKTxZPb0L/ob1WBT0mhiq1GzB431cXgbxyh8EdKk+xSptA3V+ca2V2
    NuXlJIJaOoPMj/qjDW4I/peKGnk9tLknJ0hpRzz11j77pJsV0dGoGKVHIR2oZqT5
    0ZJJb5DXNbiTnspKLNmBt0YlNiXtlCIPxVUkhL141FuCLc8h6FjD6E0CAwEAATAN
    BgkqhkiG9w0BAQ0FAAOCAgEAVFzNKhEpkH8V8l0NEBAZHNi1e+lcg35fZZ9plqcw
    Pvk+6M7LW0KD0QWYQWm/dJme4DFsM7lh5u4/m+H4yS7/RP9pads9YwBudchvGR1c
    S4CCrRAmO8/A0vpQJcEwdS7fdYShBsqMrZ2TvzceVn2dvQbxB6pLkK7KIbDPVJA2
    HXFFXe2npHmdc80iTz2ShbdVSvyPvk6vc6NFFCg6lSQFuif3vV0+aYqi6DXv4h92
    9qAdES8ZLDfDulxyajyPbtF35f2Of99CumP5UzG4RQbvtI8gShuK1YFYe2sWJFE0
    MgSsqGCbl5mcrWxm9YxysRKMZ+Hc4tnkvfmG6GsKtp8u/5pG11XgxXaQl4fZ7JNa
    QFuD5gEXkEC1mCnhWlnguJgjQlpKadMOORmVTqG9dNQ6GEsha+XWpinm5L9fEZuA
    F88nNyubKLwEl68N7WWWKQlIl4q8Pe5FEp1pd9rLjOW4gzgYBccIfBK3oMC7uFJg
    a/9GeOKPiq90UMrCI+CAsIbzuPOaAp3g69JonuDwcs4cu8ui1udxs9q7ox3qSWGZ
    G1U/hmwvZH9kfIv5BKIzNLy4oxXPDJ7MZIBsxVxaNv8KUQ/JLtpVJa3oYqEx18+V
    JNr8Pr3y61X8pLmJnaCu+ixshiy2gjxXxDFBVEEt1G9JHrSs3R+yvcHxCrM3+ian
    Nh4=
    -----END CERTIFICATE-----
    """.strip()

Loading Certificates
~~~~~~~~~~~~~~~~~~~~

.. function:: load_pem_x509_certificate(data)
    :canonical: cryptography.x509.base.load_pem_x509_certificate

    .. versionadded:: 0.7

    Deserialize a certificate from PEM encoded data. PEM certificates are
    base64 decoded and have delimiters that look like
    ``-----BEGIN CERTIFICATE-----``.

    :param bytes data: The PEM encoded certificate data.

    :returns: An instance of :class:`~cryptography.x509.Certificate`.

    .. doctest::

        >>> from cryptography import x509
        >>> cert = x509.load_pem_x509_certificate(pem_data)
        >>> cert.serial_number
        2

.. function:: load_pem_x509_certificates(data)
    :canonical: cryptography.x509.base.load_pem_x509_certificates

    .. versionadded:: 39.0.0

    Deserialize one or more certificates from PEM encoded data.

    This is like :func:`~cryptography.x509.load_pem_x509_certificate`, but
    allows for loading multiple certificates (as adjacent PEMs) at once.

    :param bytes data: One or more PEM-encoded certificates.

    :returns: list of :class:`~cryptography.x509.Certificate`

    :raises ValueError: If there isn't at least one certificate, or if any
        certificate is malformed.

.. function:: load_der_x509_certificate(data)
    :canonical: cryptography.x509.base.load_der_x509_certificate

    .. versionadded:: 0.7

    Deserialize a certificate from DER encoded data. DER is a binary format
    and is commonly found in files with the ``.cer`` extension (although file
    extensions are not a guarantee of encoding type).

    :param bytes data: The DER encoded certificate data.

    :returns: An instance of :class:`~cryptography.x509.Certificate`.

Loading Certificate Revocation Lists
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. function:: load_pem_x509_crl(data)
    :canonical: cryptography.x509.base.load_pem_x509_crl

    .. versionadded:: 1.1

    Deserialize a certificate revocation list (CRL) from PEM encoded data. PEM
    requests are base64 decoded and have delimiters that look like
    ``-----BEGIN X509 CRL-----``.

    :param bytes data: The PEM encoded request data.

    :returns: An instance of
        :class:`~cryptography.x509.CertificateRevocationList`.

    .. doctest::

        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives import hashes
        >>> crl = x509.load_pem_x509_crl(pem_crl_data)
        >>> isinstance(crl.signature_hash_algorithm, hashes.SHA256)
        True

.. function:: load_der_x509_crl(data)
    :canonical: cryptography.x509.base.load_der_x509_crl

    .. versionadded:: 1.1

    Deserialize a certificate revocation list (CRL) from DER encoded data. DER
    is a binary format.

    :param bytes data: The DER encoded request data.

    :returns: An instance of
        :class:`~cryptography.x509.CertificateRevocationList`.

Loading Certificate Signing Requests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. function:: load_pem_x509_csr(data)
    :canonical: cryptography.x509.base.load_pem_x509_csr

    .. versionadded:: 0.9

    Deserialize a certificate signing request (CSR) from PEM encoded data. PEM
    requests are base64 decoded and have delimiters that look like
    ``-----BEGIN CERTIFICATE REQUEST-----``. This format is also known as
    PKCS#10.

    :param bytes data: The PEM encoded request data.

    :returns: An instance of
        :class:`~cryptography.x509.CertificateSigningRequest`.

    .. doctest::

        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives import hashes
        >>> csr = x509.load_pem_x509_csr(pem_req_data)
        >>> isinstance(csr.signature_hash_algorithm, hashes.SHA256)
        True

.. function:: load_der_x509_csr(data)
    :canonical: cryptography.x509.base.load_der_x509_csr

    .. versionadded:: 0.9

    Deserialize a certificate signing request (CSR) from DER encoded data. DER
    is a binary format and is not commonly used with CSRs.

    :param bytes data: The DER encoded request data.

    :returns: An instance of
        :class:`~cryptography.x509.CertificateSigningRequest`.

X.509 Certificate Object
~~~~~~~~~~~~~~~~~~~~~~~~

.. class:: Certificate
    :canonical: cryptography.x509.base.Certificate

    .. versionadded:: 0.7

    .. attribute:: version

        :type: :class:`~cryptography.x509.Version`

        The certificate version as an enumeration. Version 3 certificates are
        the latest version and also the only type you should see in practice.

        :raises cryptography.x509.InvalidVersion: If the version in the
            certificate is not a known
            :class:`X.509 version <cryptography.x509.Version>`.

        .. doctest::

            >>> cert.version
            <Version.v3: 2>

    .. method:: fingerprint(algorithm)

        :param algorithm: The
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            that will be used to generate the fingerprint.

        :return bytes: The fingerprint using the supplied hash algorithm, as
            bytes.

        .. doctest::

            >>> from cryptography.hazmat.primitives import hashes
            >>> cert.fingerprint(hashes.SHA256())
            b'\x86\xd2\x187Gc\xfc\xe7}[+E9\x8d\xb4\x8f\x10\xe5S\xda\x18u\xbe}a\x03\x08[\xac\xa04?'

    .. attribute:: serial_number

        :type: int

        The serial as a Python integer.

        .. doctest::

            >>> cert.serial_number
            2

    .. method:: public_key()

        The public key associated with the certificate.

        :returns: One of
            :data:`~cryptography.hazmat.primitives.asymmetric.types.CertificatePublicKeyTypes`.

        .. doctest::

            >>> from cryptography.hazmat.primitives.asymmetric import rsa
            >>> public_key = cert.public_key()
            >>> isinstance(public_key, rsa.RSAPublicKey)
            True

    .. attribute:: not_valid_before

        :type: :class:`datetime.datetime`

        A naïve datetime representing the beginning of the validity period for
        the certificate in UTC. This value is inclusive.

        .. doctest::

            >>> cert.not_valid_before
            datetime.datetime(2010, 1, 1, 8, 30)

    .. attribute:: not_valid_after

        :type: :class:`datetime.datetime`

        A naïve datetime representing the end of the validity period for the
        certificate in UTC. This value is inclusive.

        .. doctest::

            >>> cert.not_valid_after
            datetime.datetime(2030, 12, 31, 8, 30)

    .. attribute:: issuer

        .. versionadded:: 0.8

        :type: :class:`Name`

        The :class:`Name` of the issuer.

    .. attribute:: subject

        .. versionadded:: 0.8

        :type: :class:`Name`

        The :class:`Name` of the subject.

    .. attribute:: signature_hash_algorithm

        :type: :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`

        Returns the
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` which
        was used in signing this certificate.  Can be ``None`` if signature
        did not use separate hash
        (:attr:`~cryptography.x509.oid.SignatureAlgorithmOID.ED25519`,
        :attr:`~cryptography.x509.oid.SignatureAlgorithmOID.ED448`).

        .. doctest::

            >>> from cryptography.hazmat.primitives import hashes
            >>> isinstance(cert.signature_hash_algorithm, hashes.SHA256)
            True

    .. attribute:: signature_algorithm_oid

        .. versionadded:: 1.6

        :type: :class:`ObjectIdentifier`

        Returns the :class:`ObjectIdentifier` of the signature algorithm used
        to sign the certificate. This will be one of the OIDs from
        :class:`~cryptography.x509.oid.SignatureAlgorithmOID`.


        .. doctest::

            >>> cert.signature_algorithm_oid
            <ObjectIdentifier(oid=1.2.840.113549.1.1.11, name=sha256WithRSAEncryption)>

    .. attribute:: extensions

        :type: :class:`Extensions`

        The extensions encoded in the certificate.

        :raises cryptography.x509.DuplicateExtension: If more than one
            extension of the same type is found within the certificate.

        :raises cryptography.x509.UnsupportedGeneralNameType: If an extension
            contains a general name that is not supported.

        .. doctest::

            >>> for ext in cert.extensions:
            ...     print(ext)
            <Extension(oid=<ObjectIdentifier(oid=2.5.29.35, name=authorityKeyIdentifier)>, critical=False, value=<AuthorityKeyIdentifier(key_identifier=b'\xe4}_\xd1\\\x95\x86\x08,\x05\xae\xbeu\xb6e\xa7\xd9]\xa8f', authority_cert_issuer=None, authority_cert_serial_number=None)>)>
            <Extension(oid=<ObjectIdentifier(oid=2.5.29.14, name=subjectKeyIdentifier)>, critical=False, value=<SubjectKeyIdentifier(digest=b'X\x01\x84$\x1b\xbc+R\x94J=\xa5\x10r\x14Q\xf5\xaf:\xc9')>)>
            <Extension(oid=<ObjectIdentifier(oid=2.5.29.15, name=keyUsage)>, critical=True, value=<KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False)>)>
            <Extension(oid=<ObjectIdentifier(oid=2.5.29.32, name=certificatePolicies)>, critical=False, value=<CertificatePolicies([<PolicyInformation(policy_identifier=<ObjectIdentifier(oid=2.16.840.1.101.3.2.1.48.1, name=Unknown OID)>, policy_qualifiers=None)>])>)>
            <Extension(oid=<ObjectIdentifier(oid=2.5.29.19, name=basicConstraints)>, critical=True, value=<BasicConstraints(ca=True, path_length=None)>)>

    .. attribute:: signature

        .. versionadded:: 1.2

        :type: bytes

        The bytes of the certificate's signature.

    .. attribute:: tbs_certificate_bytes

        .. versionadded:: 1.2

        :type: bytes

        The DER encoded bytes payload (as defined by :rfc:`5280`) that is hashed
        and then signed by the private key of the certificate's issuer. This
        data may be used to validate a signature, but use extreme caution as
        certificate validation is a complex problem that involves much more
        than just signature checks.

        To validate the signature on a certificate you can do the following.
        Note: This only verifies that the certificate was signed with the
        private key associated with the public key provided and does not
        perform any of the other checks needed for secure certificate
        validation. Additionally, this example will only work for RSA public
        keys with ``PKCS1v15`` signatures, and so it can't be used for general
        purpose signature verification.

        .. doctest::

           >>> from cryptography.hazmat.primitives.serialization import load_pem_public_key
           >>> from cryptography.hazmat.primitives.asymmetric import padding
           >>> issuer_public_key = load_pem_public_key(pem_issuer_public_key)
           >>> cert_to_check = x509.load_pem_x509_certificate(pem_data_to_check)
           >>> issuer_public_key.verify(
           ...     cert_to_check.signature,
           ...     cert_to_check.tbs_certificate_bytes,
           ...     # Depends on the algorithm used to create the certificate
           ...     padding.PKCS1v15(),
           ...     cert_to_check.signature_hash_algorithm,
           ... )

       An :class:`~cryptography.exceptions.InvalidSignature` exception will be
       raised if the signature fails to verify.

    .. method:: verify_directly_issued_by(issuer)

        .. versionadded:: 40.0.0

        :param issuer: The issuer certificate to check against.
        :type issuer: :class:`~cryptography.x509.Certificate`

        .. warning::
            This method verifies that the certificate issuer name matches the
            issuer subject name and that the certificate is signed by the
            issuer's private key. **No other validation is performed.**
            Callers are responsible for performing any additional
            validations required for their use case (e.g. checking the validity
            period, whether the signer is allowed to issue certificates,
            that the issuing certificate has a strong public key, etc).

        Validates that the certificate is signed by the provided issuer and
        that the issuer's subject name matches the issuer name of the
        certificate.

        :return: None
        :raise ValueError: If the issuer name on the certificate does
            not match the subject name of the issuer or the signature
            algorithm is unsupported.
        :raise TypeError: If the issuer does not have a supported public
            key type.
        :raise cryptography.exceptions.InvalidSignature: If the
            signature fails to verify.


    .. attribute:: tbs_precertificate_bytes

        .. versionadded:: 38.0.0

        :type: bytes

        :raises ValueError: If the certificate doesn't have the expected
            Certificate Transparency extensions.

        The DER encoded bytes payload (as defined by :rfc:`6962`) that is hashed
        and then signed by the private key of the pre-certificate's issuer.
        This data may be used to validate a Signed Certificate Timestamp's
        signature, but use extreme caution as SCT validation is a complex
        problem that involves much more than just signature checks.

        This method is primarily useful in the context of programs that
        interact with and verify the products of Certificate Transparency logs,
        as specified in :rfc:`6962`. If you are not directly interacting with a
        Certificate Transparency log, this method unlikely to be what you
        want. To make unintentional misuse less likely, it raises a
        ``ValueError`` if the underlying certificate does not contain the
        expected Certificate Transparency extensions.

    .. method:: public_bytes(encoding)

        .. versionadded:: 1.0

        :param encoding: The
            :class:`~cryptography.hazmat.primitives.serialization.Encoding`
            that will be used to serialize the certificate.

        :return bytes: The data that can be written to a file or sent
            over the network to be verified by clients.

X.509 CRL (Certificate Revocation List) Object
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. class:: CertificateRevocationList
    :canonical: cryptography.x509.base.CertificateRevocationList

    .. versionadded:: 1.0

    A CertificateRevocationList is an object representing a list of revoked
    certificates. The object is iterable and will yield the RevokedCertificate
    objects stored in this CRL.

    .. doctest::

            >>> len(crl)
            1
            >>> revoked_certificate = crl[0]
            >>> type(revoked_certificate)
            <class '...RevokedCertificate'>
            >>> for r in crl:
            ...     print(r.serial_number)
            0

    .. method:: fingerprint(algorithm)

        :param algorithm: The
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            that will be used to generate the fingerprint.

        :return bytes: The fingerprint using the supplied hash algorithm, as
            bytes.

        .. doctest::

            >>> from cryptography.hazmat.primitives import hashes
            >>> crl.fingerprint(hashes.SHA256())
            b'\xe3\x1d\xb5P\x18\x9ed\x9f\x16O\x9dm\xc1>\x8c\xca\xb1\xc6x?T\x9f\xe9t_\x1d\x8dF8V\xf78'

    .. method:: get_revoked_certificate_by_serial_number(serial_number)

        .. versionadded:: 2.3

        :param serial_number: The serial as a Python integer.
        :returns: :class:`~cryptography.x509.RevokedCertificate` if the
            ``serial_number`` is present in the CRL or ``None`` if it
            is not.

    .. attribute:: signature_hash_algorithm

        :type: :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`

        Returns the
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` which
        was used in signing this CRL.  Can be ``None`` if signature
        did not use separate hash
        (:attr:`~cryptography.x509.oid.SignatureAlgorithmOID.ED25519`,
        :attr:`~cryptography.x509.oid.SignatureAlgorithmOID.ED448`).

        .. doctest::

            >>> from cryptography.hazmat.primitives import hashes
            >>> isinstance(crl.signature_hash_algorithm, hashes.SHA256)
            True

    .. attribute:: signature_algorithm_oid

        .. versionadded:: 1.6

        :type: :class:`ObjectIdentifier`

        Returns the :class:`ObjectIdentifier` of the signature algorithm used
        to sign the CRL. This will be one of the OIDs from
        :class:`~cryptography.x509.oid.SignatureAlgorithmOID`.

        .. doctest::

            >>> crl.signature_algorithm_oid
            <ObjectIdentifier(oid=1.2.840.113549.1.1.11, name=sha256WithRSAEncryption)>

    .. attribute:: issuer

        :type: :class:`Name`

        The :class:`Name` of the issuer.

        .. doctest::

            >>> crl.issuer
            <Name(C=US,CN=cryptography.io)>

    .. attribute:: next_update

        :type: :class:`datetime.datetime`

        A naïve datetime representing when the next update to this CRL is
        expected.

        .. doctest::

            >>> crl.next_update
            datetime.datetime(2016, 1, 1, 0, 0)

    .. attribute:: last_update

        :type: :class:`datetime.datetime`

        A naïve datetime representing when this CRL was last updated.

        .. doctest::

            >>> crl.last_update
            datetime.datetime(2015, 1, 1, 0, 0)

    .. attribute:: extensions

        :type: :class:`Extensions`

        The extensions encoded in the CRL.

    .. attribute:: signature

        .. versionadded:: 1.2

        :type: bytes

        The bytes of the CRL's signature.

    .. attribute:: tbs_certlist_bytes

        .. versionadded:: 1.2

        :type: bytes

        The DER encoded bytes payload (as defined by :rfc:`5280`) that is hashed
        and then signed by the private key of the CRL's issuer. This data may be
        used to validate a signature, but use extreme caution as CRL validation
        is a complex problem that involves much more than just signature checks.

    .. method:: public_bytes(encoding)

        .. versionadded:: 1.2

        :param encoding: The
            :class:`~cryptography.hazmat.primitives.serialization.Encoding`
            that will be used to serialize the certificate revocation list.

        :return bytes: The data that can be written to a file or sent
            over the network and used as part of a certificate verification
            process.

    .. method:: is_signature_valid(public_key)

        .. versionadded:: 2.1

        .. warning::

            Checking the validity of the signature on the CRL is insufficient
            to know if the CRL should be trusted. More details are available
            in :rfc:`5280`.

        Returns True if the CRL signature is correct for given public key,
        False otherwise.

X.509 Certificate Builder
~~~~~~~~~~~~~~~~~~~~~~~~~

.. class:: CertificateBuilder
    :canonical: cryptography.x509.base.CertificateBuilder

    .. versionadded:: 1.0

    .. doctest::

        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives import hashes
        >>> from cryptography.hazmat.primitives.asymmetric import rsa
        >>> from cryptography.x509.oid import NameOID
        >>> import datetime
        >>> one_day = datetime.timedelta(1, 0, 0)
        >>> private_key = rsa.generate_private_key(
        ...     public_exponent=65537,
        ...     key_size=2048,
        ... )
        >>> public_key = private_key.public_key()
        >>> builder = x509.CertificateBuilder()
        >>> builder = builder.subject_name(x509.Name([
        ...     x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
        ... ]))
        >>> builder = builder.issuer_name(x509.Name([
        ...     x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
        ... ]))
        >>> builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        >>> builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
        >>> builder = builder.serial_number(x509.random_serial_number())
        >>> builder = builder.public_key(public_key)
        >>> builder = builder.add_extension(
        ...     x509.SubjectAlternativeName(
        ...         [x509.DNSName(u'cryptography.io')]
        ...     ),
        ...     critical=False
        ... )
        >>> builder = builder.add_extension(
        ...     x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ... )
        >>> certificate = builder.sign(
        ...     private_key=private_key, algorithm=hashes.SHA256(),
        ... )
        >>> isinstance(certificate, x509.Certificate)
        True

    .. method:: issuer_name(name)

        Sets the issuer's distinguished name.

        :param name: The :class:`~cryptography.x509.Name` that describes the
            issuer (CA).

    .. method:: subject_name(name)

        Sets the subject's distinguished name.

        :param name: The :class:`~cryptography.x509.Name` that describes the
            subject.

    .. method:: public_key(public_key)

        Sets the subject's public key.

        :param public_key: The subject's public key. This can be one of
            :data:`~cryptography.hazmat.primitives.asymmetric.types.CertificatePublicKeyTypes`.

    .. method:: serial_number(serial_number)

        Sets the certificate's serial number (an integer).  The CA's policy
        determines how it attributes serial numbers to certificates. This
        number must uniquely identify the certificate given the issuer.
        `CABForum Guidelines`_ require entropy in the serial number
        to provide protection against hash collision attacks. For more
        information on secure random number generation, see
        :doc:`/random-numbers`.

        :param serial_number: Integer number that will be used by the CA to
            identify this certificate (most notably during certificate
            revocation checking). Users should consider using
            :func:`~cryptography.x509.random_serial_number` when possible.

    .. method:: not_valid_before(time)

        Sets the certificate's activation time.  This is the time from which
        clients can start trusting the certificate.  It may be different from
        the time at which the certificate was created.

        :param time: The :class:`datetime.datetime` object (in UTC) that marks the
            activation time for the certificate.  The certificate may not be
            trusted clients if it is used before this time.

    .. method:: not_valid_after(time)

        Sets the certificate's expiration time.  This is the time from which
        clients should no longer trust the certificate.  The CA's policy will
        determine how long the certificate should remain in use.

        :param time: The :class:`datetime.datetime` object (in UTC) that marks the
            expiration time for the certificate.  The certificate may not be
            trusted clients if it is used after this time.

    .. method:: add_extension(extval, critical)

        Adds an X.509 extension to the certificate.

        :param extval: An extension conforming to the
            :class:`~cryptography.x509.ExtensionType` interface.

        :param critical: Set to ``True`` if the extension must be understood and
             handled by whoever reads the certificate.

    .. method:: sign(private_key, algorithm)

        Sign the certificate using the CA's private key.

        :param private_key: The key that will be used to sign the certificate,
            one of
            :data:`~cryptography.hazmat.primitives.asymmetric.types.CertificateIssuerPrivateKeyTypes`.

        :param algorithm: The
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` that
            will be used to generate the signature. This must be ``None`` if
            the ``private_key`` is an
            :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`
            or an
            :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey`
            and an instance of a
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            otherwise.

        :returns: :class:`~cryptography.x509.Certificate`


X.509 CSR (Certificate Signing Request) Object
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. class:: CertificateSigningRequest
    :canonical: cryptography.x509.base.CertificateSigningRequest

    .. versionadded:: 0.9

    .. method:: public_key()

        The public key associated with the request.

        :returns: One of
            :data:`~cryptography.hazmat.primitives.asymmetric.types.CertificatePublicKeyTypes`.

        .. doctest::

            >>> from cryptography.hazmat.primitives.asymmetric import rsa
            >>> public_key = csr.public_key()
            >>> isinstance(public_key, rsa.RSAPublicKey)
            True

    .. attribute:: subject

        :type: :class:`Name`

        The :class:`Name` of the subject.

    .. attribute:: signature_hash_algorithm

        :type: :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`

        Returns the
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` which
        was used in signing this request.  Can be ``None`` if signature
        did not use separate hash
        (:attr:`~cryptography.x509.oid.SignatureAlgorithmOID.ED25519`,
        :attr:`~cryptography.x509.oid.SignatureAlgorithmOID.ED448`).

        .. doctest::

            >>> from cryptography.hazmat.primitives import hashes
            >>> isinstance(csr.signature_hash_algorithm, hashes.SHA256)
            True

    .. attribute:: signature_algorithm_oid

        .. versionadded:: 1.6

        :type: :class:`ObjectIdentifier`

        Returns the :class:`ObjectIdentifier` of the signature algorithm used
        to sign the request. This will be one of the OIDs from
        :class:`~cryptography.x509.oid.SignatureAlgorithmOID`.

        .. doctest::

            >>> csr.signature_algorithm_oid
            <ObjectIdentifier(oid=1.2.840.113549.1.1.11, name=sha256WithRSAEncryption)>

    .. attribute:: extensions

        :type: :class:`Extensions`

        The extensions encoded in the certificate signing request.

        :raises cryptography.x509.DuplicateExtension: If more than one
            extension of the same type is found within the certificate signing request.

        :raises cryptography.x509.UnsupportedGeneralNameType: If an extension
            contains a general name that is not supported.

    .. attribute:: attributes

        .. versionadded:: 36.0.0

        :type: :class:`Attributes`

        The attributes encoded in the certificate signing request.

    .. method:: public_bytes(encoding)

        .. versionadded:: 1.0

        :param encoding: The
            :class:`~cryptography.hazmat.primitives.serialization.Encoding`
            that will be used to serialize the certificate request.

        :return bytes: The data that can be written to a file or sent
            over the network to be signed by the certificate
            authority.

    .. attribute:: signature

        .. versionadded:: 1.2

        :type: bytes

        The bytes of the certificate signing request's signature.

    .. attribute:: tbs_certrequest_bytes

        .. versionadded:: 1.2

        :type: bytes

        The DER encoded bytes payload (as defined by :rfc:`2986`) that is
        hashed and then signed by the private key (corresponding to the public
        key embedded in the CSR). This data may be used to validate the CSR
        signature.

    .. attribute:: is_signature_valid

        .. versionadded:: 1.3

        Returns True if the CSR signature is correct, False otherwise.

X.509 Certificate Revocation List Builder
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. class:: CertificateRevocationListBuilder
    :canonical: cryptography.x509.base.CertificateRevocationListBuilder

    .. versionadded:: 1.2

    .. doctest::

        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives import hashes
        >>> from cryptography.hazmat.primitives.asymmetric import rsa
        >>> from cryptography.x509.oid import NameOID
        >>> import datetime
        >>> one_day = datetime.timedelta(1, 0, 0)
        >>> private_key = rsa.generate_private_key(
        ...     public_exponent=65537,
        ...     key_size=2048,
        ... )
        >>> builder = x509.CertificateRevocationListBuilder()
        >>> builder = builder.issuer_name(x509.Name([
        ...     x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io CA'),
        ... ]))
        >>> builder = builder.last_update(datetime.datetime.today())
        >>> builder = builder.next_update(datetime.datetime.today() + one_day)
        >>> revoked_cert = x509.RevokedCertificateBuilder().serial_number(
        ...     333
        ... ).revocation_date(
        ...     datetime.datetime.today()
        ... ).build()
        >>> builder = builder.add_revoked_certificate(revoked_cert)
        >>> crl = builder.sign(
        ...     private_key=private_key, algorithm=hashes.SHA256(),
        ... )
        >>> len(crl)
        1

    .. method:: issuer_name(name)

        Sets the issuer's distinguished name.

        :param name: The :class:`~cryptography.x509.Name` that describes the
            issuer (CA).

    .. method:: last_update(time)

        Sets this CRL's activation time.  This is the time from which
        clients can start trusting this CRL.  It may be different from
        the time at which this CRL was created. This is also known as the
        ``thisUpdate`` time.

        :param time: The :class:`datetime.datetime` object (in UTC) that marks
            the activation time for this CRL.  The CRL may not be trusted if it
            is used before this time.

    .. method:: next_update(time)

        Sets this CRL's next update time. This is the time by which
        a new CRL will be issued. The CA is allowed to issue a new CRL before
        this date, however clients are not required to check for it.

        :param time: The :class:`datetime.datetime` object (in UTC) that marks
            the next update time for this CRL.

    .. method:: add_extension(extval, critical)

        Adds an X.509 extension to this CRL.

        :param extval: An extension with the
            :class:`~cryptography.x509.ExtensionType` interface.

        :param critical: Set to ``True`` if the extension must be understood and
             handled by whoever reads the CRL.

    .. method:: add_revoked_certificate(revoked_certificate)

        Adds a revoked certificate to this CRL.

        :param revoked_certificate: An instance of
            :class:`~cryptography.x509.RevokedCertificate`. These can be
            obtained from an existing CRL or created with
            :class:`~cryptography.x509.RevokedCertificateBuilder`.

    .. method:: sign(private_key, algorithm)

        Sign this CRL using the CA's private key.

        :param private_key: The private key that will be used to sign the
            certificate, one of
            :data:`~cryptography.hazmat.primitives.asymmetric.types.CertificateIssuerPrivateKeyTypes`.

        :param algorithm: The
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` that
            will be used to generate the signature.
            This must be ``None`` if the ``private_key`` is an
            :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`
            or an
            :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey`
            and an instance of a
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            otherwise.

        :returns: :class:`~cryptography.x509.CertificateRevocationList`

X.509 Revoked Certificate Object
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. class:: RevokedCertificate
    :canonical: cryptography.x509.base.RevokedCertificate

    .. versionadded:: 1.0

    .. attribute:: serial_number

        :type: :class:`int`

        An integer representing the serial number of the revoked certificate.

        .. doctest::

            >>> revoked_certificate.serial_number
            0

    .. attribute:: revocation_date

        :type: :class:`datetime.datetime`

        A naïve datetime representing the date this certificates was revoked.

        .. doctest::

            >>> revoked_certificate.revocation_date
            datetime.datetime(2015, 1, 1, 0, 0)

    .. attribute:: extensions

        :type: :class:`Extensions`

        The extensions encoded in the revoked certificate.

        .. doctest::

            >>> for ext in revoked_certificate.extensions:
            ...     print(ext)
            <Extension(oid=<ObjectIdentifier(oid=2.5.29.24, name=invalidityDate)>, critical=False, value=<InvalidityDate(invalidity_date=2015-01-01 00:00:00)>)>
            <Extension(oid=<ObjectIdentifier(oid=2.5.29.21, name=cRLReason)>, critical=False, value=<CRLReason(reason=ReasonFlags.key_compromise)>)>

X.509 Revoked Certificate Builder
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. class:: RevokedCertificateBuilder
    :canonical: cryptography.x509.base.RevokedCertificateBuilder

    This class is used to create :class:`~cryptography.x509.RevokedCertificate`
    objects that can be used with the
    :class:`~cryptography.x509.CertificateRevocationListBuilder`.

    .. versionadded:: 1.2

    .. doctest::

        >>> from cryptography import x509
        >>> import datetime
        >>> builder = x509.RevokedCertificateBuilder()
        >>> builder = builder.revocation_date(datetime.datetime.today())
        >>> builder = builder.serial_number(3333)
        >>> revoked_certificate = builder.build()
        >>> isinstance(revoked_certificate, x509.RevokedCertificate)
        True

    .. method:: serial_number(serial_number)

        Sets the revoked certificate's serial number.

        :param serial_number: Integer number that is used to identify the
            revoked certificate.

    .. method:: revocation_date(time)

        Sets the certificate's revocation date.

        :param time: The :class:`datetime.datetime` object (in UTC) that marks the
            revocation time for the certificate.

    .. method:: add_extension(extval, critical)

        Adds an X.509 extension to this revoked certificate.

        :param extval: An instance of one of the
            :ref:`CRL entry extensions <crl_entry_extensions>`.

        :param critical: Set to ``True`` if the extension must be understood and
             handled.

    .. method:: build()

        Create a revoked certificate object.

        :returns: :class:`~cryptography.x509.RevokedCertificate`

X.509 CSR (Certificate Signing Request) Builder Object
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. class:: CertificateSigningRequestBuilder
    :canonical: cryptography.x509.base.CertificateSigningRequestBuilder

    .. versionadded:: 1.0

    .. doctest::

        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives import hashes
        >>> from cryptography.hazmat.primitives.asymmetric import rsa
        >>> from cryptography.x509.oid import AttributeOID, NameOID
        >>> private_key = rsa.generate_private_key(
        ...     public_exponent=65537,
        ...     key_size=2048,
        ... )
        >>> builder = x509.CertificateSigningRequestBuilder()
        >>> builder = builder.subject_name(x509.Name([
        ...     x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
        ... ]))
        >>> builder = builder.add_extension(
        ...     x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ... )
        >>> builder = builder.add_attribute(
        ...     AttributeOID.CHALLENGE_PASSWORD, b"changeit"
        ... )
        >>> request = builder.sign(
        ...     private_key, hashes.SHA256()
        ... )
        >>> isinstance(request, x509.CertificateSigningRequest)
        True

    .. method:: subject_name(name)

        :param name: The :class:`~cryptography.x509.Name` of the certificate
            subject.
        :returns: A new
            :class:`~cryptography.x509.CertificateSigningRequestBuilder`.

    .. method:: add_extension(extension, critical)

        :param extension: An extension conforming to the
            :class:`~cryptography.x509.ExtensionType` interface.
        :param critical: Set to `True` if the extension must be understood and
             handled by whoever reads the certificate.
        :returns: A new
            :class:`~cryptography.x509.CertificateSigningRequestBuilder`.

    .. method:: add_attribute(oid, value)

        .. versionadded:: 3.0

        :param oid: An :class:`ObjectIdentifier` instance.
        :param value: The value of the attribute.
        :type value: bytes
        :returns: A new
            :class:`~cryptography.x509.CertificateSigningRequestBuilder`.

    .. method:: sign(private_key, algorithm)

        :param private_key: The private key
            that will be used to sign the request.  When the request is
            signed by a certificate authority, the private key's associated
            public key will be stored in the resulting certificate. One of
            :data:`~cryptography.hazmat.primitives.asymmetric.types.CertificateIssuerPrivateKeyTypes`.

        :param algorithm: The
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            that will be used to generate the request signature.
            This must be ``None`` if the ``private_key`` is an
            :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`
            or an
            :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey`
            and an instance of a
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`
            otherwise.

        :returns: A new
            :class:`~cryptography.x509.CertificateSigningRequest`.


.. class:: Name
    :canonical: cryptography.x509.name.Name

    .. versionadded:: 0.8

    An X509 Name is an ordered list of attributes. The object is iterable to
    get every attribute or you can use :meth:`Name.get_attributes_for_oid` to
    obtain the specific type you want. Names are sometimes represented as a
    slash or comma delimited string (e.g. ``/CN=mydomain.com/O=My Org/C=US`` or
    ``CN=mydomain.com,O=My Org,C=US``).

    Technically, a Name is a list of *sets* of attributes, called *Relative
    Distinguished Names* or *RDNs*, although multi-valued RDNs are rarely
    encountered.  The iteration order of values within a multi-valued RDN is
    preserved.  If you need to handle multi-valued RDNs, the ``rdns`` property
    gives access to an ordered list of :class:`RelativeDistinguishedName`
    objects.

    A Name can be initialized with an iterable of :class:`NameAttribute` (the
    common case where each RDN has a single attribute) or an iterable of
    :class:`RelativeDistinguishedName` objects (in the rare case of
    multi-valued RDNs).

    .. doctest::

        >>> len(cert.subject)
        3
        >>> for attribute in cert.subject:
        ...     print(attribute)
        <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.6, name=countryName)>, value='US')>
        <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.10, name=organizationName)>, value='Test Certificates 2011')>
        <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value='Good CA')>

    .. attribute:: rdns

        .. versionadded:: 1.6

        :type: list of :class:`RelativeDistinguishedName`

    .. classmethod:: from_rfc4514_string(data, attr_name_overrides=None)

        .. versionadded: 37.0.0

        :param str data: An :rfc:`4514` string.
        :param attr_name_overrides: Specify custom OID to name mappings, which
            can be used to match vendor-specific extensions. See
            :class:`~cryptography.x509.oid.NameOID` for common attribute
            OIDs.

        :returns: A :class:`Name` parsed from ``data``.


        .. doctest::

            >>> x509.Name.from_rfc4514_string("CN=cryptography.io")
            <Name(CN=cryptography.io)>
            >>> x509.Name.from_rfc4514_string("E=pyca@cryptography.io", {"E": NameOID.EMAIL_ADDRESS})
            <Name(1.2.840.113549.1.9.1=pyca@cryptography.io)>

    .. method:: get_attributes_for_oid(oid)

        :param oid: An :class:`ObjectIdentifier` instance.

        :returns: A list of :class:`NameAttribute` instances that match the
            OID provided. If nothing matches an empty list will be returned.

        .. doctest::

            >>> cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            [<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value='Good CA')>]

    .. method:: public_bytes()

        .. versionadded:: 1.6

        :return bytes: The DER encoded name.

    .. method:: rfc4514_string(attr_name_overrides=None)

        .. versionadded:: 2.5
        .. versionchanged:: 36.0.0

            Added ``attr_name_overrides`` parameter.

        Format the given name as a :rfc:`4514` Distinguished Name
        string, for example ``CN=mydomain.com,O=My Org,C=US``.

        By default, attributes ``CN``, ``L``, ``ST``, ``O``, ``OU``, ``C``,
        ``STREET``, ``DC``, ``UID`` are represented by their short name.
        Unrecognized attributes are formatted as dotted OID strings.

        Example:

        .. doctest::

            >>> name = x509.Name([
            ...     x509.NameAttribute(NameOID.EMAIL_ADDRESS, "santa@north.pole"),
            ...     x509.NameAttribute(NameOID.COMMON_NAME, "Santa Claus"),
            ... ])
            >>> name.rfc4514_string()
            'CN=Santa Claus,1.2.840.113549.1.9.1=santa@north.pole'
            >>> name.rfc4514_string({NameOID.EMAIL_ADDRESS: "E"})
            'CN=Santa Claus,E=santa@north.pole'

        :type attr_name_overrides:
            Dict-like mapping from :class:`~cryptography.x509.ObjectIdentifier`
            to ``str``
        :param attr_name_overrides: Specify custom OID to name mappings, which
            can be used to match vendor-specific extensions. See
            :class:`~cryptography.x509.oid.NameOID` for common attribute
            OIDs.

        :rtype: str


.. class:: Version
    :canonical: cryptography.x509.base.Version

    .. versionadded:: 0.7

    An enumeration for X.509 versions.

    .. attribute:: v1

        For version 1 X.509 certificates.

    .. attribute:: v3

        For version 3 X.509 certificates.

.. class:: NameAttribute
    :canonical: cryptography.x509.name.NameAttribute

    .. versionadded:: 0.8

    An X.509 name consists of a list of :class:`RelativeDistinguishedName`
    instances, which consist of a set of :class:`NameAttribute` instances.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        The attribute OID.

    .. attribute:: value

        :type: ``str`` or ``bytes``

        The value of the attribute. This will generally be a ``str``, the only
        times it can be a ``bytes`` is when :attr:`oid` is
        ``X500_UNIQUE_IDENTIFIER``.

    .. attribute:: rfc4514_attribute_name

        .. versionadded:: 35.0.0

        :type: str

        The :rfc:`4514` short attribute name (for example "CN"),
        or the OID dotted string if a short name is unavailable.

    .. method:: rfc4514_string(attr_name_overrides=None)

        .. versionadded:: 2.5
        .. versionchanged:: 36.0.0

            Added ``attr_name_overrides`` parameter.

        :return str: Format the given attribute as a :rfc:`4514` Distinguished
            Name string.

        :type attr_name_overrides:
            Dict-like mapping from :class:`~cryptography.x509.ObjectIdentifier`
            to ``str``
        :param attr_name_overrides: Specify custom OID to name mappings, which
            can be used to match vendor-specific extensions.


.. class:: RelativeDistinguishedName(attributes)
    :canonical: cryptography.x509.name.RelativeDistinguishedName

    .. versionadded:: 1.6

    A relative distinguished name is a non-empty set of name attributes.  The
    object is iterable to get every attribute, preserving the original order.
    Passing duplicate attributes to the constructor raises ``ValueError``.

    .. method:: get_attributes_for_oid(oid)

        :param oid: An :class:`ObjectIdentifier` instance.

        :returns: A list of :class:`NameAttribute` instances that match the OID
            provided.  The list should contain zero or one values.

    .. method:: rfc4514_string(attr_name_overrides=None)

        .. versionadded:: 2.5
        .. versionchanged:: 36.0.0

            Added ``attr_name_overrides`` parameter.

        :return str: Format the given RDN set as a :rfc:`4514` Distinguished
            Name string.

        :type attr_name_overrides:
            Dict-like mapping from :class:`~cryptography.x509.ObjectIdentifier`
            to ``str``
        :param attr_name_overrides: Specify custom OID to name mappings, which
            can be used to match vendor-specific extensions.


.. class:: ObjectIdentifier
    :canonical: ObjectIdentifier

    .. versionadded:: 0.8

    Object identifiers (frequently seen abbreviated as OID) identify the type
    of a value (see: :class:`NameAttribute`).

    .. attribute:: dotted_string

        :type: :class:`str`

        The dotted string value of the OID (e.g. ``"2.5.4.3"``)


.. _general_name_classes:

General Name Classes
~~~~~~~~~~~~~~~~~~~~

.. class:: GeneralName
    :canonical: cryptography.x509.general_name.GeneralName

    .. versionadded:: 0.9

    This is the generic interface that all the following classes are registered
    against.

.. class:: RFC822Name(value)
    :canonical: cryptography.x509.general_name.RFC822Name

    .. versionadded:: 0.9

    .. versionchanged:: 3.1

        :term:`U-label` support has been removed. Encode them to
        :term:`A-label` before use.

    This corresponds to an email address. For example, ``user@example.com``.

    :param value: The email address. If the address contains an
        internationalized domain name then it must be encoded to an
        :term:`A-label` string before being passed.

    :raises ValueError: If the provided string is not an :term:`A-label`.

    .. attribute:: value

        :type: str

.. class:: DNSName(value)
    :canonical: cryptography.x509.general_name.DNSName

    .. versionadded:: 0.9

    .. versionchanged:: 3.1

        :term:`U-label` support has been removed. Encode them to
        :term:`A-label` before use.

    This corresponds to a domain name. For example, ``cryptography.io``.

    :param value: The domain name. If it is an internationalized domain
        name then it must be encoded to an :term:`A-label` string before being
        passed.

    :raises ValueError: If the provided string is not an :term:`A-label`.

        :type: str

    .. attribute:: value

        :type: str

.. class:: DirectoryName(value)
    :canonical: cryptography.x509.general_name.DirectoryName

    .. versionadded:: 0.9

    This corresponds to a directory name.

    .. attribute:: value

        :type: :class:`Name`

.. class:: UniformResourceIdentifier(value)
    :canonical: cryptography.x509.general_name.UniformResourceIdentifier

    .. versionadded:: 0.9

    .. versionchanged:: 3.1

        :term:`U-label` support has been removed. Encode them to
        :term:`A-label` before use.

    This corresponds to a uniform resource identifier.  For example,
    ``https://cryptography.io``.

    :param value: The URI. If it contains an internationalized domain
        name then it must be encoded to an :term:`A-label` string before
        being passed.

    :raises ValueError: If the provided string is not an :term:`A-label`.

    .. attribute:: value

        :type: str

.. class:: IPAddress(value)
    :canonical: cryptography.x509.general_name.IPAddress

    .. versionadded:: 0.9

    This corresponds to an IP address.

    .. attribute:: value

        :type: :class:`~ipaddress.IPv4Address`,
            :class:`~ipaddress.IPv6Address`,  :class:`~ipaddress.IPv4Network`,
            or :class:`~ipaddress.IPv6Network`.

.. class:: RegisteredID(value)
    :canonical: cryptography.x509.general_name.RegisteredID

    .. versionadded:: 0.9

    This corresponds to a registered ID.

    .. attribute:: value

        :type: :class:`ObjectIdentifier`

.. class:: OtherName(type_id, value)
    :canonical: cryptography.x509.general_name.OtherName

    .. versionadded:: 1.0

    This corresponds to an ``otherName.``  An ``otherName`` has a type identifier and a value represented in binary DER format.

    .. attribute:: type_id

        :type: :class:`ObjectIdentifier`

    .. attribute:: value

        :type: bytes

X.509 Extensions
~~~~~~~~~~~~~~~~

.. class:: Extensions
    :canonical: cryptography.x509.extensions.Extensions

    .. versionadded:: 0.9

    An X.509 Extensions instance is an ordered list of extensions.  The object
    is iterable to get every extension.

    .. method:: get_extension_for_oid(oid)

        :param oid: An :class:`ObjectIdentifier` instance.

        :returns: An instance of :class:`Extension`.

        :raises cryptography.x509.ExtensionNotFound: If the certificate does
            not have the extension requested.

        .. doctest::

            >>> from cryptography.x509.oid import ExtensionOID
            >>> cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            <Extension(oid=<ObjectIdentifier(oid=2.5.29.19, name=basicConstraints)>, critical=True, value=<BasicConstraints(ca=True, path_length=None)>)>

    .. method:: get_extension_for_class(extclass)

        .. versionadded:: 1.1

        :param extclass: An extension class.

        :returns: An instance of :class:`Extension`.

        :raises cryptography.x509.ExtensionNotFound: If the certificate does
            not have the extension requested.

        .. doctest::

            >>> from cryptography import x509
            >>> cert.extensions.get_extension_for_class(x509.BasicConstraints)
            <Extension(oid=<ObjectIdentifier(oid=2.5.29.19, name=basicConstraints)>, critical=True, value=<BasicConstraints(ca=True, path_length=None)>)>

.. class:: Extension
    :canonical: cryptography.x509.extensions.Extension

    .. versionadded:: 0.9

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        One of the :class:`~cryptography.x509.oid.ExtensionOID` OIDs.

    .. attribute:: critical

        :type: bool

        Determines whether a given extension is critical or not. :rfc:`5280`
        requires that "A certificate-using system MUST reject the certificate
        if it encounters a critical extension it does not recognize or a
        critical extension that contains information that it cannot process".

    .. attribute:: value

        Returns an instance of the extension type corresponding to the OID.

.. class:: ExtensionType
    :canonical: cryptography.x509.extensions.ExtensionType

    .. versionadded:: 1.0

    This is the interface against which all the following extension types are
    registered.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns the OID associated with the given extension type.

    .. method:: public_bytes()

        .. versionadded:: 36.0.0

        :return bytes:

            A bytes string representing the extension's DER encoded value.

.. class:: KeyUsage(digital_signature, content_commitment, key_encipherment, data_encipherment, key_agreement, key_cert_sign, crl_sign, encipher_only, decipher_only)
    :canonical: cryptography.x509.extensions.KeyUsage

    .. versionadded:: 0.9

    The key usage extension defines the purpose of the key contained in the
    certificate.  The usage restriction might be employed when a key that could
    be used for more than one operation is to be restricted.

    .. attribute:: oid

        .. versionadded:: 1.0

        :type: :class:`ObjectIdentifier`

        Returns :attr:`~cryptography.x509.oid.ExtensionOID.KEY_USAGE`.

    .. attribute:: digital_signature

        :type: bool

        This purpose is set to true when the subject public key is used for verifying
        digital signatures, other than signatures on certificates
        (``key_cert_sign``) and CRLs (``crl_sign``).

    .. attribute:: content_commitment

        :type: bool

        This purpose is set to true when the subject public key is used for verifying
        digital signatures, other than signatures on certificates
        (``key_cert_sign``) and CRLs (``crl_sign``). It is used to provide a
        non-repudiation service that protects against the signing entity
        falsely denying some action. In the case of later conflict, a
        reliable third party may determine the authenticity of the signed
        data. This was called ``non_repudiation`` in older revisions of the
        X.509 specification.

    .. attribute:: key_encipherment

        :type: bool

        This purpose is set to true when the subject public key is used for
        enciphering private or secret keys.

    .. attribute:: data_encipherment

        :type: bool

        This purpose is set to true when the subject public key is used for
        directly enciphering raw user data without the use of an intermediate
        symmetric cipher.

    .. attribute:: key_agreement

        :type: bool

        This purpose is set to true when the subject public key is used for key
        agreement.  For example, when a Diffie-Hellman key is to be used for
        key management, then this purpose is set to true.

    .. attribute:: key_cert_sign

        :type: bool

        This purpose is set to true when the subject public key is used for
        verifying signatures on public key certificates. If this purpose is set
        to true then ``ca`` must be true in the :class:`BasicConstraints`
        extension.

    .. attribute:: crl_sign

        :type: bool

        This purpose is set to true when the subject public key is used for
        verifying signatures on certificate revocation lists.

    .. attribute:: encipher_only

        :type: bool

        When this purposes is set to true and the ``key_agreement`` purpose is
        also set, the subject public key may be used only for enciphering data
        while performing key agreement.

        :raises ValueError: This is raised if accessed when ``key_agreement``
            is false.

    .. attribute:: decipher_only

        :type: bool

        When this purposes is set to true and the ``key_agreement`` purpose is
        also set, the subject public key may be used only for deciphering data
        while performing key agreement.

        :raises ValueError: This is raised if accessed when ``key_agreement``
            is false.


.. class:: BasicConstraints(ca, path_length)
    :canonical: cryptography.x509.extensions.BasicConstraints

    .. versionadded:: 0.9

    Basic constraints is an X.509 extension type that defines whether a given
    certificate is allowed to sign additional certificates and what path
    length restrictions may exist.

    .. attribute:: oid

        .. versionadded:: 1.0

        :type: :class:`ObjectIdentifier`

        Returns :attr:`~cryptography.x509.oid.ExtensionOID.BASIC_CONSTRAINTS`.

    .. attribute:: ca

        :type: bool

        Whether the certificate can sign certificates.

    .. attribute:: path_length

        :type: int or None

        The maximum path length for certificates subordinate to this
        certificate. This attribute only has meaning if ``ca`` is true.
        If ``ca`` is true then a path length of None means there's no
        restriction on the number of subordinate CAs in the certificate chain.
        If it is zero or greater then it defines the maximum length for a
        subordinate CA's certificate chain. For example, a ``path_length`` of 1
        means the certificate can sign a subordinate CA, but the subordinate CA
        is not allowed to create subordinates with ``ca`` set to true.

.. class:: ExtendedKeyUsage(usages)
    :canonical: cryptography.x509.extensions.ExtendedKeyusage

    .. versionadded:: 0.9

    This extension indicates one or more purposes for which the certified
    public key may be used, in addition to or in place of the basic
    purposes indicated in the key usage extension. The object is
    iterable to obtain the list of
    :class:`~cryptography.x509.oid.ExtendedKeyUsageOID` OIDs present.

    :param list usages: A list of
        :class:`~cryptography.x509.oid.ExtendedKeyUsageOID` OIDs.

    .. attribute:: oid

        .. versionadded:: 1.0

        :type: :class:`ObjectIdentifier`

        Returns :attr:`~cryptography.x509.oid.ExtensionOID.EXTENDED_KEY_USAGE`.


.. class:: OCSPNoCheck()
    :canonical: cryptography.x509.extensions.OCSPNoCheck

    .. versionadded:: 1.0

    This presence of this extension indicates that an OCSP client can trust a
    responder for the lifetime of the responder's certificate. CAs issuing
    such a certificate should realize that a compromise of the responder's key
    is as serious as the compromise of a CA key used to sign CRLs, at least for
    the validity period of this certificate. CA's may choose to issue this type
    of certificate with a very short lifetime and renew it frequently. This
    extension is only relevant when the certificate is an authorized OCSP
    responder.

    .. attribute:: oid

        .. versionadded:: 1.0

        :type: :class:`ObjectIdentifier`

        Returns :attr:`~cryptography.x509.oid.ExtensionOID.OCSP_NO_CHECK`.


.. class:: TLSFeature(features)
    :canonical: cryptography.x509.extensions.TLSFeature

    .. versionadded:: 2.1

    The TLS Feature extension is defined in :rfc:`7633` and is used in
    certificates for OCSP Must-Staple. The object is iterable to get every
    element.

    :param list features: A list of features to enable from the
        :class:`~cryptography.x509.TLSFeatureType` enum. At this time only
        ``status_request`` or ``status_request_v2`` are allowed.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns :attr:`~cryptography.x509.oid.ExtensionOID.TLS_FEATURE`.

.. class:: TLSFeatureType
    :canonical: cryptography.x509.extensions.TLSFeatureType

    .. versionadded:: 2.1

    An enumeration of TLS Feature types.

    .. attribute:: status_request

        This feature type is defined in :rfc:`6066` and, when embedded in
        an X.509 certificate, signals to the client that it should require
        a stapled OCSP response in the TLS handshake. Commonly known as OCSP
        Must-Staple in certificates.

    .. attribute:: status_request_v2

        This feature type is defined in :rfc:`6961`. This value is not
        commonly used and if you want to enable OCSP Must-Staple you should
        use ``status_request``.


.. class:: NameConstraints(permitted_subtrees, excluded_subtrees)
    :canonical: cryptography.x509.extensions.NameConstraints

    .. versionadded:: 1.0

    The name constraints extension, which only has meaning in a CA certificate,
    defines a name space within which all subject names in certificates issued
    beneath the CA certificate must (or must not) be in. For specific details
    on the way this extension should be processed see :rfc:`5280`.

    .. attribute:: oid

        .. versionadded:: 1.0

        :type: :class:`ObjectIdentifier`

        Returns :attr:`~cryptography.x509.oid.ExtensionOID.NAME_CONSTRAINTS`.

    .. attribute:: permitted_subtrees

        :type: list of :class:`GeneralName` objects or None

        The set of permitted name patterns. If a name matches this and an
        element in ``excluded_subtrees`` it is invalid. At least one of
        ``permitted_subtrees`` and ``excluded_subtrees`` will be non-None.

    .. attribute:: excluded_subtrees

        :type: list of :class:`GeneralName` objects or None

        Any name matching a restriction in the ``excluded_subtrees`` field is
        invalid regardless of information appearing in the
        ``permitted_subtrees``. At least one of ``permitted_subtrees`` and
        ``excluded_subtrees`` will be non-None.

.. class:: AuthorityKeyIdentifier(key_identifier, authority_cert_issuer, authority_cert_serial_number)
    :canonical: cryptography.x509.extensions.AuthorityKeyIdentifier

    .. versionadded:: 0.9

    The authority key identifier extension provides a means of identifying the
    public key corresponding to the private key used to sign a certificate.
    This extension is typically used to assist in determining the appropriate
    certificate chain. For more information about generation and use of this
    extension see `RFC 5280 section 4.2.1.1`_.

    .. attribute:: oid

        .. versionadded:: 1.0

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER`.

    .. attribute:: key_identifier

        :type: bytes

        A value derived from the public key used to verify the certificate's
        signature.

    .. attribute:: authority_cert_issuer

        :type: A list of :class:`GeneralName` instances or None

        The :class:`GeneralName` (one or multiple) of the issuer's issuer.

    .. attribute:: authority_cert_serial_number

        :type: int or None

        The serial number of the issuer's issuer.

    .. classmethod:: from_issuer_public_key(public_key)

        .. versionadded:: 1.0

        .. note::

            This method should be used if the issuer certificate does not
            contain a :class:`~cryptography.x509.SubjectKeyIdentifier`.
            Otherwise, use
            :meth:`~cryptography.x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier`.

        Creates a new AuthorityKeyIdentifier instance using the public key
        provided to generate the appropriate digest. This should be the
        **issuer's public key**. The resulting object will contain
        :attr:`~cryptography.x509.AuthorityKeyIdentifier.key_identifier`, but
        :attr:`~cryptography.x509.AuthorityKeyIdentifier.authority_cert_issuer`
        and
        :attr:`~cryptography.x509.AuthorityKeyIdentifier.authority_cert_serial_number`
        will be None.
        The generated ``key_identifier`` is the SHA1 hash of the ``subjectPublicKey``
        ASN.1 bit string. This is the first recommendation in :rfc:`5280`
        section 4.2.1.2.

        :param public_key: One of
            :data:`~cryptography.hazmat.primitives.asymmetric.types.CertificateIssuerPublicKeyTypes`.

        .. doctest::

            >>> from cryptography import x509
            >>> issuer_cert = x509.load_pem_x509_certificate(pem_data)
            >>> x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key())
            <AuthorityKeyIdentifier(key_identifier=b'X\x01\x84$\x1b\xbc+R\x94J=\xa5\x10r\x14Q\xf5\xaf:\xc9', authority_cert_issuer=None, authority_cert_serial_number=None)>

    .. classmethod:: from_issuer_subject_key_identifier(ski)

        .. versionadded:: 1.3

        .. note::
            This method should be used if the issuer certificate contains a
            :class:`~cryptography.x509.SubjectKeyIdentifier`.  Otherwise, use
            :meth:`~cryptography.x509.AuthorityKeyIdentifier.from_issuer_public_key`.

        Creates a new AuthorityKeyIdentifier instance using the
        SubjectKeyIdentifier from the issuer certificate. The resulting object
        will contain
        :attr:`~cryptography.x509.AuthorityKeyIdentifier.key_identifier`, but
        :attr:`~cryptography.x509.AuthorityKeyIdentifier.authority_cert_issuer`
        and
        :attr:`~cryptography.x509.AuthorityKeyIdentifier.authority_cert_serial_number`
        will be None.

        :param ski: The
            :class:`~cryptography.x509.SubjectKeyIdentifier` from the issuer
            certificate.

        .. doctest::

            >>> from cryptography import x509
            >>> issuer_cert = x509.load_pem_x509_certificate(pem_data)
            >>> ski_ext = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            >>> x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski_ext.value)
            <AuthorityKeyIdentifier(key_identifier=b'X\x01\x84$\x1b\xbc+R\x94J=\xa5\x10r\x14Q\xf5\xaf:\xc9', authority_cert_issuer=None, authority_cert_serial_number=None)>

.. class:: SubjectKeyIdentifier(digest)
    :canonical: cryptography.x509.extensions.SubjectKeyIdentifier

    .. versionadded:: 0.9

    The subject key identifier extension provides a means of identifying
    certificates that contain a particular public key.

    .. attribute:: oid

        .. versionadded:: 1.0

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER`.

    .. attribute:: key_identifier

        .. versionadded:: 35.0.0

        :type: bytes

        The binary value of the identifier.

    .. attribute:: digest

        :type: bytes

        The binary value of the identifier. An alias of ``key_identifier``.

    .. classmethod:: from_public_key(public_key)

        .. versionadded:: 1.0

        Creates a new SubjectKeyIdentifier instance using the public key
        provided to generate the appropriate digest. This should be the public
        key that is in the certificate. The generated digest is the SHA1 hash
        of the ``subjectPublicKey`` ASN.1 bit string. This is the first
        recommendation in :rfc:`5280` section 4.2.1.2.

        :param public_key: One of
            :data:`~cryptography.hazmat.primitives.asymmetric.types.CertificatePublicKeyTypes`.

        .. doctest::

            >>> from cryptography import x509
            >>> csr = x509.load_pem_x509_csr(pem_req_data)
            >>> x509.SubjectKeyIdentifier.from_public_key(csr.public_key())
            <SubjectKeyIdentifier(digest=b'\x8c"\x98\xe2\xb5\xbf]\xe8*2\xf8\xd2\'?\x00\xd2\xc7#\xe4c')>

.. class:: SubjectAlternativeName(general_names)
    :canonical: cryptography.x509.extensions.SubjectAlternativeName

    .. versionadded:: 0.9

    Subject alternative name is an X.509 extension that provides a list of
    :ref:`general name <general_name_classes>` instances that provide a set
    of identities for which the certificate is valid. The object is iterable to
    get every element.

    :param list general_names: A list of :class:`GeneralName` instances.

    .. attribute:: oid

        .. versionadded:: 1.0

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME`.

    .. method:: get_values_for_type(type)

        :param type: A :class:`GeneralName` instance. This is one of the
            :ref:`general name classes <general_name_classes>`.

        :returns: A list of values extracted from the matched general names.
            The type of the returned values depends on the :class:`GeneralName`.

        .. doctest::

            >>> from cryptography import x509
            >>> from cryptography.hazmat.primitives import hashes
            >>> cert = x509.load_pem_x509_certificate(cryptography_cert_pem)
            >>> # Get the subjectAltName extension from the certificate
            >>> ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            >>> # Get the dNSName entries from the SAN extension
            >>> ext.value.get_values_for_type(x509.DNSName)
            ['www.cryptography.io', 'cryptography.io']


.. class:: IssuerAlternativeName(general_names)
    :canonical: cryptography.x509.extensions.IssuerAlternativeName

    .. versionadded:: 1.0

    Issuer alternative name is an X.509 extension that provides a list of
    :ref:`general name <general_name_classes>` instances that provide a set
    of identities for the certificate issuer. The object is iterable to
    get every element.

    :param list general_names: A list of :class:`GeneralName` instances.

    .. attribute:: oid

        .. versionadded:: 1.0

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.ExtensionOID.ISSUER_ALTERNATIVE_NAME`.

    .. method:: get_values_for_type(type)

        :param type: A :class:`GeneralName` instance. This is one of the
            :ref:`general name classes <general_name_classes>`.

        :returns: A list of values extracted from the matched general names.


.. class:: PrecertificateSignedCertificateTimestamps(scts)
    :canonical: cryptography.x509.extensions.PrecertificateSignedCertificateTimestamps

    .. versionadded:: 2.0

    This extension contains
    :class:`~cryptography.x509.certificate_transparency.SignedCertificateTimestamp`
    instances which were issued for the pre-certificate corresponding to this
    certificate. These can be used to verify that the certificate is included
    in a public Certificate Transparency log.

    It is an iterable containing one or more
    :class:`~cryptography.x509.certificate_transparency.SignedCertificateTimestamp`
    objects.

    :param list scts: A ``list`` of
        :class:`~cryptography.x509.certificate_transparency.SignedCertificateTimestamp`
        objects.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS`.


.. class:: PrecertPoison()
    :canonical: cryptography.x509.extensions.PrecertPoison

    .. versionadded:: 2.4

    This extension indicates that the certificate should not be treated as a
    certificate for the purposes of validation, but is instead for submission
    to a certificate transparency log in order to obtain SCTs which will be
    embedded in a :class:`PrecertificateSignedCertificateTimestamps` extension
    on the final certificate.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns :attr:`~cryptography.x509.oid.ExtensionOID.PRECERT_POISON`.


.. class:: SignedCertificateTimestamps(scts)
    :canonical: cryptography.x509.extensions.SignedCertificateTimestamps

    .. versionadded:: 3.0

    This extension contains
    :class:`~cryptography.x509.certificate_transparency.SignedCertificateTimestamp`
    instances. These can be used to verify that the certificate is included
    in a public Certificate Transparency log. This extension is only found
    in OCSP responses. For SCTs in an X.509 certificate see
    :class:`~cryptography.x509.PrecertificateSignedCertificateTimestamps`.

    It is an iterable containing one or more
    :class:`~cryptography.x509.certificate_transparency.SignedCertificateTimestamp`
    objects.

    :param list scts: A ``list`` of
        :class:`~cryptography.x509.certificate_transparency.SignedCertificateTimestamp`
        objects.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS`.


.. class:: DeltaCRLIndicator(crl_number)
    :canonical: cryptography.x509.extensions.DeltaCRLIndicator

    .. versionadded:: 2.1

    The delta CRL indicator is a CRL extension that identifies a CRL as being
    a delta CRL. Delta CRLs contain updates to revocation information
    previously distributed, rather than all the information that would appear
    in a complete CRL.

    :param int crl_number: The CRL number of the complete CRL that the
        delta CRL is updating.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.ExtensionOID.DELTA_CRL_INDICATOR`.

    .. attribute:: crl_number

        :type: int


.. class:: AuthorityInformationAccess(descriptions)
    :canonical: cryptography.x509.extensions.AuthorityInformationAccess

    .. versionadded:: 0.9

    The authority information access extension indicates how to access
    information and services for the issuer of the certificate in which
    the extension appears. Information and services may include online
    validation services (such as OCSP) and issuer data. It is an iterable,
    containing one or more :class:`~cryptography.x509.AccessDescription`
    instances.

    :param list descriptions: A list of :class:`AccessDescription` objects.

    .. attribute:: oid

        .. versionadded:: 1.0

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS`.


.. class:: SubjectInformationAccess(descriptions)
    :canonical: cryptography.x509.extensions.SubjectInformationAccess

    .. versionadded:: 3.0

    The subject information access extension indicates how to access
    information and services for the subject of the certificate in which
    the extension appears. When the subject is a CA, information and
    services may include certificate validation services and CA policy
    data. When the subject is an end entity, the information describes
    the type of services offered and how to access them. It is an iterable,
    containing one or more :class:`~cryptography.x509.AccessDescription`
    instances.

    :param list descriptions: A list of :class:`AccessDescription` objects.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.ExtensionOID.SUBJECT_INFORMATION_ACCESS`.


.. class:: AccessDescription(access_method, access_location)
    :canonical: cryptography.x509.extensions.AccessDescription

    .. versionadded:: 0.9

    .. attribute:: access_method

        :type: :class:`ObjectIdentifier`

        The access method defines what the ``access_location`` means. It must
        be
        :attr:`~cryptography.x509.oid.AuthorityInformationAccessOID.OCSP` or
        :attr:`~cryptography.x509.oid.AuthorityInformationAccessOID.CA_ISSUERS`
        when used with :class:`~cryptography.x509.AuthorityInformationAccess`
        or
        :attr:`~cryptography.x509.oid.SubjectInformationAccessOID.CA_REPOSITORY`
        when used with :class:`~cryptography.x509.SubjectInformationAccess`.

        If it is
        :attr:`~cryptography.x509.oid.AuthorityInformationAccessOID.OCSP`
        the access location will be where to obtain OCSP
        information for the certificate. If it is
        :attr:`~cryptography.x509.oid.AuthorityInformationAccessOID.CA_ISSUERS`
        the access location will provide additional information about the
        issuing certificate. Finally, if it is
        :attr:`~cryptography.x509.oid.SubjectInformationAccessOID.CA_REPOSITORY`
        the access location will be the location of the CA's repository.

    .. attribute:: access_location

        :type: :class:`GeneralName`

        Where to access the information defined by the access method.

.. class:: FreshestCRL(distribution_points)
    :canonical: cryptography.x509.extensions.FreshestCRL

    .. versionadded:: 2.1

    The freshest CRL extension (also known as Delta CRL Distribution Point)
    identifies how delta CRL information is obtained. It is an iterable,
    containing one or more :class:`DistributionPoint` instances.

    :param list distribution_points: A list of :class:`DistributionPoint`
        instances.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.ExtensionOID.FRESHEST_CRL`.

.. class:: CRLDistributionPoints(distribution_points)
    :canonical: cryptography.x509.extensions.CRLDistributionPoints

    .. versionadded:: 0.9

    The CRL distribution points extension identifies how CRL information is
    obtained. It is an iterable, containing one or more
    :class:`DistributionPoint` instances.

    :param list distribution_points: A list of :class:`DistributionPoint`
        instances.

    .. attribute:: oid

        .. versionadded:: 1.0

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS`.

.. class:: DistributionPoint(full_name, relative_name, reasons, crl_issuer)
    :canonical: cryptography.x509.extensions.DistributionPoint

    .. versionadded:: 0.9

    .. attribute:: full_name

        :type: list of :class:`GeneralName` instances or None

        This field describes methods to retrieve the CRL. At most one of
        ``full_name`` or ``relative_name`` will be non-None.

    .. attribute:: relative_name

        :type: :class:`RelativeDistinguishedName` or None

        This field describes methods to retrieve the CRL relative to the CRL
        issuer. At most one of ``full_name`` or ``relative_name`` will be
        non-None.

        .. versionchanged:: 1.6
            Changed from :class:`Name` to :class:`RelativeDistinguishedName`.

    .. attribute:: crl_issuer

        :type: list of :class:`GeneralName` instances or None

        Information about the issuer of the CRL.

    .. attribute:: reasons

        :type: frozenset of :class:`ReasonFlags` or None

        The reasons a given distribution point may be used for when performing
        revocation checks.

.. class:: ReasonFlags
    :canonical: cryptography.x509.extensions.ReasonFlags

    .. versionadded:: 0.9

    An enumeration for CRL reasons.

    .. attribute:: unspecified

        It is unspecified why the certificate was revoked. This reason cannot
        be used as a reason flag in a :class:`DistributionPoint`.

    .. attribute:: key_compromise

        This reason indicates that the private key was compromised.

    .. attribute:: ca_compromise

        This reason indicates that the CA issuing the certificate was
        compromised.

    .. attribute:: affiliation_changed

        This reason indicates that the subject's name or other information has
        changed.

    .. attribute:: superseded

        This reason indicates that a certificate has been superseded.

    .. attribute:: cessation_of_operation

        This reason indicates that the certificate is no longer required.

    .. attribute:: certificate_hold

        This reason indicates that the certificate is on hold.

    .. attribute:: privilege_withdrawn

        This reason indicates that the privilege granted by this certificate
        have been withdrawn.

    .. attribute:: aa_compromise

        When an attribute authority has been compromised.

    .. attribute:: remove_from_crl

        This reason indicates that the certificate was on hold and should be
        removed from the CRL. This reason cannot be used as a reason flag
        in a :class:`DistributionPoint`.

.. class:: InhibitAnyPolicy(skip_certs)
    :canonical: cryptography.x509.extensions.InhibitAnyPolicy

    .. versionadded:: 1.0

    The inhibit ``anyPolicy`` extension indicates that the special OID
    :attr:`~cryptography.x509.oid.CertificatePoliciesOID.ANY_POLICY`, is not
    considered an explicit match for other :class:`CertificatePolicies` except
    when it appears in an intermediate self-issued CA certificate.  The value
    indicates the number of additional non-self-issued certificates that may
    appear in the path before
    :attr:`~cryptography.x509.oid.CertificatePoliciesOID.ANY_POLICY` is no
    longer permitted.  For example, a value of one indicates that
    :attr:`~cryptography.x509.oid.CertificatePoliciesOID.ANY_POLICY` may be
    processed in certificates issued by the subject of this certificate, but
    not in additional certificates in the path.

    .. attribute:: oid

        .. versionadded:: 1.0

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.ExtensionOID.INHIBIT_ANY_POLICY`.

    .. attribute:: skip_certs

        :type: int

.. class:: PolicyConstraints
    :canonical: cryptography.x509.extensions.PolicyConstraints

    .. versionadded:: 1.3

    The policy constraints extension is used to inhibit policy mapping or
    require that each certificate in a chain contain an acceptable policy
    identifier. For more information about the use of this extension see
    :rfc:`5280`.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns :attr:`~cryptography.x509.oid.ExtensionOID.POLICY_CONSTRAINTS`.

    .. attribute:: require_explicit_policy

        :type: int or None

        If this field is not None, the value indicates the number of additional
        certificates that may appear in the chain before an explicit policy is
        required for the entire path. When an explicit policy is required, it
        is necessary for all certificates in the chain to contain an acceptable
        policy identifier in the certificate policies extension.  An
        acceptable policy identifier is the identifier of a policy required
        by the user of the certification path or the identifier of a policy
        that has been declared equivalent through policy mapping.

    .. attribute:: inhibit_policy_mapping

        :type: int or None

        If this field is not None, the value indicates the number of additional
        certificates that may appear in the chain before policy mapping is no
        longer permitted.  For example, a value of one indicates that policy
        mapping may be processed in certificates issued by the subject of this
        certificate, but not in additional certificates in the chain.

.. class:: CRLNumber(crl_number)
    :canonical: cryptography.x509.extensions.CRLNumber

    .. versionadded:: 1.2

    The CRL number is a CRL extension that conveys a monotonically increasing
    sequence number for a given CRL scope and CRL issuer. This extension allows
    users to easily determine when a particular CRL supersedes another CRL.
    :rfc:`5280` requires that this extension be present in conforming CRLs.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.ExtensionOID.CRL_NUMBER`.

    .. attribute:: crl_number

        :type: int

.. class:: IssuingDistributionPoint(full_name, relative_name,\
           only_contains_user_certs, only_contains_ca_certs, only_some_reasons,\
           indirect_crl, only_contains_attribute_certs)
    :canonical: cryptography.x509.extensions.IssuingDistributionPoint

    .. versionadded:: 2.5

    Issuing distribution point is a CRL extension that identifies the CRL
    distribution point and scope for a particular CRL. It indicates whether
    the CRL covers revocation for end entity certificates only, CA certificates
    only, attribute certificates only, or a limited set of reason codes. For
    specific details on the way this extension should be processed see
    :rfc:`5280`.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.ExtensionOID.ISSUING_DISTRIBUTION_POINT`.

    .. attribute:: only_contains_user_certs

        :type: bool

        Set to ``True`` if the CRL this extension is embedded within only
        contains information about user certificates.

    .. attribute:: only_contains_ca_certs

        :type: bool

        Set to ``True`` if the CRL this extension is embedded within only
        contains information about CA certificates.

    .. attribute:: indirect_crl

        :type: bool

        Set to ``True`` if the CRL this extension is embedded within includes
        certificates issued by one or more authorities other than the CRL
        issuer.

    .. attribute:: only_contains_attribute_certs

        :type: bool

        Set to ``True`` if the CRL this extension is embedded within only
        contains information about attribute certificates.

    .. attribute:: only_some_reasons

        :type: frozenset of :class:`ReasonFlags` or None

        The reasons for which the issuing distribution point is valid. None
        indicates that it is valid for all reasons.

    .. attribute:: full_name

        :type: list of :class:`GeneralName` instances or None

        This field describes methods to retrieve the CRL. At most one of
        ``full_name`` or ``relative_name`` will be non-None.

    .. attribute:: relative_name

        :type: :class:`RelativeDistinguishedName` or None

        This field describes methods to retrieve the CRL relative to the CRL
        issuer. At most one of ``full_name`` or ``relative_name`` will be
        non-None.

.. class:: UnrecognizedExtension
    :canonical: cryptography.x509.extensions.UnrecognizedExtension

    .. versionadded:: 1.2

    A generic extension class used to hold the raw value of extensions that
    ``cryptography`` does not know how to parse. This can also be used when
    creating new certificates, CRLs, or OCSP requests and responses to encode
    extensions that ``cryptography`` does not know how to generate.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns the OID associated with this extension.

    .. attribute:: value

        :type: bytes

        Returns the DER encoded bytes payload of the extension.

.. class:: MSCertificateTemplate(template_id, major_version, minor_version)
    :canonical: cryptography.x509.extensions.MSCertificateTemplate

    .. versionadded:: 41.0.0

    The Microsoft certificate template extension is a proprietary Microsoft
    PKI extension that is used to provide information about the template
    associated with the certificate.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.ExtensionOID.MS_CERTIFICATE_TEMPLATE`.

    .. attribute:: template_id

        :type: :class:`ObjectIdentifier`

    .. attribute:: major_version

        :type: int or None

    .. attribute:: minor_version

        :type: int or None

.. class:: CertificatePolicies(policies)
    :canonical: cryptography.x509.extensions.CertificatePolicies

    .. versionadded:: 0.9

    The certificate policies extension is an iterable, containing one or more
    :class:`PolicyInformation` instances.

    :param list policies: A list of :class:`PolicyInformation` instances.

    As an example of how ``CertificatePolicies`` might be used, if you wanted
    to check if a certificated contained the CAB Forum's "domain-validated"
    policy, you might write code like:

    .. code-block:: python

        def contains_domain_validated(policies):
            return any(
                policy.policy_identifier.dotted_string == "2.23.140.1.2.1"
                for policy in policies
            )

    .. attribute:: oid

        .. versionadded:: 1.0

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.ExtensionOID.CERTIFICATE_POLICIES`.

Certificate Policies Classes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These classes may be present within a :class:`CertificatePolicies` instance.

.. class:: PolicyInformation(policy_identifier, policy_qualifiers)
    :canonical: cryptography.x509.extensions.PolicyInformation

    .. versionadded:: 0.9

    Contains a policy identifier and an optional list of qualifiers.

    .. attribute:: policy_identifier

        :type: :class:`ObjectIdentifier`

    .. attribute:: policy_qualifiers

        :type: list

        A list consisting of ``str`` and/or :class:`UserNotice` objects.  If the
        value is ``str`` it is a pointer to the practice statement published by
        the certificate authority. If it is a user notice it is meant for
        display to the relying party when the certificate is used.

.. class:: UserNotice(notice_reference, explicit_text)
    :canonical: cryptography.x509.extensions.UserNotice

    .. versionadded:: 0.9

    User notices are intended for display to a relying party when a certificate
    is used. In practice, few if any UIs expose this data and it is a rarely
    encoded component.

    .. attribute:: notice_reference

        :type: :class:`NoticeReference` or None

        The notice reference field names an organization and identifies,
        by number, a particular statement prepared by that organization.

    .. attribute:: explicit_text

        This field includes an arbitrary textual statement directly in the
        certificate.

        :type: str

.. class:: NoticeReference(organization, notice_numbers)
    :canonical: cryptography.x509.extensions.NoticeReference

    Notice reference can name an organization and provide information about
    notices related to the certificate. For example, it might identify the
    organization name and notice number 1. Application software could
    have a notice file containing the current set of notices for the named
    organization; the application would then extract the notice text from the
    file and display it. In practice this is rarely seen.

    .. versionadded:: 0.9

    .. attribute:: organization

        :type: str

    .. attribute:: notice_numbers

        :type: list

        A list of integers.

.. _crl_entry_extensions:

CRL Entry Extensions
~~~~~~~~~~~~~~~~~~~~

These extensions are only valid within a :class:`RevokedCertificate` object.

.. class:: CertificateIssuer(general_names)
    :canonical: cryptography.x509.extensions.CertificateIssuer

    .. versionadded:: 1.2

    The certificate issuer is an extension that is only valid inside
    :class:`~cryptography.x509.RevokedCertificate` objects.  If the
    ``indirectCRL`` property of the parent CRL's IssuingDistributionPoint
    extension is set, then this extension identifies the certificate issuer
    associated with the revoked certificate. The object is iterable to get
    every element.

    :param list general_names: A list of :class:`GeneralName` instances.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.CRLEntryExtensionOID.CERTIFICATE_ISSUER`.

    .. method:: get_values_for_type(type)

        :param type: A :class:`GeneralName` instance. This is one of the
            :ref:`general name classes <general_name_classes>`.

        :returns: A list of values extracted from the matched general names.
            The type of the returned values depends on the :class:`GeneralName`.

.. class:: CRLReason(reason)
    :canonical: cryptography.x509.extensions.CRLReason

    .. versionadded:: 1.2

    CRL reason (also known as ``reasonCode``) is an extension that is only
    valid inside :class:`~cryptography.x509.RevokedCertificate` objects. It
    identifies a reason for the certificate revocation.

    :param reason: An element from :class:`~cryptography.x509.ReasonFlags`.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.CRLEntryExtensionOID.CRL_REASON`.

    .. attribute:: reason

        :type: An element from :class:`~cryptography.x509.ReasonFlags`

.. class:: InvalidityDate(invalidity_date)
    :canonical: cryptography.x509.extensions.InvalidityDate

    .. versionadded:: 1.2

    Invalidity date is an extension that is only valid inside
    :class:`~cryptography.x509.RevokedCertificate` objects. It provides
    the date on which it is known or suspected that the private key was
    compromised or that the certificate otherwise became invalid.
    This date may be earlier than the revocation date in the CRL entry,
    which is the date at which the CA processed the revocation.

    :param invalidity_date: The :class:`datetime.datetime` when it is known
        or suspected that the private key was compromised.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.CRLEntryExtensionOID.INVALIDITY_DATE`.

    .. attribute:: invalidity_date

        :type: :class:`datetime.datetime`

OCSP Extensions
~~~~~~~~~~~~~~~

.. class:: OCSPNonce(nonce)
    :canonical: cryptography.x509.extensions.OCSPNonce

    .. versionadded:: 2.4

    OCSP nonce is an extension that is only valid inside
    :class:`~cryptography.x509.ocsp.OCSPRequest` and
    :class:`~cryptography.x509.ocsp.OCSPResponse` objects. The nonce
    cryptographically binds a request and a response to prevent replay attacks.
    In practice nonces are rarely used in OCSP due to the desire to precompute
    OCSP responses at large scale.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.OCSPExtensionOID.NONCE`.

    .. attribute:: nonce

        :type: bytes

.. class:: OCSPAcceptableResponses(response)
    :canonical: cryptography.x509.extensions.OCSPAcceptableResponses

    .. versionadded:: 41.0.0

    OCSP acceptable responses is an extension that is only valid inside
    :class:`~cryptography.x509.ocsp.OCSPRequest` objects. This allows an OCSP
    client to tell the server what types of responses it supports. In practice
    this is rarely used, because there is only one kind of OCSP response in
    wide use.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns
        :attr:`~cryptography.x509.oid.OCSPExtensionOID.ACCEPTABLE_RESPONSES`.

    .. attribute:: nonce

        :type: bytes


X.509 Request Attributes
~~~~~~~~~~~~~~~~~~~~~~~~

.. class:: Attributes
    :canonical: cryptography.x509.base.Attributes

    .. versionadded:: 36.0.0

    An Attributes instance is an ordered list of attributes.  The object
    is iterable to get every attribute. Each returned element is an
    :class:`Attribute`.

    .. method:: get_attribute_for_oid(oid)

        .. versionadded:: 36.0.0

        :param oid: An :class:`ObjectIdentifier` instance.

        :returns: The :class:`Attribute` or an exception if not found.

        :raises cryptography.x509.AttributeNotFound: If the request does
            not have the attribute requested.


.. class:: Attribute
    :canonical: cryptography.x509.base.Attribute

    .. versionadded:: 36.0.0

    An attribute associated with an X.509 request.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns the object identifier for the attribute.

    .. attribute:: value

        :type: bytes

        Returns the value of the attribute.

Object Identifiers
~~~~~~~~~~~~~~~~~~

X.509 elements are frequently identified by :class:`ObjectIdentifier`
instances. The following common OIDs are available as constants.

.. currentmodule:: cryptography.x509.oid

.. class:: NameOID
    :canonical: cryptography.hazmat._oid.NameOID

    These OIDs are typically seen in X.509 names.

    .. versionadded:: 1.0

    .. attribute:: COMMON_NAME

        Corresponds to the dotted string ``"2.5.4.3"``. Historically the domain
        name would be encoded here for server certificates. :rfc:`2818`
        deprecates this practice and names of that type should now be located
        in a :class:`~cryptography.x509.SubjectAlternativeName` extension.

    .. attribute:: COUNTRY_NAME

        Corresponds to the dotted string ``"2.5.4.6"``.

    .. attribute:: LOCALITY_NAME

        Corresponds to the dotted string ``"2.5.4.7"``.

    .. attribute:: STATE_OR_PROVINCE_NAME

        Corresponds to the dotted string ``"2.5.4.8"``.

    .. attribute:: STREET_ADDRESS

        .. versionadded:: 1.6

        Corresponds to the dotted string ``"2.5.4.9"``.

    .. attribute:: ORGANIZATION_NAME

        Corresponds to the dotted string ``"2.5.4.10"``.

    .. attribute:: ORGANIZATIONAL_UNIT_NAME

        Corresponds to the dotted string ``"2.5.4.11"``.

    .. attribute:: SERIAL_NUMBER

        Corresponds to the dotted string ``"2.5.4.5"``. This is distinct from
        the serial number of the certificate itself (which can be obtained with
        :attr:`~cryptography.x509.Certificate.serial_number`).

    .. attribute:: SURNAME

        Corresponds to the dotted string ``"2.5.4.4"``.

    .. attribute:: GIVEN_NAME

        Corresponds to the dotted string ``"2.5.4.42"``.

    .. attribute:: TITLE

        Corresponds to the dotted string ``"2.5.4.12"``.

    .. attribute:: GENERATION_QUALIFIER

        Corresponds to the dotted string ``"2.5.4.44"``.

    .. attribute:: X500_UNIQUE_IDENTIFIER

        .. versionadded:: 1.6

        Corresponds to the dotted string ``"2.5.4.45"``.

    .. attribute:: DN_QUALIFIER

        Corresponds to the dotted string ``"2.5.4.46"``. This specifies
        disambiguating information to add to the relative distinguished name of an
        entry. See :rfc:`2256`.

    .. attribute:: PSEUDONYM

        Corresponds to the dotted string ``"2.5.4.65"``.

    .. attribute:: USER_ID

        .. versionadded:: 1.6

        Corresponds to the dotted string ``"0.9.2342.19200300.100.1.1"``.

    .. attribute:: DOMAIN_COMPONENT

        Corresponds to the dotted string ``"0.9.2342.19200300.100.1.25"``. A string
        holding one component of a domain name. See :rfc:`4519`.

    .. attribute:: EMAIL_ADDRESS

        Corresponds to the dotted string ``"1.2.840.113549.1.9.1"``.

    .. attribute:: JURISDICTION_COUNTRY_NAME

        Corresponds to the dotted string ``"1.3.6.1.4.1.311.60.2.1.3"``.

    .. attribute:: JURISDICTION_LOCALITY_NAME

        Corresponds to the dotted string ``"1.3.6.1.4.1.311.60.2.1.1"``.

    .. attribute:: JURISDICTION_STATE_OR_PROVINCE_NAME

        Corresponds to the dotted string ``"1.3.6.1.4.1.311.60.2.1.2"``.

    .. attribute:: BUSINESS_CATEGORY

        Corresponds to the dotted string ``"2.5.4.15"``.

    .. attribute:: POSTAL_ADDRESS

        .. versionadded:: 1.6

        Corresponds to the dotted string ``"2.5.4.16"``.

    .. attribute:: POSTAL_CODE

        .. versionadded:: 1.6

        Corresponds to the dotted string ``"2.5.4.17"``.

    .. attribute:: UNSTRUCTURED_NAME

        .. versionadded:: 3.0

        Corresponds to the dotted string ``"1.2.840.113549.1.9.2"``.


.. class:: SignatureAlgorithmOID
    :canonical: cryptography.hazmat._oid.SignatureAlgorithmOID

    .. versionadded:: 1.0

    .. attribute:: RSA_WITH_MD5

        Corresponds to the dotted string ``"1.2.840.113549.1.1.4"``. This is
        an MD5 digest signed by an RSA key.

    .. attribute:: RSA_WITH_SHA1

        Corresponds to the dotted string ``"1.2.840.113549.1.1.5"``. This is
        a SHA1 digest signed by an RSA key.

    .. attribute:: RSA_WITH_SHA224

        Corresponds to the dotted string ``"1.2.840.113549.1.1.14"``. This is
        a SHA224 digest signed by an RSA key.

    .. attribute:: RSA_WITH_SHA256

        Corresponds to the dotted string ``"1.2.840.113549.1.1.11"``. This is
        a SHA256 digest signed by an RSA key.

    .. attribute:: RSA_WITH_SHA384

        Corresponds to the dotted string ``"1.2.840.113549.1.1.12"``. This is
        a SHA384 digest signed by an RSA key.

    .. attribute:: RSA_WITH_SHA512

        Corresponds to the dotted string ``"1.2.840.113549.1.1.13"``. This is
        a SHA512 digest signed by an RSA key.

    .. attribute:: RSA_WITH_SHA3_224

        Corresponds to the dotted string ``"2.16.840.1.101.3.4.3.13"``. This is
        a SHA3-224 digest signed by an RSA key.

    .. attribute:: RSA_WITH_SHA3_256

        Corresponds to the dotted string ``"2.16.840.1.101.3.4.3.14"``. This is
        a SHA3-256 digest signed by an RSA key.

    .. attribute:: RSA_WITH_SHA3_384

        Corresponds to the dotted string ``"2.16.840.1.101.3.4.3.15"``. This is
        a SHA3-384 digest signed by an RSA key.

    .. attribute:: RSA_WITH_SHA3_512

        Corresponds to the dotted string ``"2.16.840.1.101.3.4.3.16"``. This is
        a SHA3-512 digest signed by an RSA key.

    .. attribute:: RSASSA_PSS

        .. versionadded:: 2.3

        Corresponds to the dotted string ``"1.2.840.113549.1.1.10"``. This is
        signed by an RSA key using the Probabilistic Signature Scheme (PSS)
        padding from :rfc:`4055`. The hash function and padding are defined by
        signature algorithm parameters.

    .. attribute:: ECDSA_WITH_SHA1

        Corresponds to the dotted string ``"1.2.840.10045.4.1"``. This is a SHA1
        digest signed by an ECDSA key.

    .. attribute:: ECDSA_WITH_SHA224

        Corresponds to the dotted string ``"1.2.840.10045.4.3.1"``. This is
        a SHA224 digest signed by an ECDSA key.

    .. attribute:: ECDSA_WITH_SHA256

        Corresponds to the dotted string ``"1.2.840.10045.4.3.2"``. This is
        a SHA256 digest signed by an ECDSA key.

    .. attribute:: ECDSA_WITH_SHA384

        Corresponds to the dotted string ``"1.2.840.10045.4.3.3"``. This is
        a SHA384 digest signed by an ECDSA key.

    .. attribute:: ECDSA_WITH_SHA512

        Corresponds to the dotted string ``"1.2.840.10045.4.3.4"``. This is
        a SHA512 digest signed by an ECDSA key.

    .. attribute:: ECDSA_WITH_SHA3_224

        Corresponds to the dotted string ``"2.16.840.1.101.3.4.3.9"``. This is
        a SHA3-224 digest signed by an ECDSA key.

    .. attribute:: ECDSA_WITH_SHA3_256

        Corresponds to the dotted string ``"2.16.840.1.101.3.4.3.10"``. This is
        a SHA3-256 digest signed by an ECDSA key.

    .. attribute:: ECDSA_WITH_SHA3_384

        Corresponds to the dotted string ``"2.16.840.1.101.3.4.3.11"``. This is
        a SHA3-384 digest signed by an ECDSA key.

    .. attribute:: ECDSA_WITH_SHA3_512

        Corresponds to the dotted string ``"2.16.840.1.101.3.4.3.12"``. This is
        a SHA3-512 digest signed by an ECDSA key.

    .. attribute:: DSA_WITH_SHA1

        Corresponds to the dotted string ``"1.2.840.10040.4.3"``. This is
        a SHA1 digest signed by a DSA key.

    .. attribute:: DSA_WITH_SHA224

        Corresponds to the dotted string ``"2.16.840.1.101.3.4.3.1"``. This is
        a SHA224 digest signed by a DSA key.

    .. attribute:: DSA_WITH_SHA256

        Corresponds to the dotted string ``"2.16.840.1.101.3.4.3.2"``. This is
        a SHA256 digest signed by a DSA key.

    .. attribute:: DSA_WITH_SHA384

        .. versionadded:: 36.0.0

        Corresponds to the dotted string ``"2.16.840.1.101.3.4.3.3"``. This is
        a SHA384 digest signed by a DSA key.

    .. attribute:: DSA_WITH_SHA512

        .. versionadded:: 36.0.0

        Corresponds to the dotted string ``"2.16.840.1.101.3.4.3.4"``. This is
        a SHA512 digest signed by a DSA key.

    .. attribute:: ED25519

        .. versionadded:: 2.8

        Corresponds to the dotted string ``"1.3.101.112"``. This is a signature
        using an ed25519 key.

    .. attribute:: ED448

        .. versionadded:: 2.8

        Corresponds to the dotted string ``"1.3.101.113"``. This is a signature
        using an ed448 key.


.. class:: ExtendedKeyUsageOID
    :canonical: cryptography.hazmat._oid.ExtendedKeyUsageOID

    .. versionadded:: 1.0

    .. attribute:: SERVER_AUTH

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.3.1"``. This is used
        to denote that a certificate may be used for TLS web server
        authentication.

    .. attribute:: CLIENT_AUTH

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.3.2"``. This is used
        to denote that a certificate may be used for TLS web client
        authentication.

    .. attribute:: CODE_SIGNING

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.3.3"``. This is used
        to denote that a certificate may be used for code signing.

    .. attribute:: EMAIL_PROTECTION

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.3.4"``. This is used
        to denote that a certificate may be used for email protection.

    .. attribute:: TIME_STAMPING

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.3.8"``. This is used
        to denote that a certificate may be used for time stamping.

    .. attribute:: OCSP_SIGNING

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.3.9"``. This is used
        to denote that a certificate may be used for signing OCSP responses.

    .. attribute:: ANY_EXTENDED_KEY_USAGE

        .. versionadded:: 2.0

        Corresponds to the dotted string ``"2.5.29.37.0"``. This is used to
        denote that a certificate may be used for _any_ purposes. However,
        :rfc:`5280` additionally notes that applications that require the
        presence of a particular purpose _MAY_ reject certificates that include
        the ``anyExtendedKeyUsage`` OID but not the particular OID expected for
        the application. Therefore, the presence of this OID does not mean a
        given application will accept the certificate for all purposes.

    .. attribute:: SMARTCARD_LOGON

        .. versionadded:: 35.0.0

        Corresponds to the dotted string ``"1.3.6.1.4.1.311.20.2.2"``. This
        is used to denote that a certificate may be used for ``PKINIT`` access
        on Windows.

    .. attribute:: KERBEROS_PKINIT_KDC

        .. versionadded:: 35.0.0

        Corresponds to the dotted string ``"1.3.6.1.5.2.3.5"``. This
        is used to denote that a certificate may be used as a Kerberos
        domain controller certificate authorizing ``PKINIT`` access. For
        more information see :rfc:`4556`.

    .. attribute:: IPSEC_IKE

        .. versionadded:: 37.0.0

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.3.17"``. This
        is used to denote that a certificate may be assigned to an IPSEC SA,
        and can be used by the assignee to initiate an IPSec Internet Key
        Exchange. For more information see :rfc:`4945`.

    .. attribute:: CERTIFICATE_TRANSPARENCY

        .. versionadded:: 38.0.0

        Corresponds to the dotted string ``"1.3.6.1.4.1.11129.2.4.4"``. This
        is used to denote that a certificate may be used as a pre-certificate
        signing certificate for Certificate Transparency log operation
        purposes. For more information see :rfc:`6962`.


.. class:: AuthorityInformationAccessOID
    :canonical: cryptography.hazmat._oid.AuthorityInformationAccessOID

    .. versionadded:: 1.0

    .. attribute:: OCSP

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.48.1"``. Used as the
        identifier for OCSP data in
        :class:`~cryptography.x509.AccessDescription` objects.

    .. attribute:: CA_ISSUERS

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.48.2"``. Used as the
        identifier for CA issuer data in
        :class:`~cryptography.x509.AccessDescription` objects.


.. class:: SubjectInformationAccessOID
    :canonical: cryptography.hazmat._oid.SubjectInformationAccessOID

    .. versionadded:: 3.0

    .. attribute:: CA_REPOSITORY

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.48.5"``. Used as the
        identifier for CA repository data in
        :class:`~cryptography.x509.AccessDescription` objects.


.. class:: CertificatePoliciesOID
    :canonical: cryptography.hazmat._oid.CertificatePoliciesOID

    .. versionadded:: 1.0

    .. attribute:: CPS_QUALIFIER

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.2.1"``.

    .. attribute:: CPS_USER_NOTICE

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.2.2"``.

    .. attribute:: ANY_POLICY

        Corresponds to the dotted string ``"2.5.29.32.0"``.


.. class:: ExtensionOID
    :canonical: cryptography.hazmat._oid.ExtensionOID

    .. versionadded:: 1.0

    .. attribute:: BASIC_CONSTRAINTS

        Corresponds to the dotted string ``"2.5.29.19"``. The identifier for the
        :class:`~cryptography.x509.BasicConstraints` extension type.

    .. attribute:: KEY_USAGE

        Corresponds to the dotted string ``"2.5.29.15"``. The identifier for the
        :class:`~cryptography.x509.KeyUsage` extension type.

    .. attribute:: SUBJECT_ALTERNATIVE_NAME

        Corresponds to the dotted string ``"2.5.29.17"``. The identifier for the
        :class:`~cryptography.x509.SubjectAlternativeName` extension type.

    .. attribute:: ISSUER_ALTERNATIVE_NAME

        Corresponds to the dotted string ``"2.5.29.18"``. The identifier for the
        :class:`~cryptography.x509.IssuerAlternativeName` extension type.

    .. attribute:: SUBJECT_KEY_IDENTIFIER

        Corresponds to the dotted string ``"2.5.29.14"``. The identifier for the
        :class:`~cryptography.x509.SubjectKeyIdentifier` extension type.

    .. attribute:: NAME_CONSTRAINTS

        Corresponds to the dotted string ``"2.5.29.30"``. The identifier for the
        :class:`~cryptography.x509.NameConstraints` extension type.

    .. attribute:: CRL_DISTRIBUTION_POINTS

        Corresponds to the dotted string ``"2.5.29.31"``. The identifier for the
        :class:`~cryptography.x509.CRLDistributionPoints` extension type.

    .. attribute:: CERTIFICATE_POLICIES

        Corresponds to the dotted string ``"2.5.29.32"``. The identifier for the
        :class:`~cryptography.x509.CertificatePolicies` extension type.

    .. attribute:: AUTHORITY_KEY_IDENTIFIER

        Corresponds to the dotted string ``"2.5.29.35"``. The identifier for the
        :class:`~cryptography.x509.AuthorityKeyIdentifier` extension type.

    .. attribute:: EXTENDED_KEY_USAGE

        Corresponds to the dotted string ``"2.5.29.37"``. The identifier for the
        :class:`~cryptography.x509.ExtendedKeyUsage` extension type.

    .. attribute:: AUTHORITY_INFORMATION_ACCESS

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.1.1"``. The identifier
        for the :class:`~cryptography.x509.AuthorityInformationAccess` extension
        type.

    .. attribute:: SUBJECT_INFORMATION_ACCESS

        .. versionadded:: 3.0

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.1.11"``. The
        identifier for the :class:`~cryptography.x509.SubjectInformationAccess`
        extension type.

    .. attribute:: INHIBIT_ANY_POLICY

        Corresponds to the dotted string ``"2.5.29.54"``. The identifier
        for the :class:`~cryptography.x509.InhibitAnyPolicy` extension type.

    .. attribute:: OCSP_NO_CHECK

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.48.1.5"``. The
        identifier for the :class:`~cryptography.x509.OCSPNoCheck` extension
        type.

    .. attribute:: TLS_FEATURE

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.1.24"``. The
        identifier for the :class:`~cryptography.x509.TLSFeature` extension
        type.

    .. attribute:: CRL_NUMBER

        Corresponds to the dotted string ``"2.5.29.20"``. The identifier for
        the ``CRLNumber`` extension type. This extension only has meaning
        for certificate revocation lists.

    .. attribute:: DELTA_CRL_INDICATOR

        .. versionadded:: 2.1

        Corresponds to the dotted string ``"2.5.29.27"``. The identifier for
        the ``DeltaCRLIndicator`` extension type. This extension only has
        meaning for certificate revocation lists.

    .. attribute:: PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS

        .. versionadded:: 1.9

        Corresponds to the dotted string ``"1.3.6.1.4.1.11129.2.4.2"``.

    .. attribute:: PRECERT_POISON

        .. versionadded:: 2.4

        Corresponds to the dotted string ``"1.3.6.1.4.1.11129.2.4.3"``.

    .. attribute:: SIGNED_CERTIFICATE_TIMESTAMPS

        .. versionadded:: 3.0

        Corresponds to the dotted string ``"1.3.6.1.4.1.11129.2.4.5"``.

    .. attribute:: POLICY_CONSTRAINTS

        Corresponds to the dotted string ``"2.5.29.36"``. The identifier for the
        :class:`~cryptography.x509.PolicyConstraints` extension type.

    .. attribute:: FRESHEST_CRL

        Corresponds to the dotted string ``"2.5.29.46"``. The identifier for the
        :class:`~cryptography.x509.FreshestCRL` extension type.

    .. attribute:: ISSUING_DISTRIBUTION_POINT

        .. versionadded:: 2.4

        Corresponds to the dotted string ``"2.5.29.28"``.

    .. attribute:: POLICY_MAPPINGS

        Corresponds to the dotted string ``"2.5.29.33"``.

    .. attribute:: SUBJECT_DIRECTORY_ATTRIBUTES

        Corresponds to the dotted string ``"2.5.29.9"``.

    .. attribute:: MS_CERTIFICATE_TEMPLATE

        .. versionadded:: 41.0.0

        Corresponds to the dotted string ``"1.3.6.1.4.1.311.21.7"``.


.. class:: CRLEntryExtensionOID
    :canonical: cryptography.hazmat._oid.CRLEntryExtensionOID

    .. versionadded:: 1.2

    .. attribute:: CERTIFICATE_ISSUER

        Corresponds to the dotted string ``"2.5.29.29"``.

    .. attribute:: CRL_REASON

        Corresponds to the dotted string ``"2.5.29.21"``.

    .. attribute:: INVALIDITY_DATE

        Corresponds to the dotted string ``"2.5.29.24"``.


.. class:: OCSPExtensionOID
    :canonical: cryptography.hazmat._oid.OCSPExtensionOID

    .. versionadded:: 2.4

    .. attribute:: NONCE

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.48.1.2"``.

    .. attribute:: ACCEPTABLE_RESPONSES

        .. versionadded:: 41.0.0

        Corresponds to the dotted string ``"1.3.6.1.5.5.7.48.1.4"``.


.. class:: AttributeOID
    :canonical: cryptography.hazmat._oid.AttributeOID

    .. versionadded:: 3.0

    .. attribute:: CHALLENGE_PASSWORD

        Corresponds to the dotted string ``"1.2.840.113549.1.9.7"``.

    .. attribute:: UNSTRUCTURED_NAME

        Corresponds to the dotted string ``"1.2.840.113549.1.9.2"``.

Helper Functions
~~~~~~~~~~~~~~~~
.. currentmodule:: cryptography.x509

.. function:: random_serial_number()
    :canonical: cryptography.x509.base.random_serial_number

    .. versionadded:: 1.6

    Generates a random serial number suitable for use when constructing
    certificates.

Exceptions
~~~~~~~~~~
.. currentmodule:: cryptography.x509

.. class:: InvalidVersion
    :canonical: cryptography.x509.base.InvalidVersion

    This is raised when an X.509 certificate has an invalid version number.

    .. attribute:: parsed_version

        :type: int

        Returns the raw version that was parsed from the certificate.

.. class:: DuplicateExtension
    :canonical: cryptography.x509.extensions.DuplicateExtension

    This is raised when more than one X.509 extension of the same type is
    found within a certificate.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns the OID.

.. class:: ExtensionNotFound
    :canonical: cryptography.x509.extensions.ExtensionNotFound

    This is raised when calling :meth:`Extensions.get_extension_for_oid` with
    an extension OID that is not present in the certificate.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns the OID.

.. class:: AttributeNotFound
    :canonical: cryptography.x509.base.AttributeNotFound

    This is raised when calling
    :meth:`Attributes.get_attribute_for_oid` with
    an attribute OID that is not present in the request.

    .. attribute:: oid

        :type: :class:`ObjectIdentifier`

        Returns the OID.

.. class:: UnsupportedGeneralNameType
    :canonical: cryptography.x509.general_name.UnsupportedGeneralNameType

    This is raised when a certificate contains an unsupported general name
    type in an extension.

    .. attribute:: type

        :type: int

        The integer value of the unsupported type. The complete list of
        types can be found in `RFC 5280 section 4.2.1.6`_.


.. _`RFC 5280 section 4.2.1.1`: https://tools.ietf.org/html/rfc5280#section-4.2.1.1
.. _`RFC 5280 section 4.2.1.6`: https://tools.ietf.org/html/rfc5280#section-4.2.1.6
.. _`CABForum Guidelines`: https://cabforum.org/baseline-requirements-documents/
