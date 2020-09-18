.. hazmat::

S/MIME
======

.. module:: cryptography.hazmat.primitives.smime

.. testsetup::

    ca_key = b"""
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgA8Zqz5vLeR0ePZUe
    jBfdyMmnnI4U5uAJApWTsMn/RuWhRANCAAQY/8+7+Tm49d3D7sBAiwZ1BqtPzdgs
    UiROH+AQRme1XxW5Yr07zwxvvhr3tKEPtLnLboazUPlsUb/Bgte+xfkF
    -----END PRIVATE KEY-----
    """.strip()

    ca_cert = b"""
    -----BEGIN CERTIFICATE-----
    MIIBUTCB96ADAgECAgIDCTAKBggqhkjOPQQDAjAnMQswCQYDVQQGEwJVUzEYMBYG
    A1UEAwwPY3J5cHRvZ3JhcGh5IENBMB4XDTE3MDEwMTEyMDEwMFoXDTM4MTIzMTA4
    MzAwMFowJzELMAkGA1UEBhMCVVMxGDAWBgNVBAMMD2NyeXB0b2dyYXBoeSBDQTBZ
    MBMGByqGSM49AgEGCCqGSM49AwEHA0IABBj/z7v5Obj13cPuwECLBnUGq0/N2CxS
    JE4f4BBGZ7VfFblivTvPDG++Gve0oQ+0uctuhrNQ+WxRv8GC177F+QWjEzARMA8G
    A1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhANES742XWm64tkGnz8Dn
    pG6u2lHkZFQr3oaVvPcemvlbAiEA0WGGzmYx5C9UvfXIK7NEziT4pQtyESE0uRVK
    Xw4nMqk=
    -----END CERTIFICATE-----
    """.strip()


S/MIME provides a method to send and receive signed MIME messages. It is
commonly used in email. S/MIME has multiple versions, but this
module implements a subset of :rfc:`2632`, also known as S/MIME Version 3.


.. class:: SMIMESignatureBuilder

    .. versionadded:: 3.2

    .. doctest::

        >>> from cryptography.hazmat.primitives import hashes, serialization, smime
        >>> from cryptography import x509
        >>> cert = x509.load_pem_x509_certificate(ca_cert)
        >>> key = serialization.load_pem_private_key(ca_key, None)
        >>> options = [smime.SMIMEOptions.DetachedSignature]
        >>> smime.SMIMESignatureBuilder().set_data(
        ...     b"data to sign"
        ... ).add_signer(
        ...     cert, key, hashes.SHA256()
        ... ).sign(
        ...     serialization.Encoding.PEM, options
        ... )
        b'...'

    .. method:: set_data(data)

        :param data: The data to be hashed and signed.
        :type data: :term:`bytes-like`

    .. method:: add_signer(certificate, private_key, hash_algorithm)

        :param certificate: The :class:`~cryptography.x509.Certificate`.

        :param private_key: The
            :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey` or
            :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
            associated with the certificate provided.

        :param hash_algorithm: The
            :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` that
            will be used to generate the signature. This must be an instance of
            :class:`~cryptography.hazmat.primitives.hashes.SHA1`,
            :class:`~cryptography.hazmat.primitives.hashes.SHA224`,
            :class:`~cryptography.hazmat.primitives.hashes.SHA256`,
            :class:`~cryptography.hazmat.primitives.hashes.SHA384`, or
            :class:`~cryptography.hazmat.primitives.hashes.SHA512`.

    .. method:: sign(encoding, options, backend=None)

        :param encoding: :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`
            or :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`.

        :param options: A list of :class:`~cryptography.hazmat.primitives.smime.SMIMEOptions`.

        :param backend: An optional backend.


.. class:: SMIMEOptions

    .. versionadded:: 3.2

    An enumeration of options for S/MIME signature creation.

    .. attribute:: Text

        The text option adds ``text/plain`` headers to the S/MIME message when
        serializing to
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM`.
        This option is disallowed with ``DER`` serialization.

    .. attribute:: Binary

        S/MIME signing normally converts line endings (LF to CRLF). When
        passing this option the data will not be converted.

    .. attribute:: DetachedSignature

        Don't embed the signed data within the ASN.1. When signing with
        :attr:`~cryptography.hazmat.primitives.serialization.Encoding.PEM` this
        also results in the data being added as clear text before the
        PEM encoded structure.

    .. attribute:: NoCapabilities

        S/MIME structures contain a ``MIMECapabilities`` section inside the
        ``authenticatedAttributes``. Passing this as an option removes
        ``MIMECapabilities``.

    .. attribute:: NoAttributes

        S/MIME structures contain an ``authenticatedAttributes`` section.
        Passing this as an option removes that section. Note that if you
        pass ``NoAttributes`` you can't pass ``NoCapabilities`` since
        ``NoAttributes`` removes ``MIMECapabilities`` and more.
