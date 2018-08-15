OCSP
====

.. currentmodule:: cryptography.x509.ocsp

.. testsetup::

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
        >>> for request in ocsp_req:
        ...     print(request.serial_number)
        872625873161273451176241581705670534707360122361


Interfaces
~~~~~~~~~~

.. class:: OCSPRequest

    .. versionadded:: 2.4

    An ``OCSPRequest`` is an iterable containing one or more
    :class:`~cryptography.x509.ocsp.Request` objects.

    .. method:: public_bytes(encoding)

        :param encoding: The encoding to use. Only
            :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`
            is supported.

        :return bytes: The serialized OCSP request.

.. class:: Request

    .. versionadded:: 2.4

    A ``Request`` contains several attributes that create a unique identifier
    for a certificate whose status is being checked. It may also contain
    additional extensions (currently unsupported).

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
