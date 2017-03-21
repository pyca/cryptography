Certificate Transparency
========================

.. currentmodule:: cryptography.x509.certificate_transparency

Certificate Transparency is a set of protocols specified in :rfc:`6962` which
allow X.509 certificates to be sent to append-only logs and have small
cryptographic proofs that a certificate has been publicly logged. This allows
for external auditing of the certificates that a certificate authority has
issued.

.. class:: SignedCertificateTimestamp

    .. versionadded:: 1.9

    SignedCertificateTimestamps (SCTs) are small cryptographically signed
    assertions that the specified certificate has been submitted to a
    Certificate Transparency Log, and that it will be part of the public log
    within some time period.

    .. attribute:: version

        :type: :class:`~cryptography.x509.certificate_transparency.Version`

        The SCT version as an enumeration. Currently only one version has been
        specified.

    .. attribute:: log_id

        :type: bytes

        An opaque identifier, indicating which log this SCT is from.

    .. attribute:: timestamp

        :type: datetime.datetime

        A naïve datetime representing the timestamp at which the log asserts
        the certificate had been submitted to it.

    .. attribute:: entry_type

        :type:
            :class:`~cryptogrography.x509.certificate_transparency.LogEntryType`

        The type of submission to the log that this SCT is for. Log submissions
        can either be certificates themselves or "pre-certificates" which
        indicate a binding-intent to issue a certificate for the same data,
        with SCTs embedded in it.


.. class:: Version

    .. versionadded:: 1.9

    An enumeration for SignedCertificateTimestamp versions.

    .. attribute:: v1

        For version 1 SignedCertificateTimestamps.

.. class:: LogEntryType

    .. versionadded:: 1.9

    An enumeration for SignedCertificateTimestamp log entry types.

    .. attribute:: X509_CERTIFICATE

        For SCTs corresponding to X.509 certificates.

    .. attribute:: PRE_CERTIFICATE

        For SCTs corresponding to pre-certificates.
