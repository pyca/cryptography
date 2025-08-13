X.509
=====

X.509 is a standard for `public key infrastructure`_. ``cryptography``
implements X.509 in accordance with :rfc:`5280`, and is principally focused on
WebPKI use cases. X.509 certificates are commonly used in protocols like
`TLS`_.

In some cases we tolerate divergences from the these specifications, however
these should be regarded as exceptional cases.

.. toctree::
    :maxdepth: 2

    tutorial
    certificate-transparency
    ocsp
    verification
    reference

.. _`public key infrastructure`: https://en.wikipedia.org/wiki/Public_key_infrastructure
.. _`TLS`: https://en.wikipedia.org/wiki/Transport_Layer_Security
