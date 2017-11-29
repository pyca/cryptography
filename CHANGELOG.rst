Changelog
=========


.. _v2-1-4:

2.1.4 - 2017-11-29
~~~~~~~~~~~~~~~~~~

* Added ``X509_up_ref`` for an upcoming ``pyOpenSSL`` release.

.. _v2-1-3:

2.1.3 - 2017-11-02
~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and ``manylinux1`` wheels to be compiled with
  OpenSSL 1.1.0g.

.. _v2-1-2:

2.1.2 - 2017-10-24
~~~~~~~~~~~~~~~~~~

* Corrected a bug with the ``manylinux1`` wheels where OpenSSL's stack was
  marked executable.

.. _v2-1-1:

2.1.1 - 2017-10-12
~~~~~~~~~~~~~~~~~~

* Fixed support for install with the system ``pip`` on Ubuntu 16.04.

.. _v2-1:

2.1 - 2017-10-11
~~~~~~~~~~~~~~~~

* **FINAL DEPRECATION** Python 2.6 support is deprecated, and will be removed
  in the next release of ``cryptography``.
* **BACKWARDS INCOMPATIBLE:** ``Whirlpool``, ``RIPEMD160``, and
  ``UnsupportedExtension`` have been removed in accordance with our
  :doc:`/api-stability` policy.
* **BACKWARDS INCOMPATIBLE:** :attr:`~cryptography.x509.DNSName.value`,
  :attr:`~cryptography.x509.RFC822Name.value`, and
  :attr:`~cryptography.x509.UniformResourceIdentifier.value` will now return
  an :term:`A-label` string when parsing a certificate containing an
  internationalized domain name (IDN) or if the caller passed a :term:`U-label`
  to the constructor. See below for additional deprecations related to this
  change.
* Installing ``cryptography`` now requires ``pip`` 6 or newer.
* Deprecated passing :term:`U-label` strings to the
  :class:`~cryptography.x509.DNSName`,
  :class:`~cryptography.x509.UniformResourceIdentifier`, and
  :class:`~cryptography.x509.RFC822Name` constructors. Instead, users should
  pass values as :term:`A-label` strings with ``idna`` encoding if necessary.
  This change will not affect anyone who is not processing internationalized
  domains.
* Added support for
  :class:`~cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20`. In
  most cases users should choose
  :class:`~cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`
  rather than using this unauthenticated form.
* Added :meth:`~cryptography.x509.CertificateRevocationList.is_signature_valid`
  to :class:`~cryptography.x509.CertificateRevocationList`.
* Support :class:`~cryptography.hazmat.primitives.hashes.BLAKE2b` and
  :class:`~cryptography.hazmat.primitives.hashes.BLAKE2s` with
  :class:`~cryptography.hazmat.primitives.hmac.HMAC`.
* Added support for
  :class:`~cryptography.hazmat.primitives.ciphers.modes.XTS` mode for
  AES.
* Added support for using labels with
  :class:`~cryptography.hazmat.primitives.asymmetric.padding.OAEP` when using
  OpenSSL 1.0.2 or greater.
* Improved compatibility with NSS when issuing certificates from an issuer
  that has a subject with non-``UTF8String`` string types.
* Add support for the :class:`~cryptography.x509.DeltaCRLIndicator` extension.
* Add support for the :class:`~cryptography.x509.TLSFeature`
  extension. This is commonly used for enabling ``OCSP Must-Staple`` in
  certificates.
* Add support for the :class:`~cryptography.x509.FreshestCRL` extension.

.. _v2-0-3:

2.0.3 - 2017-08-03
~~~~~~~~~~~~~~~~~~

* Fixed an issue with weak linking symbols when compiling on macOS
  versions older than 10.12.


.. _v2-0-2:

2.0.2 - 2017-07-27
~~~~~~~~~~~~~~~~~~

* Marked all symbols as hidden in the ``manylinux1`` wheel to avoid a
  bug with symbol resolution in certain scenarios.


.. _v2-0-1:

2.0.1 - 2017-07-26
~~~~~~~~~~~~~~~~~~

* Fixed a compilation bug affecting OpenBSD.
* Altered the ``manylinux1`` wheels to statically link OpenSSL instead of
  dynamically linking and bundling the shared object. This should resolve
  crashes seen when using ``uwsgi`` or other binaries that link against
  OpenSSL independently.
* Fixed the stack level for the ``signer`` and ``verifier`` warnings.


.. _v2-0:

2.0 - 2017-07-17
~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** Support for Python 3.3 has been dropped.
* We now ship ``manylinux1`` wheels linked against OpenSSL 1.1.0f. These wheels
  will be automatically used with most Linux distributions if you are running
  the latest pip.
* Deprecated the use of ``signer`` on
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`,
  and
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
  in favor of ``sign``.
* Deprecated the use of ``verifier`` on
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`,
  and
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
  in favor of ``verify``.
* Added support for parsing
  :class:`~cryptography.x509.certificate_transparency.SignedCertificateTimestamp`
  objects from X.509 certificate extensions.
* Added support for
  :class:`~cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`.
* Added support for
  :class:`~cryptography.hazmat.primitives.ciphers.aead.AESCCM`.
* Added
  :class:`~cryptography.hazmat.primitives.ciphers.aead.AESGCM`, a "one shot"
  API for AES GCM encryption.
* Added support for :doc:`/hazmat/primitives/asymmetric/x25519`.
* Added support for serializing and deserializing Diffie-Hellman parameters
  with
  :func:`~cryptography.hazmat.primitives.serialization.load_pem_parameters`,
  :func:`~cryptography.hazmat.primitives.serialization.load_der_parameters`,
  and
  :meth:`~cryptography.hazmat.primitives.asymmetric.dh.DHParameters.parameter_bytes`
  .
* The ``extensions`` attribute on :class:`~cryptography.x509.Certificate`,
  :class:`~cryptography.x509.CertificateSigningRequest`,
  :class:`~cryptography.x509.CertificateRevocationList`, and
  :class:`~cryptography.x509.RevokedCertificate` now caches the computed
  ``Extensions`` object. There should be no performance change, just a
  performance improvement for programs accessing the ``extensions`` attribute
  multiple times.


.. _v1-9:

1.9 - 2017-05-29
~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** Elliptic Curve signature verification no longer
  returns ``True`` on success. This brings it in line with the interface's
  documentation, and our intent. The correct way to use
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.verify`
  has always been to check whether or not
  :class:`~cryptography.exceptions.InvalidSignature` was raised.
* **BACKWARDS INCOMPATIBLE:** Dropped support for macOS 10.7 and 10.8.
* **BACKWARDS INCOMPATIBLE:** The minimum supported PyPy version is now 5.3.
* Python 3.3 support has been deprecated, and will be removed in the next
  ``cryptography`` release.
* Add support for providing ``tag`` during
  :class:`~cryptography.hazmat.primitives.ciphers.modes.GCM` finalization via
  :meth:`~cryptography.hazmat.primitives.ciphers.AEADDecryptionContext.finalize_with_tag`.
* Fixed an issue preventing ``cryptography`` from compiling against
  LibreSSL 2.5.x.
* Added
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.key_size`
  and
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.key_size`
  as convenience methods for determining the bit size of a secret scalar for
  the curve.
* Accessing an unrecognized extension marked critical on an X.509 object will
  no longer raise an ``UnsupportedExtension`` exception, instead an
  :class:`~cryptography.x509.UnrecognizedExtension` object will be returned.
  This behavior was based on a poor reading of the RFC, unknown critical
  extensions only need to be rejected on certificate verification.
* The CommonCrypto backend has been removed.
* MultiBackend has been removed.
* ``Whirlpool`` and ``RIPEMD160`` have been deprecated.


.. _v1-8-2:

1.8.2 - 2017-05-26
~~~~~~~~~~~~~~~~~~

* Fixed a compilation bug affecting OpenSSL 1.1.0f.
* Updated Windows and macOS wheels to be compiled against OpenSSL 1.1.0f.


.. _v1-8-1:

1.8.1 - 2017-03-10
~~~~~~~~~~~~~~~~~~

* Fixed macOS wheels to properly link against 1.1.0 rather than 1.0.2.


.. _v1-8:

1.8 - 2017-03-09
~~~~~~~~~~~~~~~~

* Added support for Python 3.6.
* Windows and macOS wheels now link against OpenSSL 1.1.0.
* macOS wheels are no longer universal. This change significantly shrinks the
  size of the wheels. Users on macOS 32-bit Python (if there are any) should
  migrate to 64-bit or build their own packages.
* Changed ASN.1 dependency from ``pyasn1`` to ``asn1crypto`` resulting in a
  general performance increase when encoding/decoding ASN.1 structures. Also,
  the ``pyasn1_modules`` test dependency is no longer required.
* Added support for
  :meth:`~cryptography.hazmat.primitives.ciphers.CipherContext.update_into` on
  :class:`~cryptography.hazmat.primitives.ciphers.CipherContext`.
* Added
  :meth:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKeyWithSerialization.private_bytes`
  to
  :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKeyWithSerialization`.
* Added
  :meth:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey.public_bytes`
  to
  :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey`.
* :func:`~cryptography.hazmat.primitives.serialization.load_pem_private_key`
  and
  :func:`~cryptography.hazmat.primitives.serialization.load_der_private_key`
  now require that ``password`` must be bytes if provided. Previously this
  was documented but not enforced.
* Added support for subgroup order in :doc:`/hazmat/primitives/asymmetric/dh`.


.. _v1-7-2:

1.7.2 - 2017-01-27
~~~~~~~~~~~~~~~~~~

* Updated Windows and macOS wheels to be compiled against OpenSSL 1.0.2k.


.. _v1-7-1:

1.7.1 - 2016-12-13
~~~~~~~~~~~~~~~~~~

* Fixed a regression in ``int_from_bytes`` where it failed to accept
  ``bytearray``.


.. _v1-7:

1.7 - 2016-12-12
~~~~~~~~~~~~~~~~

* Support for OpenSSL 1.0.0 has been removed. Users on older version of OpenSSL
  will need to upgrade.
* Added support for Diffie-Hellman key exchange using
  :meth:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey.exchange`.
* The OS random engine for OpenSSL has been rewritten to improve compatibility
  with embedded Python and other edge cases. More information about this change
  can be found in the
  `pull request <https://github.com/pyca/cryptography/pull/3229>`_.


.. _v1-6:

1.6 - 2016-11-22
~~~~~~~~~~~~~~~~

* Deprecated support for OpenSSL 1.0.0. Support will be removed in
  ``cryptography`` 1.7.
* Replaced the Python-based OpenSSL locking callbacks with a C version to fix
  a potential deadlock that could occur if a garbage collection cycle occurred
  while inside the lock.
* Added support for :class:`~cryptography.hazmat.primitives.hashes.BLAKE2b` and
  :class:`~cryptography.hazmat.primitives.hashes.BLAKE2s` when using OpenSSL
  1.1.0.
* Added
  :attr:`~cryptography.x509.Certificate.signature_algorithm_oid` support to
  :class:`~cryptography.x509.Certificate`.
* Added
  :attr:`~cryptography.x509.CertificateSigningRequest.signature_algorithm_oid`
  support to :class:`~cryptography.x509.CertificateSigningRequest`.
* Added
  :attr:`~cryptography.x509.CertificateRevocationList.signature_algorithm_oid`
  support to :class:`~cryptography.x509.CertificateRevocationList`.
* Added support for :class:`~cryptography.hazmat.primitives.kdf.scrypt.Scrypt`
  when using OpenSSL 1.1.0.
* Added a workaround to improve compatibility with Python application bundling
  tools like ``PyInstaller`` and ``cx_freeze``.
* Added support for generating a
  :meth:`~cryptography.x509.random_serial_number`.
* Added support for encoding ``IPv4Network`` and ``IPv6Network`` in X.509
  certificates for use with :class:`~cryptography.x509.NameConstraints`.
* Added :meth:`~cryptography.x509.Name.public_bytes` to
  :class:`~cryptography.x509.Name`.
* Added :class:`~cryptography.x509.RelativeDistinguishedName`
* :class:`~cryptography.x509.DistributionPoint` now accepts
  :class:`~cryptography.x509.RelativeDistinguishedName` for
  :attr:`~cryptography.x509.DistributionPoint.relative_name`.
  Deprecated use of :class:`~cryptography.x509.Name` as
  :attr:`~cryptography.x509.DistributionPoint.relative_name`.
* :class:`~cryptography.x509.Name` now accepts an iterable of
  :class:`~cryptography.x509.RelativeDistinguishedName`.  RDNs can
  be accessed via the :attr:`~cryptography.x509.Name.rdns`
  attribute.  When constructed with an iterable of
  :class:`~cryptography.x509.NameAttribute`, each attribute becomes
  a single-valued RDN.
* Added
  :func:`~cryptography.hazmat.primitives.asymmetric.ec.derive_private_key`.
* Added support for signing and verifying RSA, DSA, and ECDSA signatures with
  :class:`~cryptography.hazmat.primitives.asymmetric.utils.Prehashed`
  digests.


.. _v1-5-3:

1.5.3 - 2016-11-05
~~~~~~~~~~~~~~~~~~

* **SECURITY ISSUE**: Fixed a bug where ``HKDF`` would return an empty
  byte-string if used with a ``length`` less than ``algorithm.digest_size``.
  Credit to **Markus Döring** for reporting the issue. *CVE-2016-9243*


.. _v1-5-2:

1.5.2 - 2016-09-26
~~~~~~~~~~~~~~~~~~

* Updated Windows and OS X wheels to be compiled against OpenSSL 1.0.2j.


.. _v1-5-1:

1.5.1 - 2016-09-22
~~~~~~~~~~~~~~~~~~

* Updated Windows and OS X wheels to be compiled against OpenSSL 1.0.2i.
* Resolved a ``UserWarning`` when used with cffi 1.8.3.
* Fixed a memory leak in name creation with X.509.
* Added a workaround for old versions of setuptools.
* Fixed an issue preventing ``cryptography`` from compiling against
  OpenSSL 1.0.2i.



.. _v1-5:

1.5 - 2016-08-26
~~~~~~~~~~~~~~~~

* Added
  :func:`~cryptography.hazmat.primitives.asymmetric.padding.calculate_max_pss_salt_length`.
* Added "one shot"
  :meth:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey.sign`
  and
  :meth:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey.verify`
  methods to DSA keys.
* Added "one shot"
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.sign`
  and
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.verify`
  methods to ECDSA keys.
* Switched back to the older callback model on Python 3.5 in order to mitigate
  the locking callback problem with OpenSSL <1.1.0.
* :class:`~cryptography.x509.CertificateBuilder`,
  :class:`~cryptography.x509.CertificateRevocationListBuilder`, and
  :class:`~cryptography.x509.RevokedCertificateBuilder` now accept timezone
  aware ``datetime`` objects as method arguments
* ``cryptography`` now supports OpenSSL 1.1.0 as a compilation target.



.. _v1-4:

1.4 - 2016-06-04
~~~~~~~~~~~~~~~~

* Support for OpenSSL 0.9.8 has been removed. Users on older versions of
  OpenSSL will need to upgrade.
* Added :class:`~cryptography.hazmat.primitives.kdf.kbkdf.KBKDFHMAC`.
* Added support for ``OpenSSH`` public key serialization.
* Added support for SHA-2 in RSA
  :class:`~cryptography.hazmat.primitives.asymmetric.padding.OAEP` when using
  OpenSSL 1.0.2 or greater.
* Added "one shot"
  :meth:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.sign`
  and
  :meth:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.verify`
  methods to RSA keys.
* Deprecated the ``serial`` attribute on
  :class:`~cryptography.x509.Certificate`, in favor of
  :attr:`~cryptography.x509.Certificate.serial_number`.



.. _v1-3-4:

1.3.4 - 2016-06-03
~~~~~~~~~~~~~~~~~~

* Added another OpenSSL function to the bindings to support an upcoming
  ``pyOpenSSL`` release.



.. _v1-3-3:

1.3.3 - 2016-06-02
~~~~~~~~~~~~~~~~~~

* Added two new OpenSSL functions to the bindings to support an upcoming
  ``pyOpenSSL`` release.


.. _v1-3-2:

1.3.2 - 2016-05-04
~~~~~~~~~~~~~~~~~~

* Updated Windows and OS X wheels to be compiled against OpenSSL 1.0.2h.
* Fixed an issue preventing ``cryptography`` from compiling against
  LibreSSL 2.3.x.


.. _v1-3-1:

1.3.1 - 2016-03-21
~~~~~~~~~~~~~~~~~~

* Fixed a bug that caused an ``AttributeError`` when using ``mock`` to patch
  some ``cryptography`` modules.


.. _v1-3:

1.3 - 2016-03-18
~~~~~~~~~~~~~~~~

* Added support for padding ANSI X.923 with
  :class:`~cryptography.hazmat.primitives.padding.ANSIX923`.
* Deprecated support for OpenSSL 0.9.8. Support will be removed in
  ``cryptography`` 1.4.
* Added support for the :class:`~cryptography.x509.PolicyConstraints`
  X.509 extension including both parsing and generation using
  :class:`~cryptography.x509.CertificateBuilder` and
  :class:`~cryptography.x509.CertificateSigningRequestBuilder`.
* Added :attr:`~cryptography.x509.CertificateSigningRequest.is_signature_valid`
  to :class:`~cryptography.x509.CertificateSigningRequest`.
* Fixed an intermittent ``AssertionError`` when performing an RSA decryption on
  an invalid ciphertext, ``ValueError`` is now correctly raised in all cases.
* Added
  :meth:`~cryptography.x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier`.


.. _v1-2-3:

1.2.3 - 2016-03-01
~~~~~~~~~~~~~~~~~~

* Updated Windows and OS X wheels to be compiled against OpenSSL 1.0.2g.


.. _v1-2-2:

1.2.2 - 2016-01-29
~~~~~~~~~~~~~~~~~~

* Updated Windows and OS X wheels to be compiled against OpenSSL 1.0.2f.


.. _v1-2-1:

1.2.1 - 2016-01-08
~~~~~~~~~~~~~~~~~~

* Reverts a change to an OpenSSL ``EVP_PKEY`` object that caused errors with
  ``pyOpenSSL``.


.. _v1-2:

1.2 - 2016-01-08
~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:**
  :class:`~cryptography.x509.RevokedCertificate`
  :attr:`~cryptography.x509.RevokedCertificate.extensions` now uses extension
  classes rather than returning raw values inside the
  :class:`~cryptography.x509.Extension`
  :attr:`~cryptography.x509.Extension.value`. The new classes
  are:

  * :class:`~cryptography.x509.CertificateIssuer`
  * :class:`~cryptography.x509.CRLReason`
  * :class:`~cryptography.x509.InvalidityDate`
* Deprecated support for OpenSSL 0.9.8 and 1.0.0. At this time there is no time
  table for actually dropping support, however we strongly encourage all users
  to upgrade, as those versions no longer receive support from the OpenSSL
  project.
* The :class:`~cryptography.x509.Certificate` class now has
  :attr:`~cryptography.x509.Certificate.signature` and
  :attr:`~cryptography.x509.Certificate.tbs_certificate_bytes` attributes.
* The :class:`~cryptography.x509.CertificateSigningRequest` class now has
  :attr:`~cryptography.x509.CertificateSigningRequest.signature` and
  :attr:`~cryptography.x509.CertificateSigningRequest.tbs_certrequest_bytes`
  attributes.
* The :class:`~cryptography.x509.CertificateRevocationList` class now has
  :attr:`~cryptography.x509.CertificateRevocationList.signature` and
  :attr:`~cryptography.x509.CertificateRevocationList.tbs_certlist_bytes`
  attributes.
* :class:`~cryptography.x509.NameConstraints` are now supported in the
  :class:`~cryptography.x509.CertificateBuilder` and
  :class:`~cryptography.x509.CertificateSigningRequestBuilder`.
* Support serialization of certificate revocation lists using the
  :meth:`~cryptography.x509.CertificateRevocationList.public_bytes` method of
  :class:`~cryptography.x509.CertificateRevocationList`.
* Add support for parsing :class:`~cryptography.x509.CertificateRevocationList`
  :meth:`~cryptography.x509.CertificateRevocationList.extensions` in the
  OpenSSL backend. The following extensions are currently supported:

  * :class:`~cryptography.x509.AuthorityInformationAccess`
  * :class:`~cryptography.x509.AuthorityKeyIdentifier`
  * :class:`~cryptography.x509.CRLNumber`
  * :class:`~cryptography.x509.IssuerAlternativeName`
* Added :class:`~cryptography.x509.CertificateRevocationListBuilder` and
  :class:`~cryptography.x509.RevokedCertificateBuilder` to allow creation of
  CRLs.
* Unrecognized non-critical X.509 extensions are now parsed into an
  :class:`~cryptography.x509.UnrecognizedExtension` object.


.. _v1-1-2:

1.1.2 - 2015-12-10
~~~~~~~~~~~~~~~~~~

* Fixed a SIGBUS crash with the OS X wheels caused by redefinition of a
  method.
* Fixed a runtime error ``undefined symbol EC_GFp_nistp224_method`` that
  occurred with some OpenSSL installations.
* Updated Windows and OS X wheels to be compiled against OpenSSL 1.0.2e.


.. _v1-1-1:

1.1.1 - 2015-11-19
~~~~~~~~~~~~~~~~~~

* Fixed several small bugs related to compiling the OpenSSL bindings with
  unusual OpenSSL configurations.
* Resolved an issue where, depending on the method of installation and
  which Python interpreter they were using, users on El Capitan (OS X 10.11)
  may have seen an ``InternalError`` on import.


.. _v1-1:

1.1 - 2015-10-28
~~~~~~~~~~~~~~~~

* Added support for Elliptic Curve Diffie-Hellman with
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.ECDH`.
* Added :class:`~cryptography.hazmat.primitives.kdf.x963kdf.X963KDF`.
* Added support for parsing certificate revocation lists (CRLs) using
  :func:`~cryptography.x509.load_pem_x509_crl` and
  :func:`~cryptography.x509.load_der_x509_crl`.
* Add support for AES key wrapping with
  :func:`~cryptography.hazmat.primitives.keywrap.aes_key_wrap` and
  :func:`~cryptography.hazmat.primitives.keywrap.aes_key_unwrap`.
* Added a ``__hash__`` method to :class:`~cryptography.x509.Name`.
* Add support for encoding and decoding elliptic curve points to a byte string
  form using
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers.encode_point`
  and
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers.from_encoded_point`.
* Added :meth:`~cryptography.x509.Extensions.get_extension_for_class`.
* :class:`~cryptography.x509.CertificatePolicies` are now supported in the
  :class:`~cryptography.x509.CertificateBuilder`.
* ``countryName`` is now encoded as a ``PrintableString`` when creating subject
  and issuer distinguished names with the Certificate and CSR builder classes.


.. _v1-0-2:

1.0.2 - 2015-09-27
~~~~~~~~~~~~~~~~~~
* **SECURITY ISSUE**: The OpenSSL backend prior to 1.0.2 made extensive use
  of assertions to check response codes where our tests could not trigger a
  failure.  However, when Python is run with ``-O`` these asserts are optimized
  away.  If a user ran Python with this flag and got an invalid response code
  this could result in undefined behavior or worse. Accordingly, all response
  checks from the OpenSSL backend have been converted from ``assert``
  to a true function call. Credit **Emilia Käsper (Google Security Team)**
  for the report.


.. _v1-0-1:

1.0.1 - 2015-09-05
~~~~~~~~~~~~~~~~~~

* We now ship OS X wheels that statically link OpenSSL by default. When
  installing a wheel on OS X 10.10+ (and using a Python compiled against the
  10.10 SDK) users will no longer need to compile. See :doc:`/installation` for
  alternate installation methods if required.
* Set the default string mask to UTF-8 in the OpenSSL backend to resolve
  character encoding issues with older versions of OpenSSL.
* Several new OpenSSL bindings have been added to support a future pyOpenSSL
  release.
* Raise an error during install on PyPy < 2.6. 1.0+ requires PyPy 2.6+.


.. _v1-0:

1.0 - 2015-08-12
~~~~~~~~~~~~~~~~

* Switched to the new `cffi`_ ``set_source`` out-of-line API mode for
  compilation. This results in significantly faster imports and lowered
  memory consumption. Due to this change we no longer support PyPy releases
  older than 2.6 nor do we support any released version of PyPy3 (until a
  version supporting cffi 1.0 comes out).
* Fix parsing of OpenSSH public keys that have spaces in comments.
* Support serialization of certificate signing requests using the
  ``public_bytes`` method of
  :class:`~cryptography.x509.CertificateSigningRequest`.
* Support serialization of certificates using the ``public_bytes`` method of
  :class:`~cryptography.x509.Certificate`.
* Add ``get_provisioning_uri`` method to
  :class:`~cryptography.hazmat.primitives.twofactor.hotp.HOTP` and
  :class:`~cryptography.hazmat.primitives.twofactor.totp.TOTP` for generating
  provisioning URIs.
* Add :class:`~cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHash`
  and :class:`~cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHMAC`.
* Raise a ``TypeError`` when passing objects that are not text as the value to
  :class:`~cryptography.x509.NameAttribute`.
* Add support for :class:`~cryptography.x509.OtherName` as a general name
  type.
* Added new X.509 extension support in :class:`~cryptography.x509.Certificate`
  The following new extensions are now supported:

  * :class:`~cryptography.x509.OCSPNoCheck`
  * :class:`~cryptography.x509.InhibitAnyPolicy`
  * :class:`~cryptography.x509.IssuerAlternativeName`
  * :class:`~cryptography.x509.NameConstraints`

* Extension support was added to
  :class:`~cryptography.x509.CertificateSigningRequest`.
* Add support for creating signed certificates with
  :class:`~cryptography.x509.CertificateBuilder`. This includes support for
  the following extensions:

  * :class:`~cryptography.x509.BasicConstraints`
  * :class:`~cryptography.x509.SubjectAlternativeName`
  * :class:`~cryptography.x509.KeyUsage`
  * :class:`~cryptography.x509.ExtendedKeyUsage`
  * :class:`~cryptography.x509.SubjectKeyIdentifier`
  * :class:`~cryptography.x509.AuthorityKeyIdentifier`
  * :class:`~cryptography.x509.AuthorityInformationAccess`
  * :class:`~cryptography.x509.CRLDistributionPoints`
  * :class:`~cryptography.x509.InhibitAnyPolicy`
  * :class:`~cryptography.x509.IssuerAlternativeName`
  * :class:`~cryptography.x509.OCSPNoCheck`

* Add support for creating certificate signing requests with
  :class:`~cryptography.x509.CertificateSigningRequestBuilder`. This includes
  support for the same extensions supported in the ``CertificateBuilder``.
* Deprecate ``encode_rfc6979_signature`` and ``decode_rfc6979_signature`` in
  favor of
  :func:`~cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature`
  and
  :func:`~cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature`.



.. _v0-9-3:

0.9.3 - 2015-07-09
~~~~~~~~~~~~~~~~~~

* Updated Windows wheels to be compiled against OpenSSL 1.0.2d.


.. _v0-9-2:

0.9.2 - 2015-07-04
~~~~~~~~~~~~~~~~~~

* Updated Windows wheels to be compiled against OpenSSL 1.0.2c.


.. _v0-9-1:

0.9.1 - 2015-06-06
~~~~~~~~~~~~~~~~~~

* **SECURITY ISSUE**: Fixed a double free in the OpenSSL backend when using DSA
  to verify signatures. Note that this only affects PyPy 2.6.0 and (presently
  unreleased) CFFI versions greater than 1.1.0.


.. _v0-9:

0.9 - 2015-05-13
~~~~~~~~~~~~~~~~

* Removed support for Python 3.2. This version of Python is rarely used
  and caused support headaches. Users affected by this should upgrade to 3.3+.
* Deprecated support for Python 2.6. At the time there is no time table for
  actually dropping support, however we strongly encourage all users to upgrade
  their Python, as Python 2.6 no longer receives support from the Python core
  team.
* Add support for the
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.SECP256K1` elliptic
  curve.
* Fixed compilation when using an OpenSSL which was compiled with the
  ``no-comp`` (``OPENSSL_NO_COMP``) option.
* Support :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`
  serialization of public keys using the ``public_bytes`` method of
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithSerialization`,
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKeyWithSerialization`,
  and
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKeyWithSerialization`.
* Support :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`
  serialization of private keys using the ``private_bytes`` method of
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization`,
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization`,
  and
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization`.
* Add support for parsing X.509 certificate signing requests (CSRs) with
  :func:`~cryptography.x509.load_pem_x509_csr` and
  :func:`~cryptography.x509.load_der_x509_csr`.
* Moved ``cryptography.exceptions.InvalidToken`` to
  :class:`cryptography.hazmat.primitives.twofactor.InvalidToken` and deprecated
  the old location. This was moved to minimize confusion between this exception
  and :class:`cryptography.fernet.InvalidToken`.
* Added support for X.509 extensions in :class:`~cryptography.x509.Certificate`
  objects. The following extensions are supported as of this release:

  * :class:`~cryptography.x509.BasicConstraints`
  * :class:`~cryptography.x509.AuthorityKeyIdentifier`
  * :class:`~cryptography.x509.SubjectKeyIdentifier`
  * :class:`~cryptography.x509.KeyUsage`
  * :class:`~cryptography.x509.SubjectAlternativeName`
  * :class:`~cryptography.x509.ExtendedKeyUsage`
  * :class:`~cryptography.x509.CRLDistributionPoints`
  * :class:`~cryptography.x509.AuthorityInformationAccess`
  * :class:`~cryptography.x509.CertificatePolicies`

  Note that unsupported extensions with the critical flag raise
  ``UnsupportedExtension`` while unsupported extensions set to non-critical are
  silently ignored. Read the :doc:`X.509 documentation</x509/index>` for more
  information.


.. _v0-8-2:

0.8.2 - 2015-04-10
~~~~~~~~~~~~~~~~~~

* Fixed a race condition when initializing the OpenSSL or CommonCrypto backends
  in a multi-threaded scenario.


.. _v0-8-1:

0.8.1 - 2015-03-20
~~~~~~~~~~~~~~~~~~

* Updated Windows wheels to be compiled against OpenSSL 1.0.2a.


.. _v0-8:

0.8 - 2015-03-08
~~~~~~~~~~~~~~~~

* :func:`~cryptography.hazmat.primitives.serialization.load_ssh_public_key` can
  now load elliptic curve public keys.
* Added
  :attr:`~cryptography.x509.Certificate.signature_hash_algorithm` support to
  :class:`~cryptography.x509.Certificate`.
* Added
  :func:`~cryptography.hazmat.primitives.asymmetric.rsa.rsa_recover_prime_factors`
* :class:`~cryptography.hazmat.primitives.kdf.KeyDerivationFunction` was moved
  from ``cryptography.hazmat.primitives.interfaces`` to
  :mod:`~cryptography.hazmat.primitives.kdf`.
* Added support for parsing X.509 names. See the
  :doc:`X.509 documentation</x509/index>` for more information.
* Added
  :func:`~cryptography.hazmat.primitives.serialization.load_der_private_key` to
  support loading of DER encoded private keys and
  :func:`~cryptography.hazmat.primitives.serialization.load_der_public_key` to
  support loading DER encoded public keys.
* Fixed building against LibreSSL, a compile-time substitute for OpenSSL.
* FreeBSD 9.2 was removed from the continuous integration system.
* Updated Windows wheels to be compiled against OpenSSL 1.0.2.
* :func:`~cryptography.hazmat.primitives.serialization.load_pem_public_key`
  and :func:`~cryptography.hazmat.primitives.serialization.load_der_public_key`
  now support PKCS1 RSA public keys (in addition to the previous support for
  SubjectPublicKeyInfo format for RSA, EC, and DSA).
* Added
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization`
  and deprecated ``EllipticCurvePrivateKeyWithNumbers``.
* Added
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization.private_bytes`
  to
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization`.
* Added
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization`
  and deprecated ``RSAPrivateKeyWithNumbers``.
* Added
  :meth:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization.private_bytes`
  to
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization`.
* Added
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization`
  and deprecated ``DSAPrivateKeyWithNumbers``.
* Added
  :meth:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization.private_bytes`
  to
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization`.
* Added
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithSerialization`
  and deprecated ``RSAPublicKeyWithNumbers``.
* Added ``public_bytes`` to
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithSerialization`.
* Added
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKeyWithSerialization`
  and deprecated ``EllipticCurvePublicKeyWithNumbers``.
* Added ``public_bytes`` to
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKeyWithSerialization`.
* Added
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKeyWithSerialization`
  and deprecated ``DSAPublicKeyWithNumbers``.
* Added ``public_bytes`` to
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKeyWithSerialization`.
* :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` and
  :class:`~cryptography.hazmat.primitives.hashes.HashContext` were moved from
  ``cryptography.hazmat.primitives.interfaces`` to
  :mod:`~cryptography.hazmat.primitives.hashes`.
* :class:`~cryptography.hazmat.primitives.ciphers.CipherContext`,
  :class:`~cryptography.hazmat.primitives.ciphers.AEADCipherContext`,
  :class:`~cryptography.hazmat.primitives.ciphers.AEADEncryptionContext`,
  :class:`~cryptography.hazmat.primitives.ciphers.CipherAlgorithm`, and
  :class:`~cryptography.hazmat.primitives.ciphers.BlockCipherAlgorithm`
  were moved from ``cryptography.hazmat.primitives.interfaces`` to
  :mod:`~cryptography.hazmat.primitives.ciphers`.
* :class:`~cryptography.hazmat.primitives.ciphers.modes.Mode`,
  :class:`~cryptography.hazmat.primitives.ciphers.modes.ModeWithInitializationVector`,
  :class:`~cryptography.hazmat.primitives.ciphers.modes.ModeWithNonce`, and
  :class:`~cryptography.hazmat.primitives.ciphers.modes.ModeWithAuthenticationTag`
  were moved from ``cryptography.hazmat.primitives.interfaces`` to
  :mod:`~cryptography.hazmat.primitives.ciphers.modes`.
* :class:`~cryptography.hazmat.primitives.padding.PaddingContext` was moved
  from ``cryptography.hazmat.primitives.interfaces`` to
  :mod:`~cryptography.hazmat.primitives.padding`.
*
  :class:`~cryptography.hazmat.primitives.asymmetric.padding.AsymmetricPadding`
  was moved from ``cryptography.hazmat.primitives.interfaces`` to
  :mod:`~cryptography.hazmat.primitives.asymmetric.padding`.
* ``AsymmetricSignatureContext`` and ``AsymmetricVerificationContext``
  were moved from ``cryptography.hazmat.primitives.interfaces`` to
  ``cryptography.hazmat.primitives.asymmetric``.
* :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters`,
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParametersWithNumbers`,
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`,
  ``DSAPrivateKeyWithNumbers``,
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey` and
  ``DSAPublicKeyWithNumbers`` were moved from
  ``cryptography.hazmat.primitives.interfaces`` to
  :mod:`~cryptography.hazmat.primitives.asymmetric.dsa`
* :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve`,
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurveSignatureAlgorithm`,
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`,
  ``EllipticCurvePrivateKeyWithNumbers``,
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`,
  and ``EllipticCurvePublicKeyWithNumbers``
  were moved from ``cryptography.hazmat.primitives.interfaces`` to
  :mod:`~cryptography.hazmat.primitives.asymmetric.ec`.
* :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`,
  ``RSAPrivateKeyWithNumbers``,
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey` and
  ``RSAPublicKeyWithNumbers`` were moved from
  ``cryptography.hazmat.primitives.interfaces`` to
  :mod:`~cryptography.hazmat.primitives.asymmetric.rsa`.


.. _v0-7-2:

0.7.2 - 2015-01-16
~~~~~~~~~~~~~~~~~~

* Updated Windows wheels to be compiled against OpenSSL 1.0.1l.
* ``enum34`` is no longer installed on Python 3.4, where it is included in
  the standard library.
* Added a new function to the OpenSSL bindings to support additional
  functionality in pyOpenSSL.


.. _v0-7-1:

0.7.1 - 2014-12-28
~~~~~~~~~~~~~~~~~~

* Fixed an issue preventing compilation on platforms where ``OPENSSL_NO_SSL3``
  was defined.


.. _v0-7:

0.7 - 2014-12-17
~~~~~~~~~~~~~~~~

* Cryptography has been relicensed from the Apache Software License, Version
  2.0, to being available under *either* the Apache Software License, Version
  2.0, or the BSD license.
* Added key-rotation support to :doc:`Fernet </fernet>` with
  :class:`~cryptography.fernet.MultiFernet`.
* More bit-lengths are now supported for ``p`` and ``q`` when loading DSA keys
  from numbers.
* Added :class:`~cryptography.hazmat.primitives.mac.MACContext` as a
  common interface for CMAC and HMAC and deprecated ``CMACContext``.
* Added support for encoding and decoding :rfc:`6979` signatures in
  :doc:`/hazmat/primitives/asymmetric/utils`.
* Added
  :func:`~cryptography.hazmat.primitives.serialization.load_ssh_public_key` to
  support the loading of OpenSSH public keys (:rfc:`4253`). Only RSA and DSA
  keys are currently supported.
* Added initial support for X.509 certificate parsing. See the
  :doc:`X.509 documentation</x509/index>` for more information.


.. _v0-6-1:

0.6.1 - 2014-10-15
~~~~~~~~~~~~~~~~~~

* Updated Windows wheels to be compiled against OpenSSL 1.0.1j.
* Fixed an issue where OpenSSL 1.0.1j changed the errors returned by some
  functions.
* Added our license file to the ``cryptography-vectors`` package.
* Implemented DSA hash truncation support (per FIPS 186-3) in the OpenSSL
  backend. This works around an issue in 1.0.0, 1.0.0a, and 1.0.0b where
  truncation was not implemented.


.. _v0-6:

0.6 - 2014-09-29
~~~~~~~~~~~~~~~~

* Added
  :func:`~cryptography.hazmat.primitives.serialization.load_pem_private_key` to
  ease loading private keys, and
  :func:`~cryptography.hazmat.primitives.serialization.load_pem_public_key` to
  support loading public keys.
* Removed the, deprecated in 0.4, support for the ``salt_length`` argument to
  the :class:`~cryptography.hazmat.primitives.asymmetric.padding.MGF1`
  constructor. The ``salt_length`` should be passed to
  :class:`~cryptography.hazmat.primitives.asymmetric.padding.PSS` instead.
* Fix compilation on OS X Yosemite.
* Deprecated ``elliptic_curve_private_key_from_numbers`` and
  ``elliptic_curve_public_key_from_numbers`` in favor of
  ``load_elliptic_curve_private_numbers`` and
  ``load_elliptic_curve_public_numbers`` on
  :class:`~cryptography.hazmat.backends.interfaces.EllipticCurveBackend`.
* Added ``EllipticCurvePrivateKeyWithNumbers`` and
  ``EllipticCurvePublicKeyWithNumbers`` support.
* Work around three GCM related bugs in CommonCrypto and OpenSSL.

  * On the CommonCrypto backend adding AAD but not subsequently calling update
    would return null tag bytes.

  * One the CommonCrypto backend a call to update without an empty add AAD call
    would return null ciphertext bytes.

  * On the OpenSSL backend with certain versions adding AAD only would give
    invalid tag bytes.

* Support loading EC private keys from PEM.


.. _v0-5-4:

0.5.4 - 2014-08-20
~~~~~~~~~~~~~~~~~~

* Added several functions to the OpenSSL bindings to support new
  functionality in pyOpenSSL.
* Fixed a redefined constant causing compilation failure with Solaris 11.2.


.. _v0-5-3:

0.5.3 - 2014-08-06
~~~~~~~~~~~~~~~~~~

* Updated Windows wheels to be compiled against OpenSSL 1.0.1i.


.. _v0-5-2:

0.5.2 - 2014-07-09
~~~~~~~~~~~~~~~~~~

* Add ``TraditionalOpenSSLSerializationBackend`` support to ``multibackend``.
* Fix compilation error on OS X 10.8 (Mountain Lion).


.. _v0-5-1:

0.5.1 - 2014-07-07
~~~~~~~~~~~~~~~~~~

* Add ``PKCS8SerializationBackend`` support to ``multibackend``.


.. _v0-5:

0.5 - 2014-07-07
~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:**
  :class:`~cryptography.hazmat.primitives.ciphers.modes.GCM` no longer allows
  truncation of tags by default. Previous versions of ``cryptography`` allowed
  tags to be truncated by default, applications wishing to preserve this
  behavior (not recommended) can pass the ``min_tag_length`` argument.
* Windows builds now statically link OpenSSL by default. When installing a
  wheel on Windows you no longer need to install OpenSSL separately. Windows
  users can switch between static and dynamic linking with an environment
  variable. See :doc:`/installation` for more details.
* Added :class:`~cryptography.hazmat.primitives.kdf.hkdf.HKDFExpand`.
* Added :class:`~cryptography.hazmat.primitives.ciphers.modes.CFB8` support
  for :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES` and
  :class:`~cryptography.hazmat.primitives.ciphers.algorithms.TripleDES` on
  ``commoncrypto`` and :doc:`/hazmat/backends/openssl`.
* Added ``AES`` :class:`~cryptography.hazmat.primitives.ciphers.modes.CTR`
  support to the OpenSSL backend when linked against 0.9.8.
* Added ``PKCS8SerializationBackend`` and
  ``TraditionalOpenSSLSerializationBackend`` support to the
  :doc:`/hazmat/backends/openssl`.
* Added :doc:`/hazmat/primitives/asymmetric/ec` and
  :class:`~cryptography.hazmat.backends.interfaces.EllipticCurveBackend`.
* Added :class:`~cryptography.hazmat.primitives.ciphers.modes.ECB` support
  for :class:`~cryptography.hazmat.primitives.ciphers.algorithms.TripleDES` on
  ``commoncrypto`` and :doc:`/hazmat/backends/openssl`.
* Deprecated the concrete ``RSAPrivateKey`` class in favor of backend
  specific providers of the
  :class:`cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
  interface.
* Deprecated the concrete ``RSAPublicKey`` in favor of backend specific
  providers of the
  :class:`cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`
  interface.
* Deprecated the concrete ``DSAPrivateKey`` class in favor of backend
  specific providers of the
  :class:`cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`
  interface.
* Deprecated the concrete ``DSAPublicKey`` class in favor of backend specific
  providers of the
  :class:`cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`
  interface.
* Deprecated the concrete ``DSAParameters`` class in favor of backend specific
  providers of the
  :class:`cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters`
  interface.
* Deprecated ``encrypt_rsa``, ``decrypt_rsa``, ``create_rsa_signature_ctx`` and
  ``create_rsa_verification_ctx`` on
  :class:`~cryptography.hazmat.backends.interfaces.RSABackend`.
* Deprecated ``create_dsa_signature_ctx`` and ``create_dsa_verification_ctx``
  on :class:`~cryptography.hazmat.backends.interfaces.DSABackend`.


.. _v0-4:

0.4 - 2014-05-03
~~~~~~~~~~~~~~~~

* Deprecated ``salt_length`` on
  :class:`~cryptography.hazmat.primitives.asymmetric.padding.MGF1` and added it
  to :class:`~cryptography.hazmat.primitives.asymmetric.padding.PSS`. It will
  be removed from ``MGF1`` in two releases per our :doc:`/api-stability`
  policy.
* Added :class:`~cryptography.hazmat.primitives.ciphers.algorithms.SEED`
  support.
* Added :class:`~cryptography.hazmat.primitives.cmac.CMAC`.
* Added decryption support to
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
  and encryption support to
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`.
* Added signature support to
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`
  and verification support to
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`.


.. _v0-3:

0.3 - 2014-03-27
~~~~~~~~~~~~~~~~

* Added :class:`~cryptography.hazmat.primitives.twofactor.hotp.HOTP`.
* Added :class:`~cryptography.hazmat.primitives.twofactor.totp.TOTP`.
* Added :class:`~cryptography.hazmat.primitives.ciphers.algorithms.IDEA`
  support.
* Added signature support to
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
  and verification support to
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`.
* Moved test vectors to the new ``cryptography_vectors`` package.


.. _v0-2-2:

0.2.2 - 2014-03-03
~~~~~~~~~~~~~~~~~~

* Removed a constant definition that was causing compilation problems with
  specific versions of OpenSSL.


.. _v0-2-1:

0.2.1 - 2014-02-22
~~~~~~~~~~~~~~~~~~

* Fix a bug where importing cryptography from multiple paths could cause
  initialization to fail.


.. _v0-2:

0.2 - 2014-02-20
~~~~~~~~~~~~~~~~

* Added ``commoncrypto``.
* Added initial ``commoncrypto``.
* Removed ``register_cipher_adapter`` method from
  :class:`~cryptography.hazmat.backends.interfaces.CipherBackend`.
* Added support for the OpenSSL backend under Windows.
* Improved thread-safety for the OpenSSL backend.
* Fixed compilation on systems where OpenSSL's ``ec.h`` header is not
  available, such as CentOS.
* Added :class:`~cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC`.
* Added :class:`~cryptography.hazmat.primitives.kdf.hkdf.HKDF`.
* Added ``multibackend``.
* Set default random for the :doc:`/hazmat/backends/openssl` to the OS
  random engine.
* Added :class:`~cryptography.hazmat.primitives.ciphers.algorithms.CAST5`
  (CAST-128) support.


.. _v0-1:

0.1 - 2014-01-08
~~~~~~~~~~~~~~~~

* Initial release.

.. _`master`: https://github.com/pyca/cryptography/
.. _`cffi`: https://cffi.readthedocs.io/
