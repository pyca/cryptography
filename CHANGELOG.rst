Changelog
=========

.. _v46-0-0:

46.0.0 - `main`_
~~~~~~~~~~~~~~~~

.. note:: This version is not yet released and is under active development.

* **BACKWARDS INCOMPATIBLE:** Support for Python 3.7 has been removed.
* Removed the deprecated ``get_attribute_for_oid`` method on
  :class:`~cryptography.x509.CertificateSigningRequest`. Users should use
  :meth:`~cryptography.x509.Attributes.get_attribute_for_oid` instead.
* Removed the deprecated ``CAST5``, ``SEED``, ``IDEA``, and ``Blowfish``
  classes from the cipher module. These are still available in
  :doc:`/hazmat/decrepit/index`.

.. _v45-0-4:

45.0.4 - 2025-06-09
~~~~~~~~~~~~~~~~~~~

* Fixed decrypting PKCS#8 files encrypted with SHA1-RC4. (This is not
  considered secure, and is supported only for backwards compatibility.)

.. _v45-0-3:

45.0.3 - 2025-05-25
~~~~~~~~~~~~~~~~~~~

* Fixed decrypting PKCS#8 files encrypted with long salts (this impacts keys
  encrypted by Bouncy Castle).
* Fixed decrypting PKCS#8 files encrypted with DES-CBC-MD5. While wildly
  insecure, this remains prevalent.

.. _v45-0-2:

45.0.2 - 2025-05-17
~~~~~~~~~~~~~~~~~~~

* Fixed using ``mypy`` with ``cryptography`` on older versions of Python.

.. _v45-0-1:

45.0.1 - 2025-05-17
~~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.5.0.

.. _v45-0-0:

45.0.0 - 2025-05-17 (YANKED)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Support for Python 3.7 is deprecated and will be removed in the next
  ``cryptography`` release.
* Updated the minimum supported Rust version (MSRV) to 1.74.0, from 1.65.0.
* Added support for serialization of PKCS#12 Java truststores in
  :func:`~cryptography.hazmat.primitives.serialization.pkcs12.serialize_java_truststore`
* Added :meth:`~cryptography.hazmat.primitives.kdf.argon2.Argon2id.derive_phc_encoded` and
  :meth:`~cryptography.hazmat.primitives.kdf.argon2.Argon2id.verify_phc_encoded` methods
  to support password hashing in the PHC string format
* Added support for PKCS7 decryption and encryption using AES-256 as the
  content algorithm, in addition to AES-128.
* **BACKWARDS INCOMPATIBLE:** Made SSH private key loading more consistent with
  other private key loading:
  :func:`~cryptography.hazmat.primitives.serialization.load_ssh_private_key`
  now raises a ``TypeError`` if the key is unencrypted but a password is
  provided (previously no exception was raised), and raises a ``TypeError`` if
  the key is encrypted but no password is provided (previously a ``ValueError``
  was raised).
* Added ``__copy__`` to the
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.x448.X448PublicKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey`, and
  :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey`
  abstract base classes.
* We significantly refactored how private key loading (
  :func:`~cryptography.hazmat.primitives.serialization.load_pem_private_key`
  and
  :func:`~cryptography.hazmat.primitives.serialization.load_der_private_key`)
  works. This is intended to be backwards compatible for all well-formed keys,
  therefore if you discover a key that now raises an exception, please file a
  bug with instructions for reproducing.
* Added ``unsafe_skip_rsa_key_validation`` keyword-argument to
  :func:`~cryptography.hazmat.primitives.serialization.load_ssh_private_key`.
* Added :class:`~cryptography.hazmat.primitives.hashes.XOFHash` to support
  repeated :meth:`~cryptography.hazmat.primitives.hashes.XOFHash.squeeze`
  operations on extendable output functions.
* Added
  :meth:`~cryptography.x509.ocsp.OCSPResponseBuilder.add_response_by_hash`
  method to allow creating OCSP responses using certificate hash values rather
  than full certificates.
* Extended the :mod:`X.509 path validation <cryptography.x509.verification>` API to
  support user-configured extension policies via the
  :meth:`PolicyBuilder.extension_policies <cryptography.x509.verification.PolicyBuilder.extension_policies>` method.
* Deprecated the ``subject``, ``verification_time`` and ``max_chain_depth``
  properties on :class:`~cryptography.x509.verification.ClientVerifier` and
  :class:`~cryptography.x509.verification.ServerVerifier` in favor of a new ``policy`` property.
  These properties will be removed in the next release of ``cryptography``.
* **BACKWARDS INCOMPATIBLE:** The
  :meth:`VerifiedClient.subject <cryptography.x509.verification.VerifiedClient.subjects>`
  property can now be `None` since a custom extension policy may allow certificates
  without a Subject Alternative Name extension.
* Changed the behavior when the OpenSSL 3 legacy provider fails to load.
  Instead of raising an exception, a warning is now emitted. The
  ``CRYPTOGRAPHY_OPENSSL_NO_LEGACY`` environment variable can still be used to
  disable the legacy provider at runtime.
* Added support for the ``CRYPTOGRAPHY_BUILD_OPENSSL_NO_LEGACY`` environment
  variable during build time, which prevents the library from ever attempting
  to load the legacy provider.
* Added support for the :class:`~cryptography.x509.PrivateKeyUsagePeriod` X.509 extension.
  This extension defines the period during which the private key corresponding
  to the certificate's public key may be used.
* Added support for compiling against `aws-lc`_.
* Parsing X.509 structures now more strictly enforces that ``Name`` structures
  do not have malformed ASN.1.
* We now publish ``py311`` wheels that utilize the faster ``pyo3::buffer::PyBuffer``
  interface, resulting in significantly improved performance for operations
  involving small buffers.
* Added :func:`~cryptography.hazmat.primitives.serialization.ssh_key_fingerprint`
  for computing fingerprints of SSH public keys.
* Added support for deterministic ECDSA signing via the new keyword-only argument
  ``ecdsa_deterministic`` in :meth:`~cryptography.x509.CertificateBuilder.sign`,
  :meth:`~cryptography.x509.CertificateRevocationListBuilder.sign`
  and :meth:`~cryptography.x509.CertificateSigningRequestBuilder.sign`.

.. _v44-0-3:

44.0.3 - 2025-05-02
~~~~~~~~~~~~~~~~~~~

* Fixed compilation when using LibreSSL 4.1.0.

.. _v44-0-2:

44.0.2 - 2025-03-01
~~~~~~~~~~~~~~~~~~~

* We now build wheels for PyPy 3.11.

.. _v44-0-1:

44.0.1 - 2025-02-11
~~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.4.1.
* We now build ``armv7l`` ``manylinux`` wheels and publish them to PyPI.
* We now build ``manylinux_2_34`` wheels and publish them to PyPI.

.. _v44-0-0:

44.0.0 - 2024-11-27
~~~~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** Dropped support for LibreSSL < 3.9.
* Deprecated Python 3.7 support. Python 3.7 is no longer supported by the
  Python core team. Support for Python 3.7 will be removed in a future
  ``cryptography`` release.
* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.4.0.
* macOS wheels are now built against the macOS 10.13 SDK. Users on older
  versions of macOS should upgrade, or they will need to build
  ``cryptography`` themselves.
* Enforce the :rfc:`5280` requirement that extended key usage extensions must
  not be empty.
* Added support for timestamp extraction to the
  :class:`~cryptography.fernet.MultiFernet` class.
* Relax the Authority Key Identifier requirements on root CA certificates
  during X.509 verification to allow fields permitted by :rfc:`5280` but
  forbidden by the CA/Browser BRs.
* Added support for :class:`~cryptography.hazmat.primitives.kdf.argon2.Argon2id`
  when using OpenSSL 3.2.0+.
* Added support for the :class:`~cryptography.x509.Admissions` certificate extension.
* Added basic support for PKCS7 decryption (including S/MIME 3.2) via
  :func:`~cryptography.hazmat.primitives.serialization.pkcs7.pkcs7_decrypt_der`,
  :func:`~cryptography.hazmat.primitives.serialization.pkcs7.pkcs7_decrypt_pem`, and
  :func:`~cryptography.hazmat.primitives.serialization.pkcs7.pkcs7_decrypt_smime`.

.. _v43-0-3:

43.0.3 - 2024-10-18
~~~~~~~~~~~~~~~~~~~

* Fixed release metadata for ``cryptography-vectors``

.. _v43-0-2:

43.0.2 - 2024-10-18
~~~~~~~~~~~~~~~~~~~

* Fixed compilation when using LibreSSL 4.0.0.

.. _v43-0-1:

43.0.1 - 2024-09-03
~~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.3.2.

.. _v43-0-0:

43.0.0 - 2024-07-20
~~~~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** Support for OpenSSL less than 1.1.1e has been
  removed.  Users on older version of OpenSSL will need to upgrade.
* **BACKWARDS INCOMPATIBLE:** Dropped support for LibreSSL < 3.8.
* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.3.1.
* Updated the minimum supported Rust version (MSRV) to 1.65.0, from 1.63.0.
* :func:`~cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key`
  now enforces a minimum RSA key size of 1024-bit. Note that 1024-bit is still
  considered insecure, users should generally use a key size of 2048-bits.
* :func:`~cryptography.hazmat.primitives.serialization.pkcs7.serialize_certificates`
  now emits ASN.1 that more closely follows the recommendations in :rfc:`2315`.
* Added new :doc:`/hazmat/decrepit/index` module which contains outdated and
  insecure cryptographic primitives.
  ``CAST5``, ``SEED``, ``IDEA``, and ``Blowfish``, which were
  deprecated in 37.0.0, have been added to this module. They will be removed
  from the ``cipher`` module in 45.0.0.
* Moved :class:`~cryptography.hazmat.primitives.ciphers.algorithms.TripleDES`
  and :class:`~cryptography.hazmat.primitives.ciphers.algorithms.ARC4` into
  :doc:`/hazmat/decrepit/index` and deprecated them in the ``cipher`` module.
  They will be removed from the ``cipher`` module in 48.0.0.
* Added support for deterministic
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.ECDSA` (:rfc:`6979`)
* Added support for client certificate verification to the
  :mod:`X.509 path validation <cryptography.x509.verification>` APIs in the
  form of :class:`~cryptography.x509.verification.ClientVerifier`,
  :class:`~cryptography.x509.verification.VerifiedClient`, and
  ``PolicyBuilder``
  :meth:`~cryptography.x509.verification.PolicyBuilder.build_client_verifier`.
* Added Certificate
  :attr:`~cryptography.x509.Certificate.public_key_algorithm_oid`
  and Certificate Signing Request
  :attr:`~cryptography.x509.CertificateSigningRequest.public_key_algorithm_oid`
  to determine the :class:`~cryptography.hazmat._oid.PublicKeyAlgorithmOID`
  Object Identifier of the public key found inside the certificate.
* Added :attr:`~cryptography.x509.InvalidityDate.invalidity_date_utc`, a
  timezone-aware alternative to the naïve ``datetime`` attribute
  :attr:`~cryptography.x509.InvalidityDate.invalidity_date`.
* Added support for parsing empty DN string in
  :meth:`~cryptography.x509.Name.from_rfc4514_string`.
* Added the following properties that return timezone-aware ``datetime`` objects:
  :meth:`~cryptography.x509.ocsp.OCSPResponse.produced_at_utc`,
  :meth:`~cryptography.x509.ocsp.OCSPResponse.revocation_time_utc`,
  :meth:`~cryptography.x509.ocsp.OCSPResponse.this_update_utc`,
  :meth:`~cryptography.x509.ocsp.OCSPResponse.next_update_utc`,
  :meth:`~cryptography.x509.ocsp.OCSPSingleResponse.revocation_time_utc`,
  :meth:`~cryptography.x509.ocsp.OCSPSingleResponse.this_update_utc`,
  :meth:`~cryptography.x509.ocsp.OCSPSingleResponse.next_update_utc`,
  These are timezone-aware variants of existing properties that return naïve
  ``datetime`` objects.
* Added
  :func:`~cryptography.hazmat.primitives.asymmetric.rsa.rsa_recover_private_exponent`
* Added :meth:`~cryptography.hazmat.primitives.ciphers.CipherContext.reset_nonce`
  for altering the ``nonce`` of a cipher context without initializing a new
  instance. See the docs for additional restrictions.
* :class:`~cryptography.x509.NameAttribute` now raises an exception when
  attempting to create a common name whose length is shorter or longer than
  :rfc:`5280` permits.
* Added basic support for PKCS7 encryption (including SMIME) via
  :class:`~cryptography.hazmat.primitives.serialization.pkcs7.PKCS7EnvelopeBuilder`.

.. _v42-0-8:

42.0.8 - 2024-06-04
~~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.2.2.

.. _v42-0-7:

42.0.7 - 2024-05-06
~~~~~~~~~~~~~~~~~~~

* Restored Windows 7 compatibility for our pre-built wheels. Note that we do
  not test on Windows 7 and wheels for our next release will not support it.
  Microsoft no longer provides support for Windows 7 and users are encouraged
  to upgrade.

.. _v42-0-6:

42.0.6 - 2024-05-04
~~~~~~~~~~~~~~~~~~~

* Fixed compilation when using LibreSSL 3.9.1.

.. _v42-0-5:

42.0.5 - 2024-02-23
~~~~~~~~~~~~~~~~~~~

* Limit the number of name constraint checks that will be performed in
  :mod:`X.509 path validation <cryptography.x509.verification>` to protect
  against denial of service attacks.
* Upgrade ``pyo3`` version, which fixes building on PowerPC.

.. _v42-0-4:

42.0.4 - 2024-02-20
~~~~~~~~~~~~~~~~~~~

* Fixed a null-pointer-dereference and segfault that could occur when creating
  a PKCS#12 bundle. Credit to **Alexander-Programming** for reporting the
  issue. **CVE-2024-26130**
* Fixed ASN.1 encoding for PKCS7/SMIME signed messages. The fields ``SMIMECapabilities``
  and ``SignatureAlgorithmIdentifier`` should now be correctly encoded according to the
  definitions in :rfc:`2633` :rfc:`3370`.

.. _v42-0-3:

42.0.3 - 2024-02-15
~~~~~~~~~~~~~~~~~~~

* Fixed an initialization issue that caused key loading failures for some
  users.

.. _v42-0-2:

42.0.2 - 2024-01-30
~~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.2.1.
* Fixed an issue that prevented the use of Python buffer protocol objects in
  ``sign`` and ``verify`` methods on asymmetric keys.
* Fixed an issue with incorrect keyword-argument naming with ``EllipticCurvePrivateKey``
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.exchange`,
  ``X25519PrivateKey``
  :meth:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.exchange`,
  ``X448PrivateKey``
  :meth:`~cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey.exchange`,
  and ``DHPrivateKey``
  :meth:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey.exchange`.

.. _v42-0-1:

42.0.1 - 2024-01-24
~~~~~~~~~~~~~~~~~~~

* Fixed an issue with incorrect keyword-argument naming with ``EllipticCurvePrivateKey``
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.sign`.
* Resolved compatibility issue with loading certain RSA public keys in
  :func:`~cryptography.hazmat.primitives.serialization.load_pem_public_key`.

.. _v42-0-0:

42.0.0 - 2024-01-22
~~~~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** Dropped support for LibreSSL < 3.7.
* **BACKWARDS INCOMPATIBLE:** Loading a PKCS7 with no content field using
  :func:`~cryptography.hazmat.primitives.serialization.pkcs7.load_pem_pkcs7_certificates`
  or
  :func:`~cryptography.hazmat.primitives.serialization.pkcs7.load_der_pkcs7_certificates`
  will now raise a ``ValueError`` rather than return an empty list.
* Parsing SSH certificates no longer permits malformed critical options with
  values, as documented in the 41.0.2 release notes.
* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.2.0.
* Updated the minimum supported Rust version (MSRV) to 1.63.0, from 1.56.0.
* We now publish both ``py37`` and ``py39`` ``abi3`` wheels. This should
  resolve some errors relating to initializing a module multiple times per
  process.
* Support :class:`~cryptography.hazmat.primitives.asymmetric.padding.PSS` for
  X.509 certificate signing requests and certificate revocation lists with the
  keyword-only argument ``rsa_padding`` on the ``sign`` methods for
  :class:`~cryptography.x509.CertificateSigningRequestBuilder` and
  :class:`~cryptography.x509.CertificateRevocationListBuilder`.
* Added support for obtaining X.509 certificate signing request signature
  algorithm parameters (including PSS) via
  :meth:`~cryptography.x509.CertificateSigningRequest.signature_algorithm_parameters`.
* Added support for obtaining X.509 certificate revocation list signature
  algorithm parameters (including PSS) via
  :meth:`~cryptography.x509.CertificateRevocationList.signature_algorithm_parameters`.
* Added ``mgf`` property to
  :class:`~cryptography.hazmat.primitives.asymmetric.padding.PSS`.
* Added ``algorithm`` and ``mgf`` properties to
  :class:`~cryptography.hazmat.primitives.asymmetric.padding.OAEP`.
* Added the following properties that return timezone-aware ``datetime`` objects:
  :meth:`~cryptography.x509.Certificate.not_valid_before_utc`,
  :meth:`~cryptography.x509.Certificate.not_valid_after_utc`,
  :meth:`~cryptography.x509.RevokedCertificate.revocation_date_utc`,
  :meth:`~cryptography.x509.CertificateRevocationList.next_update_utc`,
  :meth:`~cryptography.x509.CertificateRevocationList.last_update_utc`.
  These are timezone-aware variants of existing properties that return naïve
  ``datetime`` objects.
* Deprecated the following properties that return naïve ``datetime`` objects:
  :meth:`~cryptography.x509.Certificate.not_valid_before`,
  :meth:`~cryptography.x509.Certificate.not_valid_after`,
  :meth:`~cryptography.x509.RevokedCertificate.revocation_date`,
  :meth:`~cryptography.x509.CertificateRevocationList.next_update`,
  :meth:`~cryptography.x509.CertificateRevocationList.last_update`
  in favor of the new timezone-aware variants mentioned above.
* Added support for
  :class:`~cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20`
  on LibreSSL.
* Added support for RSA PSS signatures in PKCS7 with
  :meth:`~cryptography.hazmat.primitives.serialization.pkcs7.PKCS7SignatureBuilder.add_signer`.
* In the next release (43.0.0) of cryptography, loading an X.509 certificate
  with a negative serial number will raise an exception. This has been
  deprecated since 36.0.0.
* Added support for
  :class:`~cryptography.hazmat.primitives.ciphers.aead.AESGCMSIV` when using
  OpenSSL 3.2.0+.
* Added the :mod:`X.509 path validation <cryptography.x509.verification>` APIs
  for :class:`~cryptography.x509.Certificate` chains. These APIs should be
  considered unstable and not subject to our stability guarantees until
  documented as such in a future release.
* Added support for
  :class:`~cryptography.hazmat.primitives.ciphers.algorithms.SM4`
  :class:`~cryptography.hazmat.primitives.ciphers.modes.GCM`
  when using OpenSSL 3.0 or greater.

.. _v41-0-7:

41.0.7 - 2023-11-27
~~~~~~~~~~~~~~~~~~~

* Fixed compilation when using LibreSSL 3.8.2.

.. _v41-0-6:

41.0.6 - 2023-11-27
~~~~~~~~~~~~~~~~~~~

* Fixed a null-pointer-dereference and segfault that could occur when loading
  certificates from a PKCS#7 bundle.  Credit to **pkuzco** for reporting the
  issue. **CVE-2023-49083**

.. _v41-0-5:

41.0.5 - 2023-10-24
~~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.1.4.
* Added a function to support an upcoming ``pyOpenSSL`` release.

.. _v41-0-4:

41.0.4 - 2023-09-19
~~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.1.3.

.. _v41-0-3:

41.0.3 - 2023-08-01
~~~~~~~~~~~~~~~~~~~

* Fixed performance regression loading DH public keys.
* Fixed a memory leak when using
  :class:`~cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`.
* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.1.2.

.. _v41-0-2:

41.0.2 - 2023-07-10
~~~~~~~~~~~~~~~~~~~

* Fixed bugs in creating and parsing SSH certificates where critical options
  with values were handled incorrectly. Certificates are now created correctly
  and parsing accepts correct values as well as the previously generated
  invalid forms with a warning. In the next release, support for parsing these
  invalid forms will be removed.

.. _v41-0-1:

41.0.1 - 2023-06-01
~~~~~~~~~~~~~~~~~~~

* Temporarily allow invalid ECDSA signature algorithm parameters in X.509
  certificates, which are generated by older versions of Java.
* Allow null bytes in pass phrases when serializing private keys.

.. _v41-0-0:

41.0.0 - 2023-05-30
~~~~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** Support for OpenSSL less than 1.1.1d has been
  removed.  Users on older version of OpenSSL will need to upgrade.
* **BACKWARDS INCOMPATIBLE:** Support for Python 3.6 has been removed.
* **BACKWARDS INCOMPATIBLE:** Dropped support for LibreSSL < 3.6.
* Updated the minimum supported Rust version (MSRV) to 1.56.0, from 1.48.0.
* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.1.1.
* Added support for the :class:`~cryptography.x509.OCSPAcceptableResponses`
  OCSP extension.
* Added support for the :class:`~cryptography.x509.MSCertificateTemplate`
  proprietary Microsoft certificate extension.
* Implemented support for equality checks on all asymmetric public key types.
* Added support for ``aes256-gcm@openssh.com`` encrypted keys in
  :func:`~cryptography.hazmat.primitives.serialization.load_ssh_private_key`.
* Added support for obtaining X.509 certificate signature algorithm parameters
  (including PSS) via
  :meth:`~cryptography.x509.Certificate.signature_algorithm_parameters`.
* Support signing :class:`~cryptography.hazmat.primitives.asymmetric.padding.PSS`
  X.509 certificates via the new keyword-only argument ``rsa_padding`` on
  :meth:`~cryptography.x509.CertificateBuilder.sign`.
* Added support for
  :class:`~cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`
  on BoringSSL.

.. _v40-0-2:

40.0.2 - 2023-04-14
~~~~~~~~~~~~~~~~~~~

* Fixed compilation when using LibreSSL 3.7.2.
* Added some functions to support an upcoming ``pyOpenSSL`` release.

.. _v40-0-1:

40.0.1 - 2023-03-24
~~~~~~~~~~~~~~~~~~~

* Fixed a bug where certain operations would fail if an object happened to be
  in the top-half of the memory-space. This only impacted 32-bit systems.

.. _v40-0-0:

40.0.0 - 2023-03-24
~~~~~~~~~~~~~~~~~~~


* **BACKWARDS INCOMPATIBLE:** As announced in the 39.0.0 changelog, the way
  ``cryptography`` links OpenSSL has changed. This only impacts users who
  build ``cryptography`` from source (i.e., not from a ``wheel``), and
  specify their own version of OpenSSL. For those users, the ``CFLAGS``,
  ``LDFLAGS``, ``INCLUDE``, ``LIB``, and ``CRYPTOGRAPHY_SUPPRESS_LINK_FLAGS``
  environment variables are no longer valid. Instead, users need to configure
  their builds `as documented here`_.
* Support for Python 3.6 is deprecated and will be removed in the next
  release.
* Deprecated the current minimum supported Rust version (MSRV) of 1.48.0.
  In the next release we will raise MSRV to 1.56.0. Users with the latest
  ``pip`` will typically get a wheel and not need Rust installed, but check
  :doc:`/installation` for documentation on installing a newer ``rustc`` if
  required.
* Deprecated support for OpenSSL less than 1.1.1d. The next release of
  ``cryptography`` will drop support for older versions.
* Deprecated support for DSA keys in
  :func:`~cryptography.hazmat.primitives.serialization.load_ssh_public_key`
  and
  :func:`~cryptography.hazmat.primitives.serialization.load_ssh_private_key`.
* Deprecated support for OpenSSH serialization in
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`
  and
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`.
* The minimum supported version of PyPy3 is now 7.3.10.
* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.1.0.
* Added support for parsing SSH certificates in addition to public keys with
  :func:`~cryptography.hazmat.primitives.serialization.load_ssh_public_identity`.
  :func:`~cryptography.hazmat.primitives.serialization.load_ssh_public_key`
  continues to support only public keys.
* Added support for generating SSH certificates with
  :class:`~cryptography.hazmat.primitives.serialization.SSHCertificateBuilder`.
* Added :meth:`~cryptography.x509.Certificate.verify_directly_issued_by` to
  :class:`~cryptography.x509.Certificate`.
* Added a check to :class:`~cryptography.x509.NameConstraints` to ensure that
  :class:`~cryptography.x509.DNSName` constraints do not contain any ``*``
  wildcards.
* Removed many unused CFFI OpenSSL bindings. This will not impact you unless
  you are using ``cryptography`` to directly invoke OpenSSL's C API. Note that
  these have never been considered a stable, supported, public API by
  ``cryptography``, this note is included as a courtesy.
* The X.509 builder classes now raise ``UnsupportedAlgorithm`` instead of
  ``ValueError`` if an unsupported hash algorithm is passed.
* Added public union type aliases for type hinting:

  * Asymmetric types:
    :const:`~cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes`,
    :const:`~cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes`,
    :const:`~cryptography.hazmat.primitives.asymmetric.types.CertificatePublicKeyTypes`,
    :const:`~cryptography.hazmat.primitives.asymmetric.types.CertificateIssuerPublicKeyTypes`,
    :const:`~cryptography.hazmat.primitives.asymmetric.types.CertificateIssuerPrivateKeyTypes`.
  * SSH keys:
    :const:`~cryptography.hazmat.primitives.serialization.SSHPublicKeyTypes`,
    :const:`~cryptography.hazmat.primitives.serialization.SSHPrivateKeyTypes`,
    :const:`~cryptography.hazmat.primitives.serialization.SSHCertPublicKeyTypes`,
    :const:`~cryptography.hazmat.primitives.serialization.SSHCertPrivateKeyTypes`.
  * PKCS12:
    :const:`~cryptography.hazmat.primitives.serialization.pkcs12.PKCS12PrivateKeyTypes`
  * PKCS7:
    :const:`~cryptography.hazmat.primitives.serialization.pkcs7.PKCS7HashTypes`,
    :const:`~cryptography.hazmat.primitives.serialization.pkcs7.PKCS7PrivateKeyTypes`.
  * Two-factor:
    :const:`~cryptography.hazmat.primitives.twofactor.hotp.HOTPHashTypes`

* Deprecated previously undocumented but not private type aliases in the
  ``cryptography.hazmat.primitives.asymmetric.types`` module in favor of new
  ones above.


.. _v39-0-2:


39.0.2 - 2023-03-02
~~~~~~~~~~~~~~~~~~~

* Fixed a bug where the content type header was not properly encoded for
  PKCS7 signatures when using the ``Text`` option and ``SMIME`` encoding.


.. _v39-0-1:

39.0.1 - 2023-02-07
~~~~~~~~~~~~~~~~~~~

* **SECURITY ISSUE** - Fixed a bug where ``Cipher.update_into`` accepted Python
  buffer protocol objects, but allowed immutable buffers. **CVE-2023-23931**
* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.0.8.

.. _v39-0-0:

39.0.0 - 2023-01-01
~~~~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** Support for OpenSSL 1.1.0 has been removed.
  Users on older version of OpenSSL will need to upgrade.
* **BACKWARDS INCOMPATIBLE:** Dropped support for LibreSSL < 3.5. The new
  minimum LibreSSL version is 3.5.0. Going forward our policy is to support
  versions of LibreSSL that are available in versions of OpenBSD that are
  still receiving security support.
* **BACKWARDS INCOMPATIBLE:** Removed the ``encode_point`` and
  ``from_encoded_point`` methods on
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers`,
  which had been deprecated for several years.
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.public_bytes`
  and
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point`
  should be used instead.
* **BACKWARDS INCOMPATIBLE:** Support for using MD5 or SHA1 in
  :class:`~cryptography.x509.CertificateBuilder`, other X.509 builders, and
  PKCS7 has been removed.
* **BACKWARDS INCOMPATIBLE:** Dropped support for macOS 10.10 and 10.11, macOS
  users must upgrade to 10.12 or newer.
* **ANNOUNCEMENT:** The next version of ``cryptography`` (40.0) will change
  the way we link OpenSSL. This will only impact users who build
  ``cryptography`` from source (i.e., not from a ``wheel``), and specify their
  own version of OpenSSL. For those users, the ``CFLAGS``, ``LDFLAGS``,
  ``INCLUDE``, ``LIB``, and ``CRYPTOGRAPHY_SUPPRESS_LINK_FLAGS`` environment
  variables will no longer be respected. Instead, users will need to
  configure their builds `as documented here`_.
* Added support for
  :ref:`disabling the legacy provider in OpenSSL 3.0.x<legacy-provider>`.
* Added support for disabling RSA key validation checks when loading RSA
  keys via
  :func:`~cryptography.hazmat.primitives.serialization.load_pem_private_key`,
  :func:`~cryptography.hazmat.primitives.serialization.load_der_private_key`,
  and
  :meth:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateNumbers.private_key`.
  This speeds up key loading but is :term:`unsafe` if you are loading potentially
  attacker supplied keys.
* Significantly improved performance for
  :class:`~cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`
  when repeatedly calling ``encrypt`` or ``decrypt`` with the same key.
* Added support for creating OCSP requests with precomputed hashes using
  :meth:`~cryptography.x509.ocsp.OCSPRequestBuilder.add_certificate_by_hash`.
* Added support for loading multiple PEM-encoded X.509 certificates from
  a single input via :func:`~cryptography.x509.load_pem_x509_certificates`.

.. _v38-0-4:

38.0.4 - 2022-11-27
~~~~~~~~~~~~~~~~~~~

* Fixed compilation when using LibreSSL 3.6.0.
* Fixed error when using ``py2app`` to build an application with a
  ``cryptography`` dependency.

.. _v38-0-3:

38.0.3 - 2022-11-01
~~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.0.7,
  which resolves *CVE-2022-3602* and *CVE-2022-3786*.

.. _v38-0-2:

38.0.2 - 2022-10-11 (YANKED)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. attention::

    This release was subsequently yanked from PyPI due to a regression in OpenSSL.

* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.0.6.


.. _v38-0-1:

38.0.1 - 2022-09-07
~~~~~~~~~~~~~~~~~~~

* Fixed parsing TLVs in ASN.1 with length greater than 65535 bytes (typically
  seen in large CRLs).

.. _v38-0-0:

38.0.0 - 2022-09-06
~~~~~~~~~~~~~~~~~~~

* Final deprecation of OpenSSL 1.1.0. The next release of ``cryptography``
  will drop support.
* We no longer ship ``manylinux2010`` wheels. Users should upgrade to the
  latest ``pip`` to ensure this doesn't cause issues downloading wheels on
  their platform. We now ship ``manylinux_2_28`` wheels for users on new
  enough platforms.
* Updated the minimum supported Rust version (MSRV) to 1.48.0, from 1.41.0.
  Users with the latest ``pip`` will typically get a wheel and not need Rust
  installed, but check :doc:`/installation` for documentation on installing a
  newer ``rustc`` if required.
* :meth:`~cryptography.fernet.Fernet.decrypt` and related methods now accept
  both ``str`` and ``bytes`` tokens.
* Parsing ``CertificateSigningRequest`` restores the behavior of enforcing
  that the ``Extension`` ``critical`` field must be correctly encoded DER. See
  `the issue <https://github.com/pyca/cryptography/issues/6368>`_ for complete
  details.
* Added two new OpenSSL functions to the bindings to support an upcoming
  ``pyOpenSSL`` release.
* When parsing :class:`~cryptography.x509.CertificateRevocationList` and
  :class:`~cryptography.x509.CertificateSigningRequest` values, it is now
  enforced that the ``version`` value in the input must be valid according to
  the rules of :rfc:`2986` and :rfc:`5280`.
* Using MD5 or SHA1 in :class:`~cryptography.x509.CertificateBuilder` and
  other X.509 builders is deprecated and support will be removed in the next
  version.
* Added additional APIs to
  :class:`~cryptography.x509.certificate_transparency.SignedCertificateTimestamp`, including
  :attr:`~cryptography.x509.certificate_transparency.SignedCertificateTimestamp.signature_hash_algorithm`,
  :attr:`~cryptography.x509.certificate_transparency.SignedCertificateTimestamp.signature_algorithm`,
  :attr:`~cryptography.x509.certificate_transparency.SignedCertificateTimestamp.signature`, and
  :attr:`~cryptography.x509.certificate_transparency.SignedCertificateTimestamp.extension_bytes`.
* Added :attr:`~cryptography.x509.Certificate.tbs_precertificate_bytes`, allowing
  users to access the to-be-signed pre-certificate data needed for signed
  certificate timestamp verification.
* :class:`~cryptography.hazmat.primitives.kdf.kbkdf.KBKDFHMAC` and
  :class:`~cryptography.hazmat.primitives.kdf.kbkdf.KBKDFCMAC` now support
  :attr:`~cryptography.hazmat.primitives.kdf.kbkdf.CounterLocation.MiddleFixed`
  counter location.
* Fixed :rfc:`4514` name parsing to reverse the order of the RDNs according
  to the section 2.1 of the RFC, affecting method
  :meth:`~cryptography.x509.Name.from_rfc4514_string`.
* It is now possible to customize some aspects of encryption when serializing
  private keys, using
  :meth:`~cryptography.hazmat.primitives.serialization.PrivateFormat.encryption_builder`.
* Removed several legacy symbols from our OpenSSL bindings. Users of pyOpenSSL
  versions older than 22.0 will need to upgrade.
* Added
  :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES128` and
  :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES256` classes.
  These classes do not replace
  :class:`~cryptography.hazmat.primitives.ciphers.algorithms.AES` (which
  allows all AES key lengths), but are intended for applications where
  developers want to be explicit about key length.

.. _v37-0-4:

37.0.4 - 2022-07-05
~~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.0.5.

.. _v37-0-3:

37.0.3 - 2022-06-21 (YANKED)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. attention::

    This release was subsequently yanked from PyPI due to a regression in OpenSSL.

* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.0.4.

.. _v37-0-2:

37.0.2 - 2022-05-03
~~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.0.3.
* Added a constant needed for an upcoming pyOpenSSL release.

.. _v37-0-1:

37.0.1 - 2022-04-27
~~~~~~~~~~~~~~~~~~~

* Fixed an issue where parsing an encrypted private key with the public
  loader functions would hang waiting for console input on OpenSSL 3.0.x rather
  than raising an error.
* Restored some legacy symbols for older ``pyOpenSSL`` users. These will be
  removed again in the future, so ``pyOpenSSL`` users should still upgrade
  to the latest version of that package when they upgrade ``cryptography``.

.. _v37-0-0:

37.0.0 - 2022-04-26
~~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 3.0.2.
* **BACKWARDS INCOMPATIBLE:** Dropped support for LibreSSL 2.9.x and 3.0.x.
  The new minimum LibreSSL version is 3.1+.
* **BACKWARDS INCOMPATIBLE:** Removed ``signer`` and ``verifier`` methods
  from the public key and private key classes. These methods were originally
  deprecated in version 2.0, but had an extended deprecation timeline due
  to usage. Any remaining users should transition to ``sign`` and ``verify``.
* Deprecated OpenSSL 1.1.0 support. OpenSSL 1.1.0 is no longer supported by
  the OpenSSL project. The next release of ``cryptography`` will be the last
  to support compiling with OpenSSL 1.1.0.
* Deprecated Python 3.6 support. Python 3.6 is no longer supported by the
  Python core team. Support for Python 3.6 will be removed in a future
  ``cryptography`` release.
* Deprecated the current minimum supported Rust version (MSRV) of 1.41.0.
  In the next release we will raise MSRV to 1.48.0. Users with the latest
  ``pip`` will typically get a wheel and not need Rust installed, but check
  :doc:`/installation` for documentation on installing a newer ``rustc`` if
  required.
* Deprecated ``CAST5``, ``SEED``, ``IDEA``, and ``Blowfish`` because
  they are legacy algorithms with extremely low usage. These will be removed
  in a future version of ``cryptography``.
* Added limited support for distinguished names containing a bit string.
* We now ship ``universal2`` wheels on macOS, which contain both ``arm64``
  and ``x86_64`` architectures. Users on macOS should upgrade to the latest
  ``pip`` to ensure they can use this wheel, although we will continue to
  ship ``x86_64`` specific wheels for now to ease the transition.
* This will be the final release for which we ship ``manylinux2010`` wheels.
  Going forward the minimum supported ``manylinux`` ABI for our wheels will
  be ``manylinux2014``. The vast majority of users will continue to receive
  ``manylinux`` wheels provided they have an up to date ``pip``. For PyPy
  wheels this release already requires ``manylinux2014`` for compatibility
  with binaries distributed by upstream.
* Added support for multiple
  :class:`~cryptography.x509.ocsp.OCSPSingleResponse` in a
  :class:`~cryptography.x509.ocsp.OCSPResponse`.
* Restored support for signing certificates and other structures in
  :doc:`/x509/index` with SHA3 hash algorithms.
* :class:`~cryptography.hazmat.primitives.ciphers.algorithms.TripleDES` is
  disabled in FIPS mode.
* Added support for serialization of PKCS#12 CA friendly names/aliases in
  :func:`~cryptography.hazmat.primitives.serialization.pkcs12.serialize_key_and_certificates`
* Added support for 12-15 byte (96 to 120 bit) nonces to
  :class:`~cryptography.hazmat.primitives.ciphers.aead.AESOCB3`. This class
  previously supported only 12 byte (96 bit).
* Added support for
  :class:`~cryptography.hazmat.primitives.ciphers.aead.AESSIV` when using
  OpenSSL 3.0.0+.
* Added support for serializing PKCS7 structures from a list of
  certificates with
  :class:`~cryptography.hazmat.primitives.serialization.pkcs7.serialize_certificates`.
* Added support for parsing :rfc:`4514` strings with
  :meth:`~cryptography.x509.Name.from_rfc4514_string`.
* Added :attr:`~cryptography.hazmat.primitives.asymmetric.padding.PSS.AUTO` to
  :class:`~cryptography.hazmat.primitives.asymmetric.padding.PSS`. This can
  be used to verify a signature where the salt length is not already known.
* Added :attr:`~cryptography.hazmat.primitives.asymmetric.padding.PSS.DIGEST_LENGTH`
  to :class:`~cryptography.hazmat.primitives.asymmetric.padding.PSS`. This
  constant will set the salt length to the same length as the ``PSS`` hash
  algorithm.
* Added support for loading RSA-PSS key types with
  :func:`~cryptography.hazmat.primitives.serialization.load_pem_private_key`
  and
  :func:`~cryptography.hazmat.primitives.serialization.load_der_private_key`.
  This functionality is limited to OpenSSL 1.1.1e+ and loads the key as a
  normal RSA private key, discarding the PSS constraint information.

.. _v36-0-2:

36.0.2 - 2022-03-15
~~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 1.1.1n.

.. _v36-0-1:

36.0.1 - 2021-12-14
~~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and Linux wheels to be compiled with OpenSSL 1.1.1m.

.. _v36-0-0:

36.0.0 - 2021-11-21
~~~~~~~~~~~~~~~~~~~

* **FINAL DEPRECATION** Support for ``verifier`` and ``signer`` on our
  asymmetric key classes was deprecated in version 2.0. These functions had an
  extended deprecation due to usage, however the next version of
  ``cryptography`` will drop support. Users should migrate to ``sign`` and
  ``verify``.
* The entire :doc:`/x509/index` layer is now written in Rust. This allows
  alternate asymmetric key implementations that can support cloud key
  management services or hardware security modules provided they implement
  the necessary interface (for example:
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`).
* :ref:`Deprecated the backend argument<faq-missing-backend>` for all
  functions.
* Added support for
  :class:`~cryptography.hazmat.primitives.ciphers.aead.AESOCB3`.
* Added support for iterating over arbitrary request
  :attr:`~cryptography.x509.CertificateSigningRequest.attributes`.
* Deprecated the ``get_attribute_for_oid`` method on
  :class:`~cryptography.x509.CertificateSigningRequest` in favor of
  :meth:`~cryptography.x509.Attributes.get_attribute_for_oid` on the new
  :class:`~cryptography.x509.Attributes` object.
* Fixed handling of PEM files to allow loading when certificate and key are
  in the same file.
* Fixed parsing of :class:`~cryptography.x509.CertificatePolicies` extensions
  containing legacy ``BMPString`` values in their ``explicitText``.
* Allow parsing of negative serial numbers in certificates. Negative serial
  numbers are prohibited by :rfc:`5280` so a deprecation warning will be
  raised whenever they are encountered. A future version of ``cryptography``
  will drop support for parsing them.
* Added support for parsing PKCS12 files with friendly names for all
  certificates with
  :func:`~cryptography.hazmat.primitives.serialization.pkcs12.load_pkcs12`,
  which will return an object of type
  :class:`~cryptography.hazmat.primitives.serialization.pkcs12.PKCS12KeyAndCertificates`.
* :meth:`~cryptography.x509.Name.rfc4514_string` and related methods now have
  an optional ``attr_name_overrides`` parameter to supply custom OID to name
  mappings, which can be used to match vendor-specific extensions.
* **BACKWARDS INCOMPATIBLE:** Reverted the nonstandard formatting of
  email address fields as ``E`` in
  :meth:`~cryptography.x509.Name.rfc4514_string` methods from version 35.0.

  The previous behavior can be restored with:
  ``name.rfc4514_string({NameOID.EMAIL_ADDRESS: "E"})``
* Allow
  :class:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey`
  and
  :class:`~cryptography.hazmat.primitives.asymmetric.x448.X448PublicKey` to
  be used as public keys when parsing certificates or creating them with
  :class:`~cryptography.x509.CertificateBuilder`. These key types must be
  signed with a different signing algorithm as ``X25519`` and ``X448`` do
  not support signing.
* Extension values can now be serialized to a DER byte string by calling
  :func:`~cryptography.x509.ExtensionType.public_bytes`.
* Added experimental support for compiling against BoringSSL. As BoringSSL
  does not commit to a stable API, ``cryptography`` tests against the
  latest commit only. Please note that several features are not available
  when building against BoringSSL.
* Parsing ``CertificateSigningRequest`` from DER and PEM now, for a limited
  time period, allows the ``Extension`` ``critical`` field to be incorrectly
  encoded. See `the issue <https://github.com/pyca/cryptography/issues/6368>`_
  for complete details. This will be reverted in a future ``cryptography``
  release.
* When :class:`~cryptography.x509.OCSPNonce` are parsed and generated their
  value is now correctly wrapped in an ASN.1 ``OCTET STRING``. This conforms
  to :rfc:`6960` but conflicts with the original behavior specified in
  :rfc:`2560`. For a temporary period for backwards compatibility, we will
  also parse values that are encoded as specified in :rfc:`2560` but this
  behavior will be removed in a future release.

.. _v35-0-0:

35.0.0 - 2021-09-29
~~~~~~~~~~~~~~~~~~~

* Changed the :ref:`version scheme <api-stability:versioning>`. This will
  result in us incrementing the major version more frequently, but does not
  change our existing backwards compatibility policy.
* **BACKWARDS INCOMPATIBLE:** The :doc:`/x509/index` PEM parsers now require
  that the PEM string passed have PEM delimiters of the correct type. For
  example, parsing a private key PEM concatenated with a certificate PEM will
  no longer be accepted by the PEM certificate parser.
* **BACKWARDS INCOMPATIBLE:** The X.509 certificate parser no longer allows
  negative serial numbers. :rfc:`5280` has always prohibited these.
* **BACKWARDS INCOMPATIBLE:** Additional forms of invalid ASN.1 found during
  :doc:`/x509/index` parsing will raise an error on initial parse rather than
  when the malformed field is accessed.
* Rust is now required for building ``cryptography``, the
  ``CRYPTOGRAPHY_DONT_BUILD_RUST`` environment variable is no longer
  respected.
* Parsers for :doc:`/x509/index` no longer use OpenSSL and have been
  rewritten in Rust. This should be backwards compatible (modulo the items
  listed above) and improve both security and performance.
* Added support for OpenSSL 3.0.0 as a compilation target.
* Added support for
  :class:`~cryptography.hazmat.primitives.hashes.SM3` and
  :class:`~cryptography.hazmat.primitives.ciphers.algorithms.SM4`,
  when using OpenSSL 1.1.1. These algorithms are provided for compatibility
  in regions where they may be required, and are not generally recommended.
* We now ship ``manylinux_2_24`` and ``musllinux_1_1`` wheels, in addition to
  our ``manylinux2010`` and ``manylinux2014`` wheels. Users on distributions
  like Alpine Linux should ensure they upgrade to the latest ``pip`` to
  correctly receive wheels.
* Added ``rfc4514_attribute_name`` attribute to :attr:`x509.NameAttribute
  <cryptography.x509.NameAttribute.rfc4514_attribute_name>`.
* Added :class:`~cryptography.hazmat.primitives.kdf.kbkdf.KBKDFCMAC`.

.. _v3-4-8:

3.4.8 - 2021-08-24
~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and ``manylinux`` wheels to be compiled with
  OpenSSL 1.1.1l.

.. _v3-4-7:

3.4.7 - 2021-03-25
~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and ``manylinux`` wheels to be compiled with
  OpenSSL 1.1.1k.

.. _v3-4-6:

3.4.6 - 2021-02-16
~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and ``manylinux`` wheels to be compiled with
  OpenSSL 1.1.1j.

.. _v3-4-5:

3.4.5 - 2021-02-13
~~~~~~~~~~~~~~~~~~

* Various improvements to type hints.
* Lower the minimum supported Rust version (MSRV) to >=1.41.0. This change
  improves compatibility with system-provided Rust on several Linux
  distributions.
* ``cryptography`` will be switching to a new versioning scheme with its next
  feature release. More information is available in our
  :doc:`/api-stability` documentation.

.. _v3-4-4:

3.4.4 - 2021-02-09
~~~~~~~~~~~~~~~~~~

* Added a ``py.typed`` file so that ``mypy`` will know to use our type
  annotations.
* Fixed an import cycle that could be triggered by certain import sequences.

.. _v3-4-3:

3.4.3 - 2021-02-08
~~~~~~~~~~~~~~~~~~

* Specify our supported Rust version (>=1.45.0) in our ``setup.py`` so users
  on older versions will get a clear error message.

.. _v3-4-2:

3.4.2 - 2021-02-08
~~~~~~~~~~~~~~~~~~

* Improvements to make the rust transition a bit easier. This includes some
  better error messages and small dependency fixes. If you experience
  installation problems **Be sure to update pip** first, then check the
  :doc:`FAQ </faq>`.

.. _v3-4-1:

3.4.1 - 2021-02-07
~~~~~~~~~~~~~~~~~~

* Fixed a circular import issue.
* Added additional debug output to assist users seeing installation errors
  due to outdated ``pip`` or missing ``rustc``.

.. _v3-4:

3.4 - 2021-02-07
~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** Support for Python 2 has been removed.
* We now ship ``manylinux2014`` wheels and no longer ship ``manylinux1``
  wheels. Users should upgrade to the latest ``pip`` to ensure this doesn't
  cause issues downloading wheels on their platform.
* ``cryptography`` now incorporates Rust code. Users building ``cryptography``
  themselves will need to have the Rust toolchain installed. Users who use an
  officially produced wheel will not need to make any changes. The minimum
  supported Rust version is 1.45.0.
* ``cryptography`` now has :pep:`484` type hints on nearly all of of its public
  APIs. Users can begin using them to type check their code with ``mypy``.

.. _v3-3-2:

3.3.2 - 2021-02-07
~~~~~~~~~~~~~~~~~~

* **SECURITY ISSUE:** Fixed a bug where certain sequences of ``update()`` calls
  when symmetrically encrypting very large payloads (>2GB) could result in an
  integer overflow, leading to buffer overflows. *CVE-2020-36242* **Update:**
  This fix is a workaround for *CVE-2021-23840* in OpenSSL, fixed in OpenSSL
  1.1.1j.

.. _v3-3-1:

3.3.1 - 2020-12-09
~~~~~~~~~~~~~~~~~~

* Re-added a legacy symbol causing problems for older ``pyOpenSSL`` users.

.. _v3-3:

3.3 - 2020-12-08
~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** Support for Python 3.5 has been removed due to
  low usage and maintenance burden.
* **BACKWARDS INCOMPATIBLE:** The
  :class:`~cryptography.hazmat.primitives.ciphers.modes.GCM` and
  :class:`~cryptography.hazmat.primitives.ciphers.aead.AESGCM` now require
  64-bit to 1024-bit (8 byte to 128 byte) initialization vectors. This change
  is to conform with an upcoming OpenSSL release that will no longer support
  sizes outside this window.
* **BACKWARDS INCOMPATIBLE:** When deserializing asymmetric keys we now
  raise ``ValueError`` rather than ``UnsupportedAlgorithm`` when an
  unsupported cipher is used. This change is to conform with an upcoming
  OpenSSL release that will no longer distinguish between error types.
* **BACKWARDS INCOMPATIBLE:** We no longer allow loading of finite field
  Diffie-Hellman parameters of less than 512 bits in length. This change is to
  conform with an upcoming OpenSSL release that no longer supports smaller
  sizes. These keys were already wildly insecure and should not have been used
  in any application outside of testing.
* Updated Windows, macOS, and ``manylinux`` wheels to be compiled with
  OpenSSL 1.1.1i.
* Python 2 support is deprecated in ``cryptography``. This is the last release
  that will support Python 2.
* Added the
  :meth:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.recover_data_from_signature`
  function to
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`
  for recovering the signed data from an RSA signature.

.. _v3-2-1:

3.2.1 - 2020-10-27
~~~~~~~~~~~~~~~~~~

* Disable blinding on RSA public keys to address an error with some versions
  of OpenSSL.

.. _v3-2:

3.2 - 2020-10-25
~~~~~~~~~~~~~~~~

* **SECURITY ISSUE:** Attempted to make RSA PKCS#1v1.5 decryption more constant
  time, to protect against Bleichenbacher vulnerabilities. Due to limitations
  imposed by our API, we cannot completely mitigate this vulnerability and a
  future release will contain a new API which is designed to be resilient to
  these for contexts where it is required. Credit to **Hubert Kario** for
  reporting the issue. *CVE-2020-25659*
* Support for OpenSSL 1.0.2 has been removed. Users on older version of OpenSSL
  will need to upgrade.
* Added basic support for PKCS7 signing (including SMIME) via
  :class:`~cryptography.hazmat.primitives.serialization.pkcs7.PKCS7SignatureBuilder`.

.. _v3-1-1:

3.1.1 - 2020-09-22
~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and ``manylinux`` wheels to be compiled with
  OpenSSL 1.1.1h.

.. _v3-1:

3.1 - 2020-08-26
~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** Removed support for ``idna`` based
  :term:`U-label` parsing in various X.509 classes. This support was originally
  deprecated in version 2.1 and moved to an extra in 2.5.
* Deprecated OpenSSL 1.0.2 support. OpenSSL 1.0.2 is no longer supported by
  the OpenSSL project. The next version of ``cryptography`` will drop support
  for it.
* Deprecated support for Python 3.5. This version sees very little use and will
  be removed in the next release.
* ``backend`` arguments to functions are no longer required and the
  default backend will automatically be selected if no ``backend`` is provided.
* Added initial support for parsing certificates from PKCS7 files with
  :func:`~cryptography.hazmat.primitives.serialization.pkcs7.load_pem_pkcs7_certificates`
  and
  :func:`~cryptography.hazmat.primitives.serialization.pkcs7.load_der_pkcs7_certificates`
  .
* Calling ``update`` or ``update_into`` on
  :class:`~cryptography.hazmat.primitives.ciphers.CipherContext` with ``data``
  longer than 2\ :sup:`31` bytes no longer raises an ``OverflowError``. This
  also resolves the same issue in :doc:`/fernet`.

.. _v3-0:

3.0 - 2020-07-20
~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** Removed support for passing an
  :class:`~cryptography.x509.Extension` instance to
  :meth:`~cryptography.x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier`,
  as per our deprecation policy.
* **BACKWARDS INCOMPATIBLE:** Support for LibreSSL 2.7.x, 2.8.x, and 2.9.0 has
  been removed (2.9.1+ is still supported).
* **BACKWARDS INCOMPATIBLE:** Dropped support for macOS 10.9, macOS users must
  upgrade to 10.10 or newer.
* **BACKWARDS INCOMPATIBLE:** RSA
  :meth:`~cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key`
  no longer accepts ``public_exponent`` values except 65537 and 3 (the latter
  for legacy purposes).
* **BACKWARDS INCOMPATIBLE:** X.509 certificate parsing now enforces that the
  ``version`` field contains a valid value, rather than deferring this check
  until :attr:`~cryptography.x509.Certificate.version` is accessed.
* Deprecated support for Python 2. At the time there is no time table for
  actually dropping support, however we strongly encourage all users to upgrade
  their Python, as Python 2 no longer receives support from the Python core
  team.

  If you have trouble suppressing this warning in tests view the :ref:`FAQ
  entry addressing this issue <faq-howto-handle-deprecation-warning>`.

* Added support for ``OpenSSH`` serialization format for
  ``ec``, ``ed25519``, ``rsa`` and ``dsa`` private keys:
  :func:`~cryptography.hazmat.primitives.serialization.load_ssh_private_key`
  for loading and
  :attr:`~cryptography.hazmat.primitives.serialization.PrivateFormat.OpenSSH`
  for writing.
* Added support for ``OpenSSH`` certificates to
  :func:`~cryptography.hazmat.primitives.serialization.load_ssh_public_key`.
* Added :meth:`~cryptography.fernet.Fernet.encrypt_at_time` and
  :meth:`~cryptography.fernet.Fernet.decrypt_at_time` to
  :class:`~cryptography.fernet.Fernet`.
* Added support for the :class:`~cryptography.x509.SubjectInformationAccess`
  X.509 extension.
* Added support for parsing
  :class:`~cryptography.x509.SignedCertificateTimestamps` in OCSP responses.
* Added support for parsing attributes in certificate signing requests via
  ``CertificateSigningRequest.get_attribute_for_oid``.
* Added support for encoding attributes in certificate signing requests via
  :meth:`~cryptography.x509.CertificateSigningRequestBuilder.add_attribute`.
* On OpenSSL 1.1.1d and higher ``cryptography`` now uses OpenSSL's
  built-in CSPRNG instead of its own OS random engine because these versions of
  OpenSSL properly reseed on fork.
* Added initial support for creating PKCS12 files with
  :func:`~cryptography.hazmat.primitives.serialization.pkcs12.serialize_key_and_certificates`.

.. _v2-9-2:

2.9.2 - 2020-04-22
~~~~~~~~~~~~~~~~~~

* Updated the macOS wheel to fix an issue where it would not run on macOS
  versions older than 10.15.

.. _v2-9-1:

2.9.1 - 2020-04-21
~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and ``manylinux`` wheels to be compiled with
  OpenSSL 1.1.1g.

.. _v2-9:

2.9 - 2020-04-02
~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** Support for Python 3.4 has been removed due to
  low usage and maintenance burden.
* **BACKWARDS INCOMPATIBLE:** Support for OpenSSL 1.0.1 has been removed.
  Users on older version of OpenSSL will need to upgrade.
* **BACKWARDS INCOMPATIBLE:** Support for LibreSSL 2.6.x has been removed.
* Removed support for calling
  :meth:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey.public_bytes`
  with no arguments, as per our deprecation policy. You must now pass
  ``encoding`` and ``format``.
* **BACKWARDS INCOMPATIBLE:** Reversed the order in which
  :meth:`~cryptography.x509.Name.rfc4514_string` returns the RDNs
  as required by :rfc:`4514`.
* Updated Windows, macOS, and ``manylinux`` wheels to be compiled with
  OpenSSL 1.1.1f.
* Added support for parsing
  :attr:`~cryptography.x509.ocsp.OCSPResponse.single_extensions` in an OCSP
  response.
* :class:`~cryptography.x509.NameAttribute` values can now be empty strings.

.. _v2-8:

2.8 - 2019-10-16
~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and ``manylinux`` wheels to be compiled with
  OpenSSL 1.1.1d.
* Added support for Python 3.8.
* Added class methods
  :meth:`Poly1305.generate_tag
  <cryptography.hazmat.primitives.poly1305.Poly1305.generate_tag>`
  and
  :meth:`Poly1305.verify_tag
  <cryptography.hazmat.primitives.poly1305.Poly1305.verify_tag>`
  for Poly1305 sign and verify operations.
* Deprecated support for OpenSSL 1.0.1. Support will be removed in
  ``cryptography`` 2.9.
* We now ship ``manylinux2010`` wheels in addition to our ``manylinux1``
  wheels.
* Added support for ``ed25519`` and ``ed448`` keys in the
  :class:`~cryptography.x509.CertificateBuilder`,
  :class:`~cryptography.x509.CertificateSigningRequestBuilder`,
  :class:`~cryptography.x509.CertificateRevocationListBuilder` and
  :class:`~cryptography.x509.ocsp.OCSPResponseBuilder`.
* ``cryptography`` no longer depends on ``asn1crypto``.
* :class:`~cryptography.x509.FreshestCRL` is now allowed as a
  :class:`~cryptography.x509.CertificateRevocationList` extension.

.. _v2-7:

2.7 - 2019-05-30
~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** We no longer distribute 32-bit ``manylinux1``
  wheels. Continuing to produce them was a maintenance burden.
* **BACKWARDS INCOMPATIBLE:** Removed the
  ``cryptography.hazmat.primitives.mac.MACContext`` interface. The ``CMAC`` and
  ``HMAC`` APIs have not changed, but they are no longer registered as
  ``MACContext`` instances.
* Updated Windows, macOS, and ``manylinux1`` wheels to be compiled with
  OpenSSL 1.1.1c.
* Removed support for running our tests with ``setup.py test``. Users
  interested in running our tests can continue to follow the directions in our
  :doc:`development documentation</development/getting-started>`.
* Add support for :class:`~cryptography.hazmat.primitives.poly1305.Poly1305`
  when using OpenSSL 1.1.1 or newer.
* Support serialization with ``Encoding.OpenSSH`` and ``PublicFormat.OpenSSH``
  in
  :meth:`Ed25519PublicKey.public_bytes
  <cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey.public_bytes>`
  .
* Correctly allow passing a ``SubjectKeyIdentifier`` to
  :meth:`~cryptography.x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier`
  and deprecate passing an ``Extension`` object. The documentation always
  required ``SubjectKeyIdentifier`` but the implementation previously
  required an ``Extension``.

.. _v2-6-1:

2.6.1 - 2019-02-27
~~~~~~~~~~~~~~~~~~

* Resolved an error in our build infrastructure that broke our Python3 wheels
  for macOS and Linux.

.. _v2-6:

2.6 - 2019-02-27
~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** Removed
  ``cryptography.hazmat.primitives.asymmetric.utils.encode_rfc6979_signature``
  and
  ``cryptography.hazmat.primitives.asymmetric.utils.decode_rfc6979_signature``,
  which had been deprecated for nearly 4 years. Use
  :func:`~cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature`
  and
  :func:`~cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature`
  instead.
* **BACKWARDS INCOMPATIBLE**: Removed ``cryptography.x509.Certificate.serial``,
  which had been deprecated for nearly 3 years. Use
  :attr:`~cryptography.x509.Certificate.serial_number` instead.
* Updated Windows, macOS, and ``manylinux1`` wheels to be compiled with
  OpenSSL 1.1.1b.
* Added support for :doc:`/hazmat/primitives/asymmetric/ed448` when using
  OpenSSL 1.1.1b or newer.
* Added support for :doc:`/hazmat/primitives/asymmetric/ed25519` when using
  OpenSSL 1.1.1b or newer.
* :func:`~cryptography.hazmat.primitives.serialization.load_ssh_public_key` can
  now load ``ed25519`` public keys.
* Add support for easily mapping an object identifier to its elliptic curve
  class via
  :func:`~cryptography.hazmat.primitives.asymmetric.ec.get_curve_for_oid`.
* Add support for OpenSSL when compiled with the ``no-engine``
  (``OPENSSL_NO_ENGINE``) flag.

.. _v2-5:

2.5 - 2019-01-22
~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** :term:`U-label` strings were deprecated in
  version 2.1, but this version removes the default ``idna`` dependency as
  well. If you still need this deprecated path please install cryptography
  with the ``idna`` extra: ``pip install cryptography[idna]``.
* **BACKWARDS INCOMPATIBLE:** The minimum supported PyPy version is now 5.4.
* Numerous classes and functions have been updated to allow :term:`bytes-like`
  types for keying material and passwords, including symmetric algorithms, AEAD
  ciphers, KDFs, loading asymmetric keys, and one time password classes.
* Updated Windows, macOS, and ``manylinux1`` wheels to be compiled with
  OpenSSL 1.1.1a.
* Added support for :class:`~cryptography.hazmat.primitives.hashes.SHA512_224`
  and :class:`~cryptography.hazmat.primitives.hashes.SHA512_256` when using
  OpenSSL 1.1.1.
* Added support for :class:`~cryptography.hazmat.primitives.hashes.SHA3_224`,
  :class:`~cryptography.hazmat.primitives.hashes.SHA3_256`,
  :class:`~cryptography.hazmat.primitives.hashes.SHA3_384`, and
  :class:`~cryptography.hazmat.primitives.hashes.SHA3_512` when using OpenSSL
  1.1.1.
* Added support for :doc:`/hazmat/primitives/asymmetric/x448` when using
  OpenSSL 1.1.1.
* Added support for :class:`~cryptography.hazmat.primitives.hashes.SHAKE128`
  and :class:`~cryptography.hazmat.primitives.hashes.SHAKE256` when using
  OpenSSL 1.1.1.
* Added initial support for parsing PKCS12 files with
  :func:`~cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates`.
* Added support for :class:`~cryptography.x509.IssuingDistributionPoint`.
* Added ``rfc4514_string()`` method to
  :meth:`x509.Name <cryptography.x509.Name.rfc4514_string>`,
  :meth:`x509.RelativeDistinguishedName
  <cryptography.x509.RelativeDistinguishedName.rfc4514_string>`, and
  :meth:`x509.NameAttribute <cryptography.x509.NameAttribute.rfc4514_string>`
  to format the name or component an :rfc:`4514` Distinguished Name string.
* Added
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point`,
  which immediately checks if the point is on the curve and supports compressed
  points. Deprecated the previous method
  ``cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers.from_encoded_point``.
* Added :attr:`~cryptography.x509.ocsp.OCSPResponse.signature_hash_algorithm`
  to ``OCSPResponse``.
* Updated :doc:`/hazmat/primitives/asymmetric/x25519` support to allow
  additional serialization methods. Calling
  :meth:`~cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey.public_bytes`
  with no arguments has been deprecated.
* Added support for encoding compressed and uncompressed points via
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.public_bytes`. Deprecated the previous method
  ``cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers.encode_point``.


.. _v2-4-2:

2.4.2 - 2018-11-21
~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and ``manylinux1`` wheels to be compiled with
  OpenSSL 1.1.0j.

.. _v2-4-1:

2.4.1 - 2018-11-11
~~~~~~~~~~~~~~~~~~

* Fixed a build breakage in our ``manylinux1`` wheels.

.. _v2-4:

2.4 - 2018-11-11
~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** Dropped support for LibreSSL 2.4.x.
* Deprecated OpenSSL 1.0.1 support. OpenSSL 1.0.1 is no longer supported by
  the OpenSSL project. At this time there is no time table for dropping
  support, however we strongly encourage all users to upgrade or install
  ``cryptography`` from a wheel.
* Added initial :doc:`OCSP </x509/ocsp>` support.
* Added support for :class:`~cryptography.x509.PrecertPoison`.

.. _v2-3-1:

2.3.1 - 2018-08-14
~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and ``manylinux1`` wheels to be compiled with
  OpenSSL 1.1.0i.

.. _v2-3:

2.3 - 2018-07-18
~~~~~~~~~~~~~~~~

* **SECURITY ISSUE:**
  :meth:`~cryptography.hazmat.primitives.ciphers.AEADDecryptionContext.finalize_with_tag`
  allowed tag truncation by default which can allow tag forgery in some cases.
  The method now enforces the ``min_tag_length`` provided to the
  :class:`~cryptography.hazmat.primitives.ciphers.modes.GCM` constructor.
  *CVE-2018-10903*
* Added support for Python 3.7.
* Added :meth:`~cryptography.fernet.Fernet.extract_timestamp` to get the
  authenticated timestamp of a :doc:`Fernet </fernet>` token.
* Support for Python 2.7.x without ``hmac.compare_digest`` has been deprecated.
  We will require Python 2.7.7 or higher (or 2.7.6 on Ubuntu) in the next
  ``cryptography`` release.
* Fixed multiple issues preventing ``cryptography`` from compiling against
  LibreSSL 2.7.x.
* Added
  :class:`~cryptography.x509.CertificateRevocationList.get_revoked_certificate_by_serial_number`
  for quick serial number searches in CRLs.
* The :class:`~cryptography.x509.RelativeDistinguishedName` class now
  preserves the order of attributes. Duplicate attributes now raise an error
  instead of silently discarding duplicates.
* :func:`~cryptography.hazmat.primitives.keywrap.aes_key_unwrap` and
  :func:`~cryptography.hazmat.primitives.keywrap.aes_key_unwrap_with_padding`
  now raise :class:`~cryptography.hazmat.primitives.keywrap.InvalidUnwrap` if
  the wrapped key is an invalid length, instead of ``ValueError``.

.. _v2-2-2:

2.2.2 - 2018-03-27
~~~~~~~~~~~~~~~~~~

* Updated Windows, macOS, and ``manylinux1`` wheels to be compiled with
  OpenSSL 1.1.0h.

.. _v2-2-1:

2.2.1 - 2018-03-20
~~~~~~~~~~~~~~~~~~

* Reverted a change to ``GeneralNames`` which prohibited having zero elements,
  due to breakages.
* Fixed a bug in
  :func:`~cryptography.hazmat.primitives.keywrap.aes_key_unwrap_with_padding`
  that caused it to raise ``InvalidUnwrap`` when key length modulo 8 was
  zero.


.. _v2-2:

2.2 - 2018-03-19
~~~~~~~~~~~~~~~~

* **BACKWARDS INCOMPATIBLE:** Support for Python 2.6 has been dropped.
* Resolved a bug in ``HKDF`` that incorrectly constrained output size.
* Added :class:`~cryptography.hazmat.primitives.asymmetric.ec.BrainpoolP256R1`,
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.BrainpoolP384R1`, and
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.BrainpoolP512R1` to
  support inter-operating with systems like German smart meters.
* Added token rotation support to :doc:`Fernet </fernet>` with
  :meth:`~cryptography.fernet.MultiFernet.rotate`.
* Fixed a memory leak in
  :func:`~cryptography.hazmat.primitives.asymmetric.ec.derive_private_key`.
* Added support for AES key wrapping with padding via
  :func:`~cryptography.hazmat.primitives.keywrap.aes_key_wrap_with_padding`
  and
  :func:`~cryptography.hazmat.primitives.keywrap.aes_key_unwrap_with_padding`
  .
* Allow loading DSA keys with 224 bit ``q``.

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
* **BACKWARDS INCOMPATIBLE:**
  :attr:`DNSName.value <cryptography.x509.DNSName.value>`,
  :attr:`RFC822Name.value <cryptography.x509.RFC822Name.value>`, and
  :attr:`UniformResourceIdentifier.value
  <cryptography.x509.UniformResourceIdentifier.value>`
  will now return an :term:`A-label` string when parsing a certificate
  containing an internationalized domain name (IDN) or if the caller passed
  a :term:`U-label` to the constructor. See below for additional deprecations
  related to this change.
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
  :meth:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey.private_bytes`
  to
  :class:`~cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey`.
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
  ``cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers.encode_point``
  and
  ``cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers.from_encoded_point``.
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
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`,
  and
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`.
* Support :attr:`~cryptography.hazmat.primitives.serialization.Encoding.DER`
  serialization of private keys using the ``private_bytes`` method of
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`,
  and
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`.
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
* Added ``EllipticCurvePrivateKeyWithSerialization`` and deprecated
  ``EllipticCurvePrivateKeyWithNumbers``.
* Added
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.private_bytes`
  to
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`.
* Added ``RSAPrivateKeyWithSerialization`` and deprecated ``RSAPrivateKeyWithNumbers``.
* Added
  :meth:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.private_bytes`
  to
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`.
* Added ``DSAPrivateKeyWithSerialization`` and deprecated ``DSAPrivateKeyWithNumbers``.
* Added
  :meth:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey.private_bytes`
  to
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`.
* Added ``RSAPublicKeyWithSerialization`` and deprecated ``RSAPublicKeyWithNumbers``.
* Added ``public_bytes`` to
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`.
* Added ``EllipticCurvePublicKeyWithSerialization`` and deprecated
  ``EllipticCurvePublicKeyWithNumbers``.
* Added ``public_bytes`` to
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`.
* Added ``DSAPublicKeyWithSerialization`` and deprecated ``DSAPublicKeyWithNumbers``.
* Added ``public_bytes`` to
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`.
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
  ``DSAParametersWithNumbers``,
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
* Added ``MACContext`` as a common interface for CMAC and HMAC and
  deprecated ``CMACContext``.
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
  ``load_elliptic_curve_public_numbers`` on ``EllipticCurveBackend``.
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
  ``commoncrypto`` and ``openssl``.
* Added ``AES`` :class:`~cryptography.hazmat.primitives.ciphers.modes.CTR`
  support to the OpenSSL backend when linked against 0.9.8.
* Added ``PKCS8SerializationBackend`` and
  ``TraditionalOpenSSLSerializationBackend`` support to ``openssl``.
* Added :doc:`/hazmat/primitives/asymmetric/ec` and ``EllipticCurveBackend``.
* Added :class:`~cryptography.hazmat.primitives.ciphers.modes.ECB` support
  for :class:`~cryptography.hazmat.primitives.ciphers.algorithms.TripleDES` on
  ``commoncrypto`` and ``openssl``.
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
  ``create_rsa_verification_ctx`` on ``RSABackend``.
* Deprecated ``create_dsa_signature_ctx`` and ``create_dsa_verification_ctx``
  on ``DSABackend``.


.. _v0-4:

0.4 - 2014-05-03
~~~~~~~~~~~~~~~~

* Deprecated ``salt_length`` on
  :class:`~cryptography.hazmat.primitives.asymmetric.padding.MGF1` and added it
  to :class:`~cryptography.hazmat.primitives.asymmetric.padding.PSS`. It will
  be removed from ``MGF1`` in two releases per our :doc:`/api-stability`
  policy.
* Added ``SEED`` support.
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
* Added ``IDEA`` support.
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
* Removed ``register_cipher_adapter`` method from ``CipherBackend``.
* Added support for the OpenSSL backend under Windows.
* Improved thread-safety for the OpenSSL backend.
* Fixed compilation on systems where OpenSSL's ``ec.h`` header is not
  available, such as CentOS.
* Added :class:`~cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC`.
* Added :class:`~cryptography.hazmat.primitives.kdf.hkdf.HKDF`.
* Added ``multibackend``.
* Set default random for ``openssl`` to the OS random engine.
* Added ``CAST5`` (CAST-128) support.


.. _v0-1:

0.1 - 2014-01-08
~~~~~~~~~~~~~~~~

* Initial release.

.. _`as documented here`: https://docs.rs/openssl/latest/openssl/#automatic
.. _`main`: https://github.com/pyca/cryptography/
.. _`cffi`: https://cffi.readthedocs.io/
.. _`aws-lc`: https://github.com/aws/aws-lc
