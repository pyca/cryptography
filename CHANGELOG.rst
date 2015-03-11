Changelog
=========

0.9 - `master`_
~~~~~~~~~~~~~~~

.. note:: This version is not yet released and is under active development.

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
* Add support for parsing X.509 requests with
  :func:`~cryptography.x509.load_pem_x509_csr`.

0.8.1 - 2015-03-20
~~~~~~~~~~~~~~~~~~

* Updated Windows wheels to be compiled against OpenSSL 1.0.2a.

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
  from :mod:`~cryptography.hazmat.primitives.interfaces` to
  :mod:`~cryptography.hazmat.primitives.kdf`.
* Added support for parsing X.509 names. See the
  :doc:`X.509 documentation</x509>` for more information.
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
  and deprecated
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithNumbers`.
* Added
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization.private_bytes`
  to
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithSerialization`.
* Added
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization`
  and deprecated
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithNumbers`.
* Added
  :meth:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization.private_bytes`
  to
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization`.
* Added
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization`
  and deprecated
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithNumbers`.
* Added
  :meth:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization.private_bytes`
  to
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithSerialization`.
* Added
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithSerialization`
  and deprecated
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithNumbers`.
* Added
  :meth:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithSerialization.public_bytes`
  to
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithSerialization`.
* Added
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKeyWithSerialization`
  and deprecated
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKeyWithNumbers`.
* Added
  :meth:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKeyWithSerialization.public_bytes`
  to
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKeyWithSerialization`.
* Added
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKeyWithSerialization`
  and deprecated
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKeyWithNumbers`.
* Added
  :meth:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKeyWithSerialization.public_bytes`
  to
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKeyWithSerialization`.
* :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` and
  :class:`~cryptography.hazmat.primitives.hashes.HashContext` were moved from
  :mod:`~cryptography.hazmat.primitives.interfaces` to
  :mod:`~cryptography.hazmat.primitives.hashes`.
* :class:`~cryptography.hazmat.primitives.ciphers.CipherContext`,
  :class:`~cryptography.hazmat.primitives.ciphers.AEADCipherContext`,
  :class:`~cryptography.hazmat.primitives.ciphers.AEADEncryptionContext`,
  :class:`~cryptography.hazmat.primitives.ciphers.CipherAlgorithm`, and
  :class:`~cryptography.hazmat.primitives.ciphers.BlockCipherAlgorithm`
  were moved from :mod:`~cryptography.hazmat.primitives.interfaces` to
  :mod:`~cryptography.hazmat.primitives.ciphers`.
* :class:`~cryptography.hazmat.primitives.ciphers.modes.Mode`,
  :class:`~cryptography.hazmat.primitives.ciphers.modes.ModeWithInitializationVector`,
  :class:`~cryptography.hazmat.primitives.ciphers.modes.ModeWithNonce`, and
  :class:`~cryptography.hazmat.primitives.ciphers.modes.ModeWithAuthenticationTag`
  were moved from :mod:`~cryptography.hazmat.primitives.interfaces` to
  :mod:`~cryptography.hazmat.primitives.ciphers.modes`.
* :class:`~cryptography.hazmat.primitives.padding.PaddingContext` was moved
  from :mod:`~cryptography.hazmat.primitives.interfaces` to
  :mod:`~cryptography.hazmat.primitives.padding`.
*
  :class:`~cryptography.hazmat.primitives.asymmetric.padding.AsymmetricPadding`
  was moved from :mod:`~cryptography.hazmat.primitives.interfaces` to
  :mod:`~cryptography.hazmat.primitives.asymmetric.padding`.
*
  :class:`~cryptography.hazmat.primitives.asymmetric.AsymmetricSignatureContext`
  and
  :class:`~cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext`
  were moved from :mod:`~cryptography.hazmat.primitives.interfaces` to
  :mod:`~cryptography.hazmat.primitives.asymmetric`.
* :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters`,
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParametersWithNumbers`,
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKeyWithNumbers`,
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey` and
  :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKeyWithNumbers`
  were moved from :mod:`~cryptography.hazmat.primitives.interfaces` to
  :mod:`~cryptography.hazmat.primitives.asymmetric.dsa`
* :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve`,
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurveSignatureAlgorithm`,
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKeyWithNumbers`,
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`,
  and
  :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKeyWithNumbers`
  were moved from :mod:`~cryptography.hazmat.primitives.interfaces` to
  :mod:`~cryptography.hazmat.primitives.asymmetric.ec`.
* :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`,
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithNumbers`,
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey` and
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKeyWithNumbers`
  were moved from :mod:`~cryptography.hazmat.primitives.interfaces` to
  :mod:`~cryptography.hazmat.primitives.asymmetric.rsa`.

0.7.2 - 2015-01-16
~~~~~~~~~~~~~~~~~~

* Updated Windows wheels to be compiled against OpenSSL 1.0.1l.
* ``enum34`` is no longer installed on Python 3.4, where it is included in
  the standard library.
* Added a new function to the OpenSSL bindings to support additional
  functionality in pyOpenSSL.

0.7.1 - 2014-12-28
~~~~~~~~~~~~~~~~~~

* Fixed an issue preventing compilation on platforms where ``OPENSSL_NO_SSL3``
  was defined.

0.7 - 2014-12-17
~~~~~~~~~~~~~~~~

* Cryptography has been relicensed from the Apache Software License, Version
  2.0, to being available under *either* the Apache Software License, Version
  2.0, or the BSD license.
* Added key-rotation support to :doc:`Fernet </fernet>` with
  :class:`~cryptography.fernet.MultiFernet`.
* More bit-lengths are now supported for ``p`` and ``q`` when loading DSA keys
  from numbers.
* Added :class:`~cryptography.hazmat.primitives.interfaces.MACContext` as a
  common interface for CMAC and HMAC and deprecated ``CMACContext``.
* Added support for encoding and decoding :rfc:`6979` signatures in
  :doc:`/hazmat/primitives/asymmetric/utils`.
* Added
  :func:`~cryptography.hazmat.primitives.serialization.load_ssh_public_key` to
  support the loading of OpenSSH public keys (:rfc:`4253`). Only RSA and DSA
  keys are currently supported.
* Added initial support for X.509 certificate parsing. See the
  :doc:`X.509 documentation</x509>` for more information.

0.6.1 - 2014-10-15
~~~~~~~~~~~~~~~~~~

* Updated Windows wheels to be compiled against OpenSSL 1.0.1j.
* Fixed an issue where OpenSSL 1.0.1j changed the errors returned by some
  functions.
* Added our license file to the ``cryptography-vectors`` package.
* Implemented DSA hash truncation support (per FIPS 186-3) in the OpenSSL
  backend. This works around an issue in 1.0.0, 1.0.0a, and 1.0.0b where
  truncation was not implemented.

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

0.5.4 - 2014-08-20
~~~~~~~~~~~~~~~~~~

* Added several functions to the OpenSSL bindings to support new
  functionality in pyOpenSSL.
* Fixed a redefined constant causing compilation failure with Solaris 11.2.

0.5.3 - 2014-08-06
~~~~~~~~~~~~~~~~~~

* Updated Windows wheels to be compiled against OpenSSL 1.0.1i.

0.5.2 - 2014-07-09
~~~~~~~~~~~~~~~~~~

* Add ``TraditionalOpenSSLSerializationBackend`` support to
  :doc:`/hazmat/backends/multibackend`.
* Fix compilation error on OS X 10.8 (Mountain Lion).

0.5.1 - 2014-07-07
~~~~~~~~~~~~~~~~~~

* Add ``PKCS8SerializationBackend`` support to
  :doc:`/hazmat/backends/multibackend`.

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
  :doc:`/hazmat/backends/commoncrypto` and :doc:`/hazmat/backends/openssl`.
* Added ``AES`` :class:`~cryptography.hazmat.primitives.ciphers.modes.CTR`
  support to the OpenSSL backend when linked against 0.9.8.
* Added ``PKCS8SerializationBackend`` and
  ``TraditionalOpenSSLSerializationBackend`` support to the
  :doc:`/hazmat/backends/openssl`.
* Added :doc:`/hazmat/primitives/asymmetric/ec` and
  :class:`~cryptography.hazmat.backends.interfaces.EllipticCurveBackend`.
* Added :class:`~cryptography.hazmat.primitives.ciphers.modes.ECB` support
  for :class:`~cryptography.hazmat.primitives.ciphers.algorithms.TripleDES` on
  :doc:`/hazmat/backends/commoncrypto` and :doc:`/hazmat/backends/openssl`.
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

0.2.2 - 2014-03-03
~~~~~~~~~~~~~~~~~~

* Removed a constant definition that was causing compilation problems with
  specific versions of OpenSSL.

0.2.1 - 2014-02-22
~~~~~~~~~~~~~~~~~~

* Fix a bug where importing cryptography from multiple paths could cause
  initialization to fail.

0.2 - 2014-02-20
~~~~~~~~~~~~~~~~

* Added :doc:`/hazmat/backends/commoncrypto`.
* Added initial :doc:`/hazmat/bindings/commoncrypto`.
* Removed ``register_cipher_adapter`` method from
  :class:`~cryptography.hazmat.backends.interfaces.CipherBackend`.
* Added support for the OpenSSL backend under Windows.
* Improved thread-safety for the OpenSSL backend.
* Fixed compilation on systems where OpenSSL's ``ec.h`` header is not
  available, such as CentOS.
* Added :class:`~cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC`.
* Added :class:`~cryptography.hazmat.primitives.kdf.hkdf.HKDF`.
* Added :doc:`/hazmat/backends/multibackend`.
* Set default random for the :doc:`/hazmat/backends/openssl` to the OS
  random engine.
* Added :class:`~cryptography.hazmat.primitives.ciphers.algorithms.CAST5`
  (CAST-128) support.

0.1 - 2014-01-08
~~~~~~~~~~~~~~~~

* Initial release.

.. _`master`: https://github.com/pyca/cryptography/
