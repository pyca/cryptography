Changelog
=========

0.5 - `master`_
~~~~~~~~~~~~~~~

.. note:: This version is not yet released and is under active development.

* **BACKWARDS INCOMPATIBLE:**
  :class:`~cryptography.hazmat.primitives.ciphers.modes.GCM` no longer allows
  truncation of tags by default. Previous versions of ``cryptography`` allowed
  tags to be truncated by default, applications wishing to preserve this
  behavior (not recommended) can pass the ``min_tag_length`` argument.
* Windows builds are now linked statically by default. When installing a
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
* Added
  :class:`~cryptography.hazmat.backends.interfaces.PKCS8SerializationBackend`
  and
  :class:`~cryptography.hazmat.backends.interfaces.TraditionalOpenSSLSerializationBackend`
  support to the :doc:`/hazmat/backends/openssl`.
* Added :doc:`/hazmat/primitives/asymmetric/ec` and
  :class:`~cryptography.hazmat.backends.interfaces.EllipticCurveBackend`.
* Added :class:`~cryptography.hazmat.primitives.ciphers.modes.ECB` support
  for :class:`~cryptography.hazmat.primitives.ciphers.algorithms.TripleDES` on
  :doc:`/hazmat/backends/commoncrypto` and :doc:`/hazmat/backends/openssl`.
* Deprecated :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
  in favor of backend specific providers of the
  :class:`~cryptography.hazmat.primitives.interfaces.RSAPrivateKey` interface.
* Deprecated :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`
  in favor of backend specific providers of the
  :class:`~cryptography.hazmat.primitives.interfaces.RSAPublicKey` interface.
* Deprecated :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey`
  in favor of backend specific providers of the
  :class:`~cryptography.hazmat.primitives.interfaces.DSAPrivateKey` interface.
* Deprecated :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey`
  in favor of backend specific providers of the
  :class:`~cryptography.hazmat.primitives.interfaces.DSAPublicKey` interface.
* Deprecated :class:`~cryptography.hazmat.primitives.asymmetric.dsa.DSAParameters`
  in favor of backend specific providers of the
  :class:`~cryptography.hazmat.primitives.interfaces.DSAParameters` interface.
* Deprecated ``encrypt_rsa``, ``decrypt_rsa``, ``create_rsa_signature_ctx`` and
  ``create_rsa_verification_ctx`` on
  :class:`~cryptography.hazmat.backends.interfaces.RSABackend`.
* Deprecated ``create_dsa_signature_ctx`` and ``create_dsa_verification_ctx``
  on :class:`~cryptography.hazmat.backends.interfaces.DSABackend`.

0.4 - 2014-05-03
~~~~~~~~~~~~~~~~

* Deprecated ``salt_length`` on
  :class:`~cryptography.hazmat.primitives.asymmetric.padding.MGF1` and added it
  to :class:`~cryptography.hazmat.primitives.asymmetric.padding.PSS`. It will be
  removed from ``MGF1`` in two releases per our :doc:`/api-stability` policy.
* Added :class:`~cryptography.hazmat.primitives.ciphers.algorithms.SEED` support.
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
* Added :class:`~cryptography.hazmat.primitives.ciphers.algorithms.IDEA` support.
* Added signature support to
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
  and verification support to
  :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`.
* Moved test vectors to the new ``cryptography_vectors`` package.

0.2.2 - 2014-03-03
~~~~~~~~~~~~~~~~~~

* Removed a constant definition that was causing compilation problems with specific versions of OpenSSL.

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
