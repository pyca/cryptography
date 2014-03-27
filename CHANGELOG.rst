Changelog
=========

0.3 - 2014-03-27
~~~~~~~~~~~~~~~~

* Added :class:`~cryptography.hazmat.primitives.twofactor.hotp.HOTP`.
* Added :class:`~cryptography.hazmat.primitives.twofactor.totp.TOTP`.
* Added :class:`~cryptography.hazmat.primitives.ciphers.algorithms.IDEA` support.
* Added signature support to :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
  and verification support to :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`.
* Moved test vectors to the new ``cryptography-vectors`` package.

0.2.2 - 2014-03-03
~~~~~~~~~~~~~~~~~~

* Removed a constant definition that was causing compilation problems with specific versions of OpenSSL.

0.2.1 - 2014-02-22
~~~~~~~~~~~~~~~~~~

* Fix a bug where importing cryptography from multiple paths could cause initialization to fail.

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
* Set default random for the :doc:`/hazmat/backends/openssl` to the OS random engine.
* Added :class:`~cryptography.hazmat.primitives.ciphers.algorithms.CAST5` (CAST-128) support.

0.1 - 2014-01-08
~~~~~~~~~~~~~~~~

* Initial release.

.. _`master`: https://github.com/pyca/cryptography/
