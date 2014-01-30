Changelog
=========

0.2 - 2014-XX-XX
~~~~~~~~~~~~~~~~

**In development**

* Added :doc:`/hazmat/backends/commoncrypto`.
* Added initial :doc:`/hazmat/bindings/commoncrypto`.
* Removed ``register_cipher_adapter`` method from
  :class:`~cryptography.hazmat.backends.interfaces.CipherBackend`.
* Added support for the OpenSSL backend under Windows.
* Improved thread-safety for the OpenSSL backend.
* Fixed compilation on systems where OpenSSL's ``ec.h`` header is not
  available, such as CentOS.
* Added :class:`~cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC`.

0.1 - 2014-01-08
~~~~~~~~~~~~~~~~

* Initial release.

