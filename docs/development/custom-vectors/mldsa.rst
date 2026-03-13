ML-DSA vector creation
======================

This page documents the ML-DSA test vectors. These vectors are used to verify:

* Unsupported ML-DSA variants (i.e. variants other than ML-DSA-65) are
  correctly rejected when loading keys.
* ML-DSA-65 private keys without a seed are correctly rejected.

ML-DSA-44 public key
--------------------

The public key was derived from the private key using the OpenSSL CLI
(requires OpenSSL 3.5+):

.. code-block:: console

    $ openssl pkey -in mldsa44_priv.der -inform DER -pubout -outform DER -out mldsa44_pub.der
