ML-DSA vector creation
======================

This page documents the code that was used to generate the ML-DSA-44 test
vector. This vector is used to verify that unsupported ML-DSA variants
(i.e. variants other than ML-DSA-65) are correctly rejected when loading
keys.

Private key
-----------

The following Python script was run to generate the vector file.

.. literalinclude:: /development/custom-vectors/mldsa/generate_mldsa.py

Download link: :download:`generate_mldsa.py
</development/custom-vectors/mldsa/generate_mldsa.py>`

Public key
----------

The public key was derived from the private key using the OpenSSL CLI
(requires OpenSSL 3.5+ or AWS-LC with ML-DSA-44 support):

.. code-block:: console

    $ openssl pkey -in mldsa44_priv.der -inform DER -pubout -outform DER -out mldsa44_pub.der
