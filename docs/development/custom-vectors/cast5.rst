CAST5 vector creation
=====================

This page documents the code that was used to generate the CAST5 CBC, CFB, OFB,
and CTR test vectors as well as the code used to verify them against another
implementation. The CBC, CFB, and OFB vectors were generated using OpenSSL and
the CTR vectors were generated using Apple's CommonCrypto. All the generated
vectors were verified with Go.

Creation
--------

``cryptography`` was modified to support CAST5 in CBC, CFB, and OFB modes. Then
the following Python script was run to generate the vector files.

.. literalinclude:: /development/custom-vectors/cast5/generate_cast5.py

Download link: :download:`generate_cast5.py
</development/custom-vectors/cast5/generate_cast5.py>`


Verification
------------

The following Go code was used to verify the vectors.

.. literalinclude:: /development/custom-vectors/cast5/verify_cast5.go
    :language: go

Download link: :download:`verify_cast5.go
</development/custom-vectors/cast5/verify_cast5.go>`
