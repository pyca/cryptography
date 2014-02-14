CAST5 Vector Creation
=====================

This page documents the code that was used to generate the CAST5 CBC, CFB, and
OFB test vectors as well as the code used to verify them against another
implementation. For CAST5 the vectors were generated using OpenSSL and verified
with Go.

Creation
--------

``cryptography`` was modified to support CAST5 in CBC, CFB, and OFB modes. Then
the following python script was run to generate the vector files.

.. literalinclude:: /development/custom-vectors/cast5/generate_cast5.py

Download link: :download:`generate_cast5.py </development/custom-vectors/cast5/generate_cast5.py>`


Verification
------------

The following go code was used to verify the vectors.

.. literalinclude:: /development/custom-vectors/cast5/verify_cast5.go
    :language: go

Download link: :download:`verify_cast5.go </development/custom-vectors/cast5/verify_cast5.go>`
