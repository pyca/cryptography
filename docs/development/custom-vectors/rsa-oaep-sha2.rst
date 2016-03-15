RSA OAEP SHA2 vector creation
=============================

This page documents the code that was used to generate the RSA OAEP SHA2
test vectors as well as code used to verify them against another
implementation.


Creation
--------

``cryptography`` was modified to allow the use of SHA2 in OAEP encryption. Then
the following python script was run to generate the vector files.

.. literalinclude:: /development/custom-vectors/rsa-oaep-sha2/generate_rsa_oaep_sha2.py

Download link: :download:`generate_rsa_oaep_sha2.py
</development/custom-vectors/rsa-oaep-sha2/generate_rsa_oaep_sha2.py>`


Verification
------------

TODO. Probably some golang.
