SECP256K1 vector creation
=========================

This page documents the code that was used to generate the SECP256K1 elliptic
curve test vectors as well as code used to verify them against another
implementation.


Creation
--------

The vectors are generated using a `pure Python ecdsa`_ implementation. The test
messages and combinations of algorithms are derived from the NIST vector data.

.. literalinclude:: /development/custom-vectors/secp256k1/generate_secp256k1.py

Download link: :download:`generate_secp256k1.py
</development/custom-vectors/secp256k1/generate_secp256k1.py>`


Verification
------------

``cryptography`` was modified to support the SECP256K1 curve. Then
the following python script was run to generate the vector files.

.. literalinclude:: /development/custom-vectors/secp256k1/verify_secp256k1.py

Download link: :download:`verify_secp256k1.py
</development/custom-vectors/secp256k1/verify_secp256k1.py>`

.. _`pure Python ecdsa`: https://pypi.python.org/pypi/ecdsa
