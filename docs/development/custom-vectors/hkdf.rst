HKDF vector creation
====================

This page documents the code that was used to generate a longer
HKDF test vector (1200 bytes) than is available in RFC 5869. All
the vectors were generated using OpenSSL and verified with Go.

Creation
--------

The following Python script was run to generate the vector files.

.. literalinclude:: /development/custom-vectors/hkdf/generate_hkdf.py

Download link: :download:`generate_hkdf.py
</development/custom-vectors/hkdf/generate_hkdf.py>`


Verification
------------

The following Go code was used to verify the vectors.

.. literalinclude:: /development/custom-vectors/hkdf/verify_hkdf.go
    :language: go

Download link: :download:`verify_hkdf.go
</development/custom-vectors/hkdf/verify_hkdf.go>`
