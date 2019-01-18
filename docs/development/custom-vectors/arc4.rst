ARC4 vector creation
====================

This page documents the code that was used to generate the ARC4 test
vectors for key lengths not available in :rfc:`6229`. All the vectors
were generated using OpenSSL and verified with Go.

Creation
--------

``cryptography`` was modified to support ARC4 key lengths not listed
in :rfc:`6229`. Then the following Python script was run to generate the
vector files.

.. literalinclude:: /development/custom-vectors/arc4/generate_arc4.py

Download link: :download:`generate_arc4.py
</development/custom-vectors/arc4/generate_arc4.py>`


Verification
------------

The following Go code was used to verify the vectors.

.. literalinclude:: /development/custom-vectors/arc4/verify_arc4.go
    :language: go

Download link: :download:`verify_arc4.go
</development/custom-vectors/arc4/verify_arc4.go>`
