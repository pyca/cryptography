ChaCha20 vector creation
========================

This page documents the code that was used to generate the vectors
to test the counter overflow behavior in ChaCha20 as well as code
used to verify them against another implementation.

Creation
--------

The following Python script was run to generate the vector files.

.. literalinclude:: /development/custom-vectors/chacha20/generate_chacha20_overflow.py

Download link: :download:`generate_chacha20_overflow.py
</development/custom-vectors/chacha20/generate_chacha20_overflow.py>`


Verification
------------

The following Python script was used to verify the vectors. The
counter overflow is handled manually to avoid relying on the same
code that generated the vectors.

.. literalinclude:: /development/custom-vectors/chacha20/verify_chacha20_overflow.py

Download link: :download:`verify_chacha20_overflow.py
</development/custom-vectors/chacha20/verify_chacha20_overflow.py>`
