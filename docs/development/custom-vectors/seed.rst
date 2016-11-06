SEED vector creation
=====================

This page documents the code that was used to generate the SEED CFB and OFB
test vectors as well as the code used to verify them against another
implementation. The vectors were generated using OpenSSL and verified
with `Botan`_.

Creation
--------

``cryptography`` was modified to support SEED in CFB and OFB modes. Then
the following python script was run to generate the vector files.

.. literalinclude:: /development/custom-vectors/seed/generate_seed.py

Download link: :download:`generate_seed.py
</development/custom-vectors/seed/generate_seed.py>`


Verification
------------

The following Python code was used to verify the vectors using the `Botan`_
project's Python bindings.

.. literalinclude:: /development/custom-vectors/seed/verify_seed.py

Download link: :download:`verify_seed.py
</development/custom-vectors/seed/verify_seed.py>`

.. _`Botan`: https://botan.randombit.net
