IDEA vector creation
=====================

This page documents the code that was used to generate the IDEA CBC, CFB, and
OFB test vectors as well as the code used to verify them against another
implementation. The vectors were generated using OpenSSL and verified with
`Botan`_.

Creation
--------

``cryptography`` was modified to support IDEA in CBC, CFB, and OFB modes. Then
the following python script was run to generate the vector files.

.. literalinclude:: /development/custom-vectors/idea/generate_idea.py

Download link: :download:`generate_idea.py
</development/custom-vectors/idea/generate_idea.py>`


Verification
------------

The following Python code was used to verify the vectors using the `Botan`_
project's Python bindings.

.. literalinclude:: /development/custom-vectors/idea/verify_idea.py

Download link: :download:`verify_idea.py
</development/custom-vectors/idea/verify_idea.py>`

.. _`Botan`: https://botan.randombit.net
