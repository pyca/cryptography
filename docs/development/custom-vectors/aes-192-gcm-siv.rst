AES-GCM-SIV vector creation
===========================

This page documents the code that was used to generate the AES-GCM-SIV test
vectors for key lengths not available in the OpenSSL test vectors. All the
vectors were generated using OpenSSL and verified with Rust.

Creation
--------

The following Python script was run to generate the vector files. The OpenSSL
test vectors were used as a base and modified to have 192-bit key length.

.. literalinclude:: /development/custom-vectors/aes-192-gcm-siv/generate_aes192gcmsiv.py

Download link: :download:`generate_aes192gcmsiv.py
</development/custom-vectors/aes-192-gcm-siv/generate_aes192gcmsiv.py>`


Verification
------------

The following Rust program was used to verify the vectors.

.. literalinclude:: /development/custom-vectors/aes-192-gcm-siv/verify-aes192gcmsiv/src/main.rs

Download link: :download:`main.rs
</development/custom-vectors/aes-192-gcm-siv/verify-aes192gcmsiv/src/main.rs>`
