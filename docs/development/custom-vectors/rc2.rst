RC2 vector creation
===================

This page documents the code that was used to generate the RC2 CBC test vector.
The CBC vector was generated using Go's internal RC2 implementation and
verified using Go and OpenSSL.

Creation/Verification
---------------------

The program below outputs a test vector in the standard format we use and
also verifies that the encrypted value round trips as expected. The output
was also checked against OpenSSL by modifying ``cryptography`` to support
the algorithm. If you wish to run this program we recommend cloning the
repository, which also contains the requisite ``go.mod`` file.

.. literalinclude:: /development/custom-vectors/rc2/genrc2.go
    :language: go

Download link: :download:`genrc2.go
</development/custom-vectors/rc2/genrc2.go>`

Download link: :download:`rc2.go
</development/custom-vectors/rc2/rc2/rc2.go>`
