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

A Java 8 program was written using `Bouncy Castle`_ to load and verify the test
vectors.


.. literalinclude:: /development/custom-vectors/rsa-oaep-sha2/VerifyRSAOAEPSHA2.java

Download link: :download:`VerifyRSAOAEPSHA2.java
</development/custom-vectors/rsa-oaep-sha2/VerifyRSAOAEPSHA2.java>`

Using the Verifier
------------------

Download and install the `Java 8 SDK`_. Initial verification was performed
using ``jdk-8u77-macosx-x64.dmg``.

Download the latest `Bouncy Castle`_ JAR.  Initial verification was performed
using ``bcprov-jdk15on-154.jar``.

Set the ``-classpath`` to include the Bouncy Castle jar and the path to
``VerifyRSAOAEPSHA2.java`` and compile the program.

.. code-block:: console

    $ javac -classpath ~/Downloads/bcprov-jdk15on-154.jar:./ VerifyRSAOAEPSHA2.java

Finally, run the program with the path to the SHA-2 vectors:

.. code-block:: console

    $ java -classpath ~/Downloads/bcprov-jdk15on-154.jar:./ VerifyRSAOAEPSHA2

.. _`Bouncy Castle`: https://www.bouncycastle.org/
.. _`Java 8 SDK`: https://www.oracle.com/technetwork/java/javase/downloads/index.html
