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

A Java 8 program was written using the Bouncy Castle (https://www.bouncycastle.org/)
cryptographic provider to load and verify the test vectors.


.. literalinclude:: /development/custom-vectors/rsa-oaep-sha2/Verify_RSA_OAEP_SHA2.java

Download link: :download:`Verify_RSA_OAEP_SHA2.java
</development/custom-vectors/rsa-oaep-sha2/Verify_RSA_OAEP_SHA2.java>`

Building Verification for OSX
----------------
Download and install the Java 8 SDK (http://www.oracle.com/technetwork/java/javase/downloads/index.html)
The following was used for the initial verification: jdk-8u77-macosx-x64.dmg

Download Bouncy Castle Jar from https://www.bouncycastle.org/latest_releases.html
The following was used for the initial verification: bcprov-jdk15on-154.jar

Set the CLASSPATH to include the Bouncy Castle jar and the path to Verify_RSA_OAEP_SHA2.java
(with colon : separation of paths)

i.e. export CLASSPATH=~/Downloads/bcprov-jdk15on-154.jar:./

Compile:
javac Verify_RSA_OAEP_SHA2.java

And run with the path to the vectors:
java Verify_RSA_OAEP_SHA2 <path to test vector files>

e.g. java Verify_RSA_OAEP_SHA2 ./vectors/
