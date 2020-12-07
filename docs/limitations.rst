Known security limitations
==========================

Secure memory wiping
--------------------

`Memory wiping`_ is used to protect secret data or key material from attackers
with access to deallocated memory. This is a defense-in-depth measure against
vulnerabilities that leak application memory.

Many ``cryptography`` APIs which accept ``bytes`` also accept types which
implement the buffer interface. Thus, users wishing to do so can pass
``memoryview`` or another mutable type to ``cryptography`` APIs, and overwrite
the contents once the data is no longer needed.

However, ``cryptography`` does not clear memory by default, as there is no way
to clear immutable structures such as ``bytes``. As a result, ``cryptography``,
like almost all software in Python is potentially vulnerable to this attack. The
`CERT secure coding guidelines`_ assesses this issue as "Severity: medium,
Likelihood: unlikely, Remediation Cost: expensive to repair" and we do not
consider this a high risk for most users.

RSA PKCS1 v1.5 constant time decryption
---------------------------------------

RSA decryption has several different modes, one of which is PKCS1 v1.5. When
used in online contexts, a secure protocol implementation requires that peers
not be able to tell whether RSA PKCS1 v1.5 decryption failed or succeeded,
even by timing variability.

``cryptography`` does not provide an API that makes this possible, due to the
fact that RSA decryption raises an exception on failure, which takes a
different amount of time than returning a value in the success case.

For this reason, at present, we recommend not implementing online protocols
that use RSA PKCS1 v1.5 decryption with ``cryptography`` -- independent of this
limitation, such protocols generally have poor security properties due to their
lack of forward security.

If a constant time RSA PKCS1 v1.5 decryption API is truly required, you should
contribute one to ``cryptography``.

.. _`Memory wiping`:  https://devblogs.microsoft.com/oldnewthing/?p=4223
.. _`CERT secure coding guidelines`: https://wiki.sei.cmu.edu/confluence/display/c/MEM03-C.+Clear+sensitive+information+stored+in+reusable+resources
