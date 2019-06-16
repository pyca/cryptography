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

.. _`Memory wiping`:  https://devblogs.microsoft.com/oldnewthing/?p=4223
.. _`CERT secure coding guidelines`: https://www.securecoding.cert.org/confluence/display/c/MEM03-C.+Clear+sensitive+information+stored+in+reusable+resources
