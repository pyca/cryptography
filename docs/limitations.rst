Known security limitations
--------------------------

Lack of secure memory wiping
============================

`Memory wiping`_ is used to protect secret data or key material from attackers
with access to uninitialized memory. This can be either because the attacker
has some kind of local user access or because of how other software uses
uninitialized memory.

Python exposes no API for us to implement this reliably and as such almost all
software in Python is potentially vulnerable to this attack. The
`CERT secure coding guidelines`_ assesses this issue as "Severity: medium,
Likelihood: unlikely, Remediation Cost: expensive to repair" and we do not
consider this a high risk for most users.

.. _`Memory wiping`:  https://blogs.msdn.microsoft.com/oldnewthing/20130529-00/?p=4223/
.. _`CERT secure coding guidelines`: https://www.securecoding.cert.org/confluence/display/c/MEM03-C.+Clear+sensitive+information+stored+in+reusable+resources
