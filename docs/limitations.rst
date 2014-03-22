Known security limitations
--------------------------

Lack of secure memory wiping
============================

`Memory wiping`_ is used to protect secret data or key material from attackers
with access to uninitialized memory. This can be either because the attacker
has some kind of local user access or because of how other software uses
uninitialized memory.

Python exposes no API for us to implement this reliably and as such most
software in Python is vulnerable to this attack. However we do not currently
believe this to be particularly high risk issue for most users.

.. _`Memory wiping`:  http://blogs.msdn.com/b/oldnewthing/archive/2013/05/29/10421912.aspx
