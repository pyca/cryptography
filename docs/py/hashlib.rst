Hashlib Compatible Interface
============================

Getting a Hashlib
-----------------

.. currentmodule:: cryptography.py.hashlib

.. class:: Hashlib(backend)

    A Python 2.7 `hashlib`_ module and `PEP247`_ compatible interface to the hashes supported by
    ``backend``. 
    
    .. doctest::

        >>> from cryptography.hazmat.backends import default_backend
        >>> from cryptography.py.hashlib import Hashlib
        >>> hashlib = Hashlib(default_backend())
        >>> hashlib.new("sha1", "cryptography").digest()
        b'H\xc9\x10\xb6aLJ\n\xa5\x85\x1a\xa7\x85q\xdd\x1e<:f\xba'
        >>> import hmac
        >>> hmac.new("key", "message", hashlib.sha1).digest()
        b' \x88\xdft\xd5\xf2\x14kH\x14l\xafIe7~\x9d\x0b\xe3\xa4'

    Unlike the ``hazmat`` interface to hash functions this API is thread-safe.

.. _`hashlib`: http://docs.python.org/2/library/hashlib.html
.. _`PEP247`: http://www.python.org/dev/peps/pep-0247/
