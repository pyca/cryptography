Hashlib Compatible Interface
============================

Getting a Hashlib
-----------------

.. currentmodule:: cryptography.py.hashlib

.. class:: Hashlib(backend)

    A Python ``hashlib`` and `PEP247`_ compatible interface to the hashes
    supported by ``backend``. This module supports both the
    `Python 2.7 hashlib`_ and `Python 3 hashlib`_ API.
    
    .. doctest::

        >>> from cryptography.hazmat.backends import default_backend
        >>> from cryptography.py.hashlib import Hashlib
        >>> hashlib = Hashlib(default_backend())
        >>> hashlib.new("sha1", b"cryptography").hexdigest()
        '48c910b6614c4a0aa5851aa78571dd1e3c3a66ba'
        >>> import hmac
        >>> hmac.new(b"key", b"message", hashlib.sha1).hexdigest()
        '2088df74d5f2146b48146caf4965377e9d0be3a4'

    Unlike the ``hazmat`` interface to hash functions this API is thread-safe.

.. _`Python 2.7 hashlib`: http://docs.python.org/2.7/library/hashlib.html
.. _`Python 3 hashlib`: http://docs.python.org/3.3/library/hashlib.html
.. _`PEP247`: http://www.python.org/dev/peps/pep-0247/
