.. hazmat::

MultiBackend
============

.. currentmodule:: cryptography.hazmat.backends.multibackend

.. class:: MultiBackend(backends)

    .. versionadded:: 0.2

    This class allows you to combine multiple backends into a single backend
    that offers the combined features of all of its constituents.

    .. testsetup::

        from cryptography import utils
        from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
        from cryptography.hazmat.backends.interfaces import HashBackend
        from cryptography.hazmat.backends.openssl.backend import backend as backend2

        @utils.register_interface(HashBackend)
        class DummyHashBackend(object):
            def hash_supported(self, algorithm):
                return False

            def create_hash_ctx(self, algorithm):
                raise UnsupportedAlgorithm("", _Reasons.UNSUPPORTED_HASH)

        backend1 = DummyHashBackend()

    .. doctest::

        >>> from cryptography.hazmat.backends.multibackend import MultiBackend
        >>> from cryptography.hazmat.primitives import hashes
        >>> backend1.hash_supported(hashes.SHA256())
        False
        >>> backend2.hash_supported(hashes.SHA256())
        True
        >>> multi_backend = MultiBackend([backend1, backend2])
        >>> multi_backend.hash_supported(hashes.SHA256())
        True

    :param backends: A ``list`` of backend objects. Backends are checked for
                     feature support in the order they appear in this list.
