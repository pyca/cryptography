Frequently asked questions
==========================

How does ``cryptography`` compare to NaCl (Networking and Cryptography Library)?
--------------------------------------------------------------------------------

While ``cryptography`` and `NaCl`_ both share the goal of making cryptography
easier, and safer, to use for developers, ``cryptography`` is designed to be a
general purpose library, interoperable with existing systems, while NaCl
features a collection of hand selected algorithms.

``cryptography``'s :ref:`recipes <cryptography-layout>` layer has similar goals
to NaCl.

If you prefer NaCl's design, we highly recommend `PyNaCl`_.

When I try to use ``cryptography`` on Windows I get a ``cffi.ffiplatform.VerificationError``
--------------------------------------------------------------------------------------------

This error looks something like:

.. code-block:: console

    cffi.ffiplatform.VerificationError: importing '<some_path>.pyd': DLL load failed:

It typically occurs on Windows when the user has not installed OpenSSL. Download
a `pre-compiled binary`_ to resolve this issue.

.. _`NaCl`: http://nacl.cr.yp.to/
.. _`PyNaCl`: https://pynacl.readthedocs.org
.. _`pre-compiled binary`: https://www.openssl.org/related/binaries.html
