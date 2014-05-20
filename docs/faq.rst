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

It typically occurs on Windows when you have not installed OpenSSL. Download
a `pre-compiled binary`_ to resolve the issue. To select the right architecture
(32-bit or 64-bit) open a command prompt and start your Python interpreter.

If it is 32-bit it will say ``32 bit`` as well as ``Intel`` in the output:

.. code-block:: console

    Python 2.7.6 (default, Nov 10 2013, 19:24:18) [MSC v.1500 32 bit (Intel)] on win32

If it is 64-bit you will see ``64 bit`` as well as ``AMD64``:

.. code-block:: console

    Python 2.7.6 (default, Nov 10 2013, 19:24:24) [MSC v.1500 64 bit (AMD64)] on win32

Note that for both 32-bit and 64-bit it will say ``win32``, but other data
in the string may vary based on your version of Python.

.. _`NaCl`: http://nacl.cr.yp.to/
.. _`PyNaCl`: https://pynacl.readthedocs.org
.. _`pre-compiled binary`: https://www.openssl.org/related/binaries.html
