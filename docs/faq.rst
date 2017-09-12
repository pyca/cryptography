Frequently asked questions
==========================

``cryptography`` failed to install!
-----------------------------------

If you are having issues installing ``cryptography`` the first troubleshooting
step is to upgrade ``pip`` and then try to install again. For most users this will
take the form of ``pip install -U pip``, but on Windows you should do
``python -m pip install -U pip``. If you are still seeing errors after upgrading
and trying ``pip install cryptography`` again, please see the :doc:`/installation`
documentation.

How does ``cryptography`` compare to NaCl (Networking and Cryptography Library)?
--------------------------------------------------------------------------------

While ``cryptography`` and `NaCl`_ both share the goal of making cryptography
easier, and safer, to use for developers, ``cryptography`` is designed to be a
general purpose library, interoperable with existing systems, while NaCl
features a collection of hand selected algorithms.

``cryptography``'s :ref:`recipes <cryptography-layout>` layer has similar goals
to NaCl.

If you prefer NaCl's design, we highly recommend `PyNaCl`_.

Why use ``cryptography``?
-------------------------

If you've done cryptographic work in Python before you have likely encountered
other libraries in Python such as *M2Crypto*, *PyCrypto*, or *PyOpenSSL*. In
building ``cryptography`` we wanted to address a few issues we observed in the
legacy libraries:

* Extremely error prone APIs and insecure defaults.
* Use of poor implementations of algorithms (i.e. ones with known side-channel
  attacks).
* Lack of maintenance.
* Lack of high level APIs.
* Lack of PyPy and Python 3 support.
* Absence of algorithms such as
  :class:`AES-GCM <cryptography.hazmat.primitives.ciphers.modes.GCM>` and
  :class:`~cryptography.hazmat.primitives.kdf.hkdf.HKDF`.

Compiling ``cryptography`` on macOS produces a ``fatal error: 'openssl/aes.h' file not found`` error
----------------------------------------------------------------------------------------------------

This happens because macOS 10.11 no longer includes a copy of OpenSSL.
``cryptography`` now provides wheels which include a statically linked copy of
OpenSSL. You're seeing this error because your copy of pip is too old to find
our wheel files. Upgrade your copy of pip with ``pip install -U pip`` and then
try install ``cryptography`` again.

If you are using PyPy, we do not currently ship ``cryptography`` wheels for
PyPy. You will need to install your own copy of OpenSSL -- we recommend using
Homebrew.

Starting ``cryptography`` using ``mod_wsgi`` produces an ``InternalError`` during a call in ``_register_osrandom_engine``
-------------------------------------------------------------------------------------------------------------------------

Upgrade to the latest ``cryptography`` and this issue should be resolved.

``cryptography`` raised an ``InternalError`` and I'm not sure what to do?
-------------------------------------------------------------------------

Frequently ``InternalError`` is raised when there are errors on the OpenSSL
error stack that were placed there by other libraries that are also using
OpenSSL. Try removing the other libraries and see if the problem persists.
If you have no other libraries using OpenSSL in your process, or they do not
appear to be at fault, it's possible that this is a bug in ``cryptography``.
Please file an `issue`_ with instructions on how to reproduce it.

Installing ``cryptography`` fails with ``ImportError: No module named setuptools_ext``
--------------------------------------------------------------------------------------

Your ``cffi`` package is out of date. ``pip install -U cffi`` to update it.

error: ``-Werror=sign-conversion``: No option ``-Wsign-conversion`` during installation
---------------------------------------------------------------------------------------

The compiler you are using is too old and not supported by ``cryptography``.
Please upgrade to a more recent version. If you are running OpenBSD 6.1 or
earlier the default compiler is extremely old. Use ``pkg_add`` to install a
newer ``gcc`` and then install ``cryptography`` using
``CC=/path/to/newer/gcc pip install cryptography``.

Installing cryptography with OpenSSL 0.9.8 or 1.0.0 fails
---------------------------------------------------------

The OpenSSL project has dropped support for the 0.9.8 and 1.0.0 release series.
Since they are no longer receiving security patches from upstream,
``cryptography`` is also dropping support for them. To fix this issue you
should upgrade to a newer version of OpenSSL (1.0.1 or later). This may require
you to upgrade to a newer operating system.

.. _`NaCl`: https://nacl.cr.yp.to/
.. _`PyNaCl`: https://pynacl.readthedocs.io
.. _`WSGIApplicationGroup`: https://modwsgi.readthedocs.io/en/develop/configuration-directives/WSGIApplicationGroup.html
.. _`issue`: https://github.com/pyca/cryptography/issues
