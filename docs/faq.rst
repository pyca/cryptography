Frequently asked questions
==========================

What issues can you help with in your issue tracker?
----------------------------------------------------

The primary purpose of our issue tracker is to enable us to identify and
resolve bugs and feature requests in ``cryptography``, so any time a user
files a bug, we start by asking: Is this a ``cryptography`` bug, or is it a
bug somewhere else?

That said, we do our best to help users to debug issues that are in their code
or environments. Please note, however, that there's a limit to our ability to
assist users in resolving problems that are specific to their environments,
particularly when we have no way to reproduce the issue.

Lastly, we're not able to provide support for general Python or Python
packaging issues.

.. _faq-howto-handle-deprecation-warning:

I cannot suppress the deprecation warning that ``cryptography`` emits on import
-------------------------------------------------------------------------------

.. hint::

   The deprecation warning emitted on import does not inherit
   :py:exc:`DeprecationWarning` but inherits :py:exc:`UserWarning`
   instead.

If your pytest setup follows the best practices of failing on
emitted warnings (``filterwarnings = error``), you may ignore it
by adding the following line at the end of the list::

   ignore:Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in a future release.:UserWarning

**Note:** Using ``cryptography.utils.CryptographyDeprecationWarning``
is not possible here because specifying it triggers
``import cryptography`` internally that emits the warning before
the ignore rule even kicks in.

Ref: https://github.com/pytest-dev/pytest/issues/7524

The same applies when you use :py:func:`~warnings.filterwarnings` in
your code or invoke CPython with :std:option:`-W` command line option.

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

If you prefer NaCl's design, we highly recommend `PyNaCl`_, which is also
maintained by the PyCA team.

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
  :class:`AES-GCM <cryptography.hazmat.primitives.ciphers.aead.AESGCM>` and
  :class:`~cryptography.hazmat.primitives.kdf.hkdf.HKDF`.

Why does ``cryptography`` require Rust?
---------------------------------------

``cryptography`` uses OpenSSL (see: :doc:`/openssl`) for its cryptographic operations. OpenSSL is
the de facto standard for cryptographic libraries and provides high performance
along with various certifications that may be relevant to developers. However,
it is written in C and lacks `memory safety`_.  We want ``cryptography`` to be
as secure as possible while retaining the advantages of OpenSSL, so we've
chosen to rewrite non-cryptographic operations (such as ASN.1 parsing) in a
high performance memory safe language: Rust.

``cryptography`` raised an ``InternalError`` and I'm not sure what to do?
-------------------------------------------------------------------------

Frequently ``InternalError`` is raised when there are errors on the OpenSSL
error stack that were placed there by other libraries that are also using
OpenSSL. Try removing the other libraries and see if the problem persists.
If you have no other libraries using OpenSSL in your process, or they do not
appear to be at fault, it's possible that this is a bug in ``cryptography``.
Please file an `issue`_ with instructions on how to reproduce it.

Installing cryptography with OpenSSL 0.9.8, 1.0.0, 1.0.1, 1.0.2, 1.1.0 fails
----------------------------------------------------------------------------

The OpenSSL project has dropped support for the 0.9.8, 1.0.0, 1.0.1, 1.0.2,
and 1.1.0 release series. Since they are no longer receiving security patches
from upstream, ``cryptography`` is also dropping support for them. To fix this
issue you should upgrade to a newer version of OpenSSL (1.1.1 or later). This
may require you to upgrade to a newer operating system.

Installing ``cryptography`` fails with ``error: Can not find Rust compiler``
----------------------------------------------------------------------------

Building ``cryptography`` from source requires you have :ref:`Rust installed
and available<installation:Rust>` on your ``PATH``. You may be able to fix this
by upgrading to a newer version of ``pip`` which will install a pre-compiled
``cryptography`` wheel. If not, you'll need to install Rust. Follow the
:ref:`instructions<installation:Rust>` to ensure you install a recent Rust
version.

Rust is only required during the build phase of ``cryptography``, you do not
need to have Rust installed after you've built ``cryptography``. This is the
same as the C compiler toolchain which is also required to build
``cryptography``, but not afterwards.

I'm getting errors installing or importing ``cryptography`` on AWS Lambda
-------------------------------------------------------------------------

Make sure you're following AWS's documentation either for
`building .zip archives for Lambda`_ or
`building container images for Lambda`_.

Why are there no wheels for my Python3.x version?
-------------------------------------------------

Our Python3 wheels are ``abi3`` wheels. This means they support multiple
versions of Python. The ``abi3`` wheel can be used with any version of Python
greater than or equal to the version it specifies. Recent versions of ``pip``
will automatically install ``abi3`` wheels.

Why can't I import my PEM file?
-------------------------------

PEM is a format (defined by several RFCs, but originally :rfc:`1421`) for
encoding keys, certificates, and others cryptographic data into a regular form.
The data is encoded as base64 and wrapped with a header and footer.

If you are having trouble importing PEM files, make sure your file fits
the following rules:

* has a one-line header like this: ``-----BEGIN [FILE TYPE]-----``
  (where ``[FILE TYPE]`` is ``CERTIFICATE``, ``PUBLIC KEY``, ``PRIVATE KEY``,
  etc.)

* has a one-line footer like this: ``-----END [FILE TYPE]-----``

* all lines, except for the final one, must consist of exactly 64
  characters.

For example, this is a PEM file for a RSA Public Key: ::

   -----BEGIN PUBLIC KEY-----
   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7CsKFSzq20NLb2VQDXma
   9DsDXtKADv0ziI5hT1KG6Bex5seE9pUoEcUxNv4uXo2jzAUgyRweRl/DLU8SoN8+
   WWd6YWik4GZvNv7j0z28h9Q5jRySxy4dmElFtIRHGiKhqd1Z06z4AzrmKEzgxkOk
   LJjY9cvwD+iXjpK2oJwNNyavvjb5YZq6V60RhpyNtKpMh2+zRLgIk9sROEPQeYfK
   22zj2CnGBMg5Gm2uPOsGDltl/I/Fdh1aO3X4i1GXwCuPf1kSAg6lPJD0batftkSG
   v0X0heUaV0j1HSNlBWamT4IR9+iJfKJHekOqvHQBcaCu7Ja4kXzx6GZ3M2j/Ja3A
   2QIDAQAB
   -----END PUBLIC KEY-----

.. _faq-missing-backend:

What happened to the backend argument?
--------------------------------------

``cryptography`` stopped requiring the use of ``backend`` arguments in
version 3.1 and deprecated their use in version 36.0. If you are on an older
version that requires these arguments please view the appropriate documentation
version or upgrade to the latest release.

Note that for forward compatibility ``backend`` is still silently accepted by
functions that previously required it, but it is ignored and no longer
documented.

Will you upload wheels for my non-x86 non-ARM64 CPU architecture?
-----------------------------------------------------------------

Maybe! But there's some pre-requisites. For us to build wheels and upload them
to PyPI, we consider it necessary to run our tests for that architecture as a
part of our CI (i.e. for every commit). If we don't run the tests, it's hard
to have confidence that everything works -- particularly with cryptography,
which frequently employs per-architecture assembly code.

For us to add something to CI we need a provider which offers builds on that
architecture, which integrate into our workflows, has sufficient capacity, and
performs well enough not to regress the contributor experience. We don't think
this is an insurmountable bar, but it's also not one that can be cleared
lightly.

If you are interested in helping support a new CPU architecture, we encourage
you to reach out, discuss, and contribute that support. We will attempt to be
supportive, but we cannot commit to doing the work ourselves.

.. _`NaCl`: https://nacl.cr.yp.to/
.. _`PyNaCl`: https://pynacl.readthedocs.io
.. _`issue`: https://github.com/pyca/cryptography/issues
.. _`memory safety`: https://alexgaynor.net/2019/aug/12/introduction-to-memory-unsafety-for-vps-of-engineering/
.. _`building .zip archives for Lambda`: https://docs.aws.amazon.com/lambda/latest/dg/python-package.html
.. _`building container images for Lambda`: https://docs.aws.amazon.com/lambda/latest/dg/python-image.html
