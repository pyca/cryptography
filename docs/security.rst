Security
========

We take the security of ``cryptography`` seriously. The following are a set of
policies we have adopted to ensure that security issues are addressed in a
timely fashion.

Infrastructure
--------------

In addition to ``cryptography``'s code, we're also concerned with the security
of the infrastructure we run (primarily ``cryptography.io``).  If you discover
a security vulnerability in our infrastructure, we ask you to report it using
the same procedure.

What is a security issue?
-------------------------

Anytime it's possible to write code using ``cryptography``'s public API which
does not provide the guarantees that a reasonable developer would expect it to
based on our documentation.

That's a bit academic, but basically it means the scope of what we consider a
vulnerability is broad, and we do not require a proof of concept or even a
specific exploit, merely a reasonable threat model under which ``cryptography``
could be attacked.

To give a few examples of things we would consider security issues:

* If a recipe, such as Fernet, made it easy for a user to bypass
  confidentiality or integrity with the public API (e.g. if the API let a user
  reuse nonces).
* If, under any circumstances, we used a CSPRNG which wasn't fork-safe.
* If ``cryptography`` used an API in an underlying C library and failed to
  handle error conditions safely.

Examples of things we wouldn't consider security issues:

* Offering ECB mode for symmetric encryption in the *Hazmat* layer. Though ECB
  is critically weak, it is documented as being weak in our documentation.
* Using a variable time comparison somewhere, if it's not possible to
  articulate any particular program in which this would result in problematic
  information disclosure.

In general, if you're unsure, we request that you to default to treating things
as security issues and handling them sensitively, the worst thing that can
happen is that we'll ask you to file a public issue.

Reporting a security issue
--------------------------

We ask that you do not report security issues to our normal GitHub issue
tracker.

If you believe you've identified a security issue with ``cryptography``, please
report it to ``alex.gaynor@gmail.com`` and/or ``paul.l.kehrer@gmail.com``. You
should verify that your MTA uses TLS to ensure the confidentiality of your
message.

Once you've submitted an issue via email, you should receive an acknowledgment
within 48 hours, and depending on the action to be taken, you may receive
further follow-up emails.

Supported Versions
------------------

At any given time, we will provide security support for the `master`_ branch
as well as the most recent release.

New releases for OpenSSL updates
--------------------------------

As of versions 0.5, 1.0.1, and 2.0.0, ``cryptography`` statically links OpenSSL
in binary distributions for Windows, macOS, and Linux respectively, to ease
installation. Due to this, ``cryptography`` will release a new version whenever
OpenSSL has a security or bug fix release to avoid shipping insecure software.

Like all our other releases, this will be announced on the mailing list and we
strongly recommend that you upgrade as soon as possible.

Disclosure Process
------------------

When we become aware of a security bug in ``cryptography``, we will endeavor to
fix it and issue a release as quickly as possible. We will generally issue a new
release for any security issue.

The steps for issuing a security release are described in our
:doc:`/doing-a-release` documentation.


.. _`master`: https://github.com/pyca/cryptography
