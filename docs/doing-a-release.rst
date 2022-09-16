Doing a release
===============

Doing a release of ``cryptography`` requires a few steps.

Security Releases
-----------------

In addition to the other steps described below, for a release which fixes a
security vulnerability, you should also include the following steps:

* Request a `CVE from MITRE`_. Once you have received the CVE, it should be
  included in the :doc:`changelog`. Ideally you should request the CVE before
  starting the release process so that the CVE is available at the time of the
  release.
* Document the CVE in the git commit that fixes the issue.
* Ensure that the :doc:`changelog` entry credits whoever reported the issue and
  contains the assigned CVE.
* Publish a GitHub Security Advisory on the repository with all relevant
  information.
* The release should be announced on the `oss-security`_ mailing list, in
  addition to the regular announcement lists.

Verifying OpenSSL version
-------------------------

The release process creates wheels bundling OpenSSL for Windows, macOS, and
Linux. Check that the Windows, macOS, and Linux builders (the ``manylinux``
containers) have the latest OpenSSL. If anything is out of date follow the
instructions for upgrading OpenSSL.

Upgrading OpenSSL
-----------------

Use the `upgrading OpenSSL issue template`_.

Bumping the version number
--------------------------

The next step in doing a release is bumping the version number in the
software.

* Update the version number in ``src/cryptography/__about__.py``.
* Update the version number in ``vectors/cryptography_vectors/__about__.py``.
* Set the release date in the :doc:`/changelog`.
* Do a commit indicating this.
* Send a pull request with this.
* Wait for it to be merged.

Performing the release
----------------------

The commit that merged the version number bump is now the official release
commit for this release. You will need to have ``gpg`` installed and a ``gpg``
key in order to do a release. Once this has happened:

* Run ``python release.py {version}``.

The release should now be available on PyPI and a tag should be available in
the repository.

Verifying the release
---------------------

You should verify that ``pip install cryptography`` works correctly:

.. code-block:: pycon

    >>> import cryptography
    >>> cryptography.__version__
    '...'
    >>> import cryptography_vectors
    >>> cryptography_vectors.__version__
    '...'

Verify that this is the version you just released.

For the Windows wheels check the builds for the ``cryptography-wheel-builder``
job and verify that the final output for each build shows it loaded and linked
the expected OpenSSL version.

Post-release tasks
------------------

* Send an email to the `mailing list`_ and `python-announce`_ announcing the
  release.
* Close the `milestone`_ for the previous release on GitHub.
* For major version releases, send a pull request to pyOpenSSL increasing the
  maximum ``cryptography`` version pin and perform a pyOpenSSL release.
* Update the version number to the next major (e.g. ``0.5.dev1``) in
  ``src/cryptography/__about__.py`` and
  ``vectors/cryptography_vectors/__about__.py``.
* Add new :doc:`/changelog` entry with next version and note that it is under
  active development
* Send a pull request with these items
* Check for any outstanding code undergoing a deprecation cycle by looking in
  ``cryptography.utils`` for ``DeprecatedIn**`` definitions. If any exist open
  a ticket to increment them for the next release.

.. _`CVE from MITRE`: https://cveform.mitre.org/
.. _`oss-security`: https://www.openwall.com/lists/oss-security/
.. _`upgrading OpenSSL issue template`: https://github.com/pyca/cryptography/issues/new?template=openssl-release.md
.. _`milestone`: https://github.com/pyca/cryptography/milestones
.. _`mailing list`: https://mail.python.org/mailman/listinfo/cryptography-dev
.. _`python-announce`: https://mail.python.org/mailman/listinfo/python-announce-list
