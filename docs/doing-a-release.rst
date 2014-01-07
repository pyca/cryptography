Doing a Release
===============

Doing a release of ``cryptography`` is a two part process.

Bumping the version number
--------------------------

The first step in doing a release is bumping the version number in the
software.

* Update the version number in ``cryptography/__about__.py``.
* Do a commit indicating this.
* Send a pull request with this.
* Wait for it to be merged.

Performing the release
----------------------

The commit which merged the version number bump is now the official release
commit for this release. Once this has happened:

* Run ``invoke release {version}``.

That's all, the release should now be available on PyPI and a tag should be
available in the repository.
