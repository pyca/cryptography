API stability
=============

From its first release, ``cryptography`` will have a strong API stability
policy.

What does this policy cover?
----------------------------

This policy includes any API or behavior that is documented in this
documentation.

What does "stable" mean?
------------------------

* Public APIs will not be removed or renamed without providing a compatibility
  alias.
* The behavior of existing APIs will not change.

What doesn't this policy cover?
-------------------------------

* We may add new features, things like the result of ``dir(obj))`` or the
  contents of ``obj.__dict__`` may change.
* Objects are not guaranteed to be pickleable, and pickled objects from one
  version of ``cryptography`` may not be loadable in future versions.
* Development versions of ``cryptography``. Before a feature is in a release,
  it is not covered by this policy and may change.

Security
~~~~~~~~

One exception to our API stability policy is for security. We will violate this
policy as necessary in order to resolve a security issue or harden
``cryptography`` against a possible attack.

Versioning
----------

This project uses a custom versioning scheme as described below.

Given a version ``cryptography X.Y.Z``,

* ``X.Y`` is a decimal number that is incremented for
  potentially-backwards-incompatible releases.

  * This increases like a standard decimal.
    In other words, 0.9 is the ninth release, and 1.0 is the tenth (not 0.10).
    The dividing decimal point can effectively be ignored.

* ``Z`` is an integer that is incremented for backward-compatible releases.

Deprecation
~~~~~~~~~~~

From time to time we will want to change the behavior of an API or remove it
entirely. In that case, here's how the process will work:

* In ``cryptography X.Y`` the feature exists.
* In ``cryptography X.Y + 0.1`` using that feature will emit a
  ``UserWarning``.
* In ``cryptography X.Y + 0.2`` using that feature will emit a
  ``UserWarning``.
* In ``cryptography X.Y + 0.3`` the feature will be removed or changed.

In short, code that runs without warnings will always continue to work for a
period of two releases.

From time to time, we may decide to deprecate an API that is particularly
widely used. In these cases, we may decide to provide an extended deprecation
period, at our discretion.
