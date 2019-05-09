Reviewing and merging patches
=============================

Everyone is encouraged to review open pull requests. We only ask that you try
and think carefully, ask questions and are `excellent to one another`_. Code
review is our opportunity to share knowledge, design ideas and make friends.

When reviewing a patch try to keep each of these concepts in mind:

Intent
------

* What is the change being proposed?
* Do we want this feature or is the bug they're fixing really a bug?

Architecture
------------

* Is the proposed change being made in the correct place? Is it a fix in a
  backend when it should be in the primitives?

Implementation
--------------

* Does the change do what the author claims?
* Are there sufficient tests?
* Has it been documented?
* Will this change introduce new bugs?

Grammar and style
-----------------

These are small things that are not caught by the automated style checkers.

* Does a variable need a better name?
* Should this be a keyword argument?

Merge requirements
------------------

Because cryptography is so complex, and the implications of getting it wrong so
devastating, ``cryptography`` has a strict merge policy for committers:

* Patches must *never* be pushed directly to ``master``, all changes (even the
  most trivial typo fixes!) must be submitted as a pull request.
* A committer may *never* merge their own pull request, a second party must
  merge their changes. If multiple people work on a pull request, it must be
  merged by someone who did not work on it.
* A patch that breaks tests, or introduces regressions by changing or removing
  existing tests should not be merged. Tests must always be passing on
  ``master``.
* If somehow the tests get into a failing state on ``master`` (such as by a
  backwards incompatible release of a dependency) no pull requests may be
  merged until this is rectified.
* All merged patches must have 100% test coverage.

The purpose of these policies is to minimize the chances we merge a change
that jeopardizes our users' security.

.. _`excellent to one another`: https://speakerdeck.com/ohrite/better-code-review
