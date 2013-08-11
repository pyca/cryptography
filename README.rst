Cryptography
============

.. image:: https://travis-ci.org/alex/cryptography.png?branch=master
   :target: https://travis-ci.org/alex/cryptography

.. image:: https://coveralls.io/repos/alex/cryptography/badge.png?branch=master
    :target: https://coveralls.io/r/alex/cryptography?branch=master

``cryptography`` is a package designed to expose cryptographic primitives and
recipes to Python developers.

It is currently in early development and isn't recommended for general usage
yet. It targets Python 2.6-2.7, Python 3.2+, as well as PyPy.

You can more documentation at `Read The Docs`_.

.. _`Read The Docs`: https://cryptography.readthedocs.org/


Why a new crypto library for Python?
------------------------------------

None of the existing ones work on PyPy, and many of them are unmaintained or
are based around very poor implementations of algorithms (i.e ones with known
side-channel attacks).

