Documentation: http://chrissimpkins.github.io/crypto/

Description
-------------

crypto provides a simple interface to symmetric Gnu Privacy Guard (gpg) encryption and decryption for one or more files on Unix and Linux platforms.  It runs on top of gpg and requires a gpg install on your system.  Encryption is performed with the AES256 cipher algorithm. `Benchmarks relative to default gpg settings are available for text and binary file mime types <https://chrissimpkins.github.io/crypto/benchmarks.html>`_.

crypto provides a number of options including automated tar archives of multiple files prior to encryption, portable ASCII armored encryption formatting, and SHA256 hash digest generation for your encrypted files.  You can view all available options in the `usage documentation <http://chrissimpkins.github.io/crypto/usage.html>`_ or with the ``--help`` option.

Tested in cPython 2.7.x, 3.4.x, and pypy 2.4.x (Python version 2.7.9)


Install
---------

Install with ``pip`` using the command:

.. code-block:: bash

	$ pip install crypto

or `download the source repository <https://github.com/chrissimpkins/crypto/tarball/master>`_, unpack it, and navigate to the top level of the repository.  Then enter:

.. code-block:: bash

	$ python setup.py install


Upgrade
-----------

You can upgrade your crypto version with the command:

.. code-block:: bash

	$ pip install --upgrade crypto


Usage
---------

Encryption (crypto)
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

	$ crypto <options> [file path] <file path 2...>

.. code-block:: bash

	$ crypto <options> [directory path] <directory path 2...>


Decryption (decrypto)
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

	$ decrypto <options> [file path] <file path 2...>

.. code-block:: bash

	$ decrypto <options> [directory path] <directory path 2...>


You can find all available options in the `documentation <http://chrissimpkins.github.io/crypto/usage.html>`_ or by using one of the following commands:

.. code-block:: bash

	$ crypto --help
	$ decrypto --help


Frequently Asked Questions
-------------------------------

`FAQ link <http://chrissimpkins.github.io/crypto/faq.html>`_


Issue Reporting
-------------------

Issue reporting is available on the `GitHub repository <https://github.com/chrissimpkins/crypto/issues>`_


Changelog
------------

`Changelog link <http://chrissimpkins.github.io/crypto/changelog.html>`_


