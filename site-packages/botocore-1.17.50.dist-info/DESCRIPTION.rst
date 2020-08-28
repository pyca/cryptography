botocore
========

.. image:: https://secure.travis-ci.org/boto/botocore.png?branch=develop
   :target: http://travis-ci.org/boto/botocore

.. image:: https://codecov.io/github/boto/botocore/coverage.svg?branch=develop
    :target: https://codecov.io/github/boto/botocore?branch=develop


A low-level interface to a growing number of Amazon Web Services. The
botocore package is the foundation for the
`AWS CLI <https://github.com/aws/aws-cli>`__ as well as
`boto3 <https://github.com/boto/boto3>`__.

On 10/09/2019 support for Python 2.6 and Python 3.3 was deprecated and support
was dropped on 01/10/2020. To avoid disruption, customers using Botocore
on Python 2.6 or 3.3 will need to upgrade their version of Python or pin the
version of Botocore in use prior to 01/10/2020. For more information, see
this `blog post <https://aws.amazon.com/blogs/developer/deprecation-of-python-2-6-and-python-3-3-in-botocore-boto3-and-the-aws-cli/>`__.

Getting Started
---------------
Assuming that you have Python and ``virtualenv`` installed, set up your environment and install the required dependencies like this or you can install the library using ``pip``:

.. code-block:: sh

    $ git clone https://github.com/boto/botocore.git
    $ cd botocore
    $ virtualenv venv
    ...
    $ . venv/bin/activate
    $ pip install -r requirements.txt
    $ pip install -e .

.. code-block:: sh

    $ pip install botocore

Using Botocore
~~~~~~~~~~~~~~
After installing botocore 

Next, set up credentials (in e.g. ``~/.aws/credentials``):

.. code-block:: ini

    [default]
    aws_access_key_id = YOUR_KEY
    aws_secret_access_key = YOUR_SECRET

Then, set up a default region (in e.g. ``~/.aws/config``):

.. code-block:: ini

   [default]
   region=us-east-1

Other credentials configuration method can be found `here <https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html>`__

Then, from a Python interpreter:

.. code-block:: python

    >>> import botocore.session
    >>> session = botocore.session.get_session()
    >>> client = session.create_client('ec2')
    >>> print(client.describe_instances())


Getting Help
------------

We use GitHub issues for tracking bugs and feature requests and have limited
bandwidth to address them. Please use these community resources for getting
help. Please note many of the same resources available for ``boto3`` are
applicable for ``botocore``:

* Ask a question on `Stack Overflow <https://stackoverflow.com/>`__ and tag it with `boto3 <https://stackoverflow.com/questions/tagged/boto3>`__
* Come join the AWS Python community chat on `gitter <https://gitter.im/boto/boto3>`__
* Open a support ticket with `AWS Support <https://console.aws.amazon.com/support/home#/>`__
* If it turns out that you may have found a bug, please `open an issue <https://github.com/boto/botocore/issues/new>`__


Contributing
------------

We value feedback and contributions from our community. Whether it's a bug report, new feature, correction, or additional documentation, we welcome your issues and pull requests. Please read through this `CONTRIBUTING <https://github.com/boto/botocore/blob/develop/CONTRIBUTING.rst>`__ document before submitting any issues or pull requests to ensure we have all the necessary information to effectively respond to your contribution. 


More Resources
--------------

* `NOTICE <https://github.com/boto/botocore/blob/develop/NOTICE>`__
* `Changelog <https://github.com/boto/botocore/blob/develop/CHANGELOG.rst>`__
* `License <https://github.com/boto/botocore/blob/develop/LICENSE.txt>`__



