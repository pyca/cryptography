#!/usr/bin/env python

# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os
import platform
import subprocess
import sys

import pkg_resources

from setuptools import find_packages, setup
from setuptools.command.test import test


base_dir = os.path.dirname(__file__)
src_dir = os.path.join(base_dir, "src")

# When executing the setup.py, we need to be able to import ourselves, this
# means that we need to add the src/ directory to the sys.path.
sys.path.insert(0, src_dir)

about = {}
with open(os.path.join(src_dir, "cryptography", "__about__.py")) as f:
    exec(f.read(), about)


VECTORS_DEPENDENCY = "cryptography_vectors=={0}".format(about['__version__'])

setup_requirements = []

if platform.python_implementation() == "PyPy":
    if sys.pypy_version_info < (5, 3):
        raise RuntimeError(
            "cryptography 1.9 is not compatible with PyPy < 5.3. Please "
            "upgrade PyPy to use this library."
        )
else:
    setup_requirements.append("cffi>=1.7")

test_requirements = [
    "pytest>=3.2.1",
    "pretend",
    "iso8601",
    "pytz",
]
if sys.version_info[:2] > (2, 6):
    test_requirements.append("hypothesis>=1.11.4")


# If there's no vectors locally that probably means we are in a tarball and
# need to go and get the matching vectors package from PyPi
if not os.path.exists(os.path.join(base_dir, "vectors/setup.py")):
    test_requirements.append(VECTORS_DEPENDENCY)


class PyTest(test):
    def finalize_options(self):
        test.finalize_options(self)
        self.test_args = []
        self.test_suite = True

        # This means there's a vectors/ folder with the package in here.
        # cd into it, install the vectors package and then refresh sys.path
        if VECTORS_DEPENDENCY not in test_requirements:
            subprocess.check_call(
                [sys.executable, "setup.py", "install"], cwd="vectors"
            )
            pkg_resources.get_distribution("cryptography_vectors").activate()

    def run_tests(self):
        # Import here because in module scope the eggs are not loaded.
        import pytest
        test_args = [os.path.join(base_dir, "tests")]
        errno = pytest.main(test_args)
        sys.exit(errno)


with open(os.path.join(base_dir, "README.rst")) as f:
    long_description = f.read()


setup(
    name=about["__title__"],
    version=about["__version__"],

    description=about["__summary__"],
    long_description=long_description,
    license=about["__license__"],
    url=about["__uri__"],

    author=about["__author__"],
    author_email=about["__email__"],

    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Operating System :: POSIX :: BSD",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Security :: Cryptography",
    ],

    package_dir={"": "src"},
    packages=find_packages(where="src", exclude=["_cffi_src", "_cffi_src.*"]),
    include_package_data=True,

    cffi_modules = [
        "src/_cffi_src/build_openssl.py:ffi",
        "src/_cffi_src/build_constant_time.py:ffi",
        "src/_cffi_src/build_padding.py:ffi",
    ]

    setup_requires=setup_requirements,
    install_requires=[
        "idna >= 2.1",
        "asn1crypto >= 0.21.0",
        "six >= 1.4.1",
    ],
    tests_require=test_requirements,
    extras_require={
        ":python_version < '3'": ["enum34", "ipaddress"],
        ":python_implementation != 'PyPy'": ["cffi >= 1.7"],

        "test": test_requirements,
        "docstest": [
            "doc8",
            "pyenchant >= 1.6.11",
            "readme_renderer >= 16.0",
            "sphinx != 1.6.1, != 1.6.2, != 1.6.3",
            "sphinx_rtd_theme",
            "sphinxcontrib-spelling",
        ],
        "pep8test": [
            "flake8",
            "flake8-import-order",
            "pep8-naming",
        ],
    },

    # for cffi
    zip_safe=False,
    ext_package="cryptography.hazmat.bindings",
    cmdclass={
        "test": PyTest,
    },
)
