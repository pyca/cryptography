#!/usr/bin/env python

# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os
import platform
import subprocess
import sys
from distutils.command.build import build

import pkg_resources

import setuptools
from setuptools import find_packages, setup
from setuptools.command.install import install
from setuptools.command.test import test


if (
    pkg_resources.parse_version(setuptools.__version__) <
    pkg_resources.parse_version("18.5")
):
    raise RuntimeError(
        "cryptography requires setuptools 18.5 or newer, please upgrade to a "
        "newer version of setuptools"
    )

base_dir = os.path.dirname(__file__)
src_dir = os.path.join(base_dir, "src")

# When executing the setup.py, we need to be able to import ourselves, this
# means that we need to add the src/ directory to the sys.path.
sys.path.insert(0, src_dir)

about = {}
with open(os.path.join(src_dir, "cryptography", "__about__.py")) as f:
    exec(f.read(), about)


VECTORS_DEPENDENCY = "cryptography_vectors=={0}".format(about['__version__'])

if platform.python_implementation() == "PyPy":
    if sys.pypy_version_info < (5, 4):
        raise RuntimeError(
            "cryptography is not compatible with PyPy < 5.4. Please upgrade "
            "PyPy to use this library."
        )

test_requirements = [
    "pytest>=3.6.0,!=3.9.0,!=3.9.1,!=3.9.2",
    "pretend",
    "iso8601",
    "pytz",
    "hypothesis>=1.11.4,!=3.79.2",
]


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
        "Development Status :: 5 - Production/Stable",
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
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Security :: Cryptography",
    ],

    package_dir={"": "src"},
    packages=find_packages(where="src", exclude=["_cffi_src", "_cffi_src.*"]),
    include_package_data=True,

    python_requires='>=2.7,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*',

    install_requires=[
        "asn1crypto >= 0.21.0",
        "six >= 1.4.1",
        # Keep this version in sync with pyproject.toml
        "cffi>=1.8,!=1.11.3",
    ],
    tests_require=test_requirements,
    extras_require={
        ":python_version < '3'": ["enum34", "ipaddress"],

        "test": test_requirements,
        "docs": [
            "sphinx >= 1.6.5,!=1.8.0",
            "sphinx_rtd_theme",
        ],
        "docstest": [
            "doc8",
            "pyenchant >= 1.6.11",
            "twine >= 1.12.0",
            "sphinxcontrib-spelling >= 4.0.1",
        ],
        "pep8test": [
            "flake8",
            "flake8-import-order",
            "pep8-naming",
        ],
        # This extra is for the U-label support that was deprecated in
        # cryptography 2.1. If you need this deprecated path install with
        # pip install cryptography[idna]
        "idna": [
            "idna >= 2.1",
        ]
    },

    cffi_modules=[
        "src/_cffi_src/build_openssl.py:ffi",
        "src/_cffi_src/build_constant_time.py:ffi",
        "src/_cffi_src/build_padding.py:ffi",
    ],

    cmdclass={
        "test": PyTest,
    },

    # for cffi
    zip_safe=False,
    ext_package="cryptography.hazmat.bindings",
)
