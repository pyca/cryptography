#!/usr/bin/env python

# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import os

from setuptools import find_packages, setup


base_dir = os.path.dirname(__file__)

about = {}
with open(os.path.join(base_dir, "cryptography_vectors", "__about__.py")) as f:
    exec(f.read(), about)


setup(
    name=about["__title__"],
    version=about["__version__"],
    description=about["__summary__"],
    license=about["__license__"],
    url=about["__uri__"],
    author=about["__author__"],
    author_email=about["__email__"],
    packages=find_packages(),
    zip_safe=False,
    include_package_data=True,
)
