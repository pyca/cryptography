# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import os
from distutils.command.build import build

from setuptools import find_packages, setup
from setuptools.command.install import install


base_dir = os.path.dirname(__file__)

about = {}
with open(os.path.join(
          base_dir, "cryptography_libscrypt", "__about__.py")) as f:
    exec(f.read(), about)


def get_ext_modules():
    from cryptography_libscrypt.binding import Binding
    ext_modules = [
        Binding.ffi.verifier.get_extension()
    ]
    return ext_modules


class CFFIBuild(build):
    def finalize_options(self):
        self.distribution.ext_modules = get_ext_modules()
        build.finalize_options(self)


class CFFIInstall(install):
    def finalize_options(self):
        self.distribution.ext_modules = get_ext_modules()
        install.finalize_options(self)


setup(
    name=about["__title__"],
    version=about["__version__"],

    description=about["__summary__"],
    license=about["__license__"],
    url=about["__uri__"],
    author=about["__author__"],
    author_email=about["__email__"],

    packages=find_packages(),
    setup_requires="cryptography>=0.6",
    install_requires="cryptography>=0.6",
    zip_safe=False,
    cmdclass={
        "build": CFFIBuild,
        "install": CFFIInstall
    },
    entry_points={
        "cryptography.backends": ["libscrypt = cryptography_libscrypt:backend"]
    }
)
