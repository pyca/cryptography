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
import sys

from setuptools import setup

install_requires = [
    "cffi>=0.6",
]

if sys.version_info[:2] < (3, 4):
    install_requires += ["enum34"]

setup(
    name="cryptography",
    license="Apache License, Version 2.0",
    install_requires=install_requires,
)
