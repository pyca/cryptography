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
import re

import invoke


def update_version(filename, identifier, version):
    path = os.path.join(os.path.dirname(__file__), filename)
    with open(path) as f:
        contents = f.read()
    contents = re.sub(
        r"^{} = .*?$".format(identifier),
        '{} = "{}"'.format(identifier, version),
        contents,
        flags=re.MULTILINE
    )
    with open(path, "w") as f:
        f.write(contents)


@invoke.task
def release(version):
    """
    ``version`` should be a string like '0.4' or '1.0'.
    """
    # This checks for changes in the repo.
    invoke.run("git diff-index --quiet HEAD")

    update_version("cryptography/__about__.py", "__version__", version)
    update_version("docs/conf.py", "version", version)
    update_version("docs/conf.py", "release", version)

    invoke.run("git commit -am 'Bump version numbers for release.'")
    invoke.run("git push")
    invoke.run("git tag -s {}".format(version))
    invoke.run("git push --tags")

    invoke.run("python setup.py sdist bdist_wheel")
    invoke.run("twine upload -s dist/cryptography-{}*".format(version))
