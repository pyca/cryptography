# Copyright 2013 Donald Stufft
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import absolute_import, division, print_function
from __future__ import unicode_literals

import os
import re
import zipfile

try:
    from StringIO import StringIO
except ImportError:
    from _io import StringIO

from pkginfo import distribution
from pkginfo.distribution import Distribution

from twine import exceptions

# Monkeypatch Metadata 2.0 support
distribution.HEADER_ATTRS_2_0 = distribution.HEADER_ATTRS_1_2
distribution.HEADER_ATTRS.update({"2.0": distribution.HEADER_ATTRS_2_0})


wheel_file_re = re.compile(
    r"""^(?P<namever>(?P<name>.+?)(-(?P<ver>\d.+?))?)
        ((-(?P<build>\d.*?))?-(?P<pyver>.+?)-(?P<abi>.+?)-(?P<plat>.+?)
        \.whl|\.dist-info)$""",
    re.VERBOSE)


def try_decode(s):
    if isinstance(s, bytes):
        return s.decode('utf8')
    return s


class Wheel(Distribution):

    def __init__(self, filename, metadata_version=None):
        self.filename = filename
        self.basefilename = os.path.basename(self.filename)
        self.metadata_version = metadata_version
        self.extractMetadata()

    @property
    def py_version(self):
        wheel_info = wheel_file_re.match(self.basefilename)
        return wheel_info.group("pyver")

    @staticmethod
    def find_candidate_metadata_files(names):
        """Filter files that may be METADATA files."""
        tuples = [
            x.split('/') for x in map(try_decode, names)
            if 'METADATA' in x
        ]
        return [x[1] for x in sorted([(len(x), x) for x in tuples])]

    def read(self):
        fqn = os.path.abspath(os.path.normpath(self.filename))
        if not os.path.exists(fqn):
            raise exceptions.InvalidDistribution(
                'No such file: %s' % fqn
            )

        if fqn.endswith('.whl'):
            archive = zipfile.ZipFile(fqn)
            names = archive.namelist()

            def read_file(name):
                return archive.read(name)
        else:
            raise exceptions.InvalidDistribution(
                'Not a known archive format: %s' % fqn
            )

        try:
            for path in self.find_candidate_metadata_files(names):
                candidate = '/'.join(path)
                data = read_file(candidate)
                if b'Metadata-Version' in data:
                    return data
        finally:
            archive.close()

        raise exceptions.InvalidDistribution(
            'No METADATA in archive: %s' % fqn
        )

    def parse(self, data):
        super(Wheel, self).parse(data)

        fp = StringIO(distribution.must_decode(data))
        msg = distribution.parse(fp)
        self.description = msg.get_payload()
