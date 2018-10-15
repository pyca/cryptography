from __future__ import absolute_import, division, print_function
from __future__ import unicode_literals

import os
import re
import zipfile

from pkginfo.distribution import Distribution

from twine import exceptions

wininst_file_re = re.compile(r".*py(?P<pyver>\d+\.\d+)\.exe$")


class WinInst(Distribution):

    def __init__(self, filename, metadata_version=None):
        self.filename = filename
        self.metadata_version = metadata_version
        self.extractMetadata()

    @property
    def py_version(self):
        m = wininst_file_re.match(self.filename)
        if m is None:
            return "any"
        else:
            return m.group("pyver")

    def read(self):
        fqn = os.path.abspath(os.path.normpath(self.filename))
        if not os.path.exists(fqn):
            raise exceptions.InvalidDistribution(
                'No such file: %s' % fqn
            )

        if fqn.endswith('.exe'):
            archive = zipfile.ZipFile(fqn)
            names = archive.namelist()

            def read_file(name):
                return archive.read(name)
        else:
            raise exceptions.InvalidDistribution(
                'Not a known archive format: %s' % fqn
            )

        try:
            tuples = [x.split('/') for x in names
                      if x.endswith(".egg-info") or x.endswith("PKG-INFO")]
            schwarz = sorted([(len(x), x) for x in tuples])
            for path in [x[1] for x in schwarz]:
                candidate = '/'.join(path)
                data = read_file(candidate)
                if b'Metadata-Version' in data:
                    return data
        finally:
            archive.close()

        raise exceptions.InvalidDistribution(
            'No PKG-INFO/.egg-info in archive: %s' % fqn
        )
