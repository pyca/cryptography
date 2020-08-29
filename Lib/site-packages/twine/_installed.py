# Copyright 2013 Tres Seaver
# Copyright 2015 Ian Cordasco
# This code was originally licensed under the Python Software Foudation
# License by Tres Seaver. In order to facilitate finding the metadata of
# installed packages, part of the most current implementation of the
# pkginfo.Installed class is reproduced here with bug fixes from
# https://bugs.launchpad.net/pkginfo/+bug/1437570.
import glob
import os
import sys
import warnings
from typing import Optional

import pkginfo


class Installed(pkginfo.Installed):
    def read(self) -> Optional[str]:
        opj = os.path.join
        if self.package is not None:
            package = self.package.__package__
            if package is None:
                package = self.package.__name__
            egg_pattern = "%s*.egg-info" % package
            dist_pattern = "%s*.dist-info" % package
            file: Optional[str] = getattr(self.package, "__file__", None)
            if file is not None:
                candidates = []

                def _add_candidate(where: str) -> None:
                    candidates.extend(glob.glob(where))

                for entry in sys.path:
                    if file.startswith(entry):
                        _add_candidate(opj(entry, "METADATA"))  # egg?
                        _add_candidate(opj(entry, "EGG-INFO"))  # egg?
                        # dist-installed?
                        _add_candidate(opj(entry, egg_pattern))
                        _add_candidate(opj(entry, dist_pattern))
                dir, name = os.path.split(self.package.__file__)
                _add_candidate(opj(dir, egg_pattern))
                _add_candidate(opj(dir, dist_pattern))
                _add_candidate(opj(dir, "..", egg_pattern))
                _add_candidate(opj(dir, "..", dist_pattern))

                for candidate in candidates:
                    if os.path.isdir(candidate):
                        path = opj(candidate, "PKG-INFO")
                        if not os.path.exists(path):
                            path = opj(candidate, "METADATA")
                    else:
                        path = candidate
                    if os.path.exists(path):
                        with open(path) as f:
                            return f.read()

        warnings.warn(
            "No PKG-INFO or METADATA found for package: %s" % self.package_name
        )
        return None
