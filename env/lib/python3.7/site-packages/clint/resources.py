# -*- coding: utf-8 -*-

"""
clint.resources
~~~~~~~~~~~~~~~

This module contains all the application resource features of clint.

"""


from __future__ import absolute_import
from __future__ import with_statement

import errno
from os import remove, removedirs
from os.path import isfile, join as path_join

from .packages.appdirs import AppDirs, AppDirsError
from .utils import mkdir_p, is_collection


__all__ = (
    'init', 'user', 'site', 'cache',
    'log', 'NotConfigured'
)


class AppDir(object):
    """Application Directory object."""

    def __init__(self, path=None):
        self.path = path
        self._exists = False

        if path:
            self._create()


    def __repr__(self):
        return '<app-dir: %s>' % (self.path)


    def __getattribute__(self, name):

        if not name in ('_exists', 'path', '_create', '_raise_if_none'):
            if not self._exists:
                self._create()
        return object.__getattribute__(self, name)


    def _raise_if_none(self):
        """Raises if operations are carried out on an unconfigured AppDir."""
        if not self.path:
            raise NotConfigured()


    def _create(self):
        """Creates current AppDir at AppDir.path."""

        self._raise_if_none()
        if not self._exists:
            mkdir_p(self.path)
            self._exists = True


    def open(self, filename, mode='r'):
        """Returns file object from given filename."""

        self._raise_if_none()
        fn = path_join(self.path, filename)

        return open(fn, mode)


    def write(self, filename, content, binary=False):
        """Writes given content to given filename."""
        self._raise_if_none()
        fn = path_join(self.path, filename)

        if binary:
            flags = 'wb'
        else:
            flags = 'w'


        with open(fn, flags) as f:
            f.write(content)


    def append(self, filename, content, binary=False):
        """Appends given content to given filename."""

        self._raise_if_none()
        fn = path_join(self.path, filename)

        if binary:
            flags = 'ab'
        else:
            flags = 'a'

        with open(fn, 'a') as f:
            f.write(content)
            return True

    def delete(self, filename=''):
        """Deletes given file or directory. If no filename is passed, current
        directory is removed.
        """
        self._raise_if_none()
        fn = path_join(self.path, filename)

        try:
            if isfile(fn):
                remove(fn)
            else:
                removedirs(fn)
        except OSError as why:
            if why.errno == errno.ENOENT:
                pass
            else:
                raise why


    def read(self, filename, binary=False):
        """Returns contents of given file with AppDir.
        If file doesn't exist, returns None."""

        self._raise_if_none()
        fn = path_join(self.path, filename)

        if binary:
            flags = 'br'
        else:
            flags = 'r'

        try:
            with open(fn, flags) as f:
                return f.read()
        except IOError:
            return None


    def sub(self, path):
        """Returns AppDir instance for given subdirectory name."""

        if is_collection(path):
            path = path_join(path)

        return AppDir(path_join(self.path, path))


# Module locals

user = AppDir()
site = AppDir()
cache = AppDir()
log = AppDir()


def init(vendor, name):

    global user, site, cache, log

    ad = AppDirs(name, vendor)

    user.path = ad.user_data_dir

    site.path = ad.site_data_dir
    cache.path = ad.user_cache_dir
    log.path = ad.user_log_dir


class NotConfigured(IOError):
    """Application configuration required. Please run resources.init() first."""
