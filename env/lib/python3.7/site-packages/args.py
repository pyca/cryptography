# -*- coding: utf-8 -*-

"""
args
~~~~

This module provides the CLI argument interface for clint.

"""

import os
from sys import argv
from glob import glob
from collections import OrderedDict

def _expand_path(path):
    """Expands directories and globs in given path."""

    paths = []
    path = os.path.expanduser(path)
    path = os.path.expandvars(path)

    if os.path.isdir(path):

        for (dir, dirs, files) in os.walk(path):
            for file in files:
                paths.append(os.path.join(dir, file))
    else:
        paths.extend(glob(path))

    return paths


def _is_collection(obj):
    """Tests if an object is a collection. Strings don't count."""

    if isinstance(obj, basestring):
        return False

    return hasattr(obj, '__getitem__')



class ArgsList(object):
    """CLI Argument management."""

    def __init__(self, args=None, no_argv=False):
        if not args:
            if not no_argv:
                self._args = argv[1:]
            else:
                self._args = []
        else:
            self._args = args


    def __len__(self):
        return len(self._args)


    def __repr__(self):
        return '<args %s>' % (repr(self._args))


    def __getitem__(self, i):
        try:
            return self.all[i]
        except IndexError:
            return None


    def __contains__(self, x):
        return self.first(x) is not None


    def get(self, x):
        """Returns argument at given index, else none."""
        try:
            return self.all[x]
        except IndexError:
            return None


    def get_with(self, x):
        """Returns first argument that contains given string."""
        return self.all[self.first_with(x)]


    def remove(self, x):
        """Removes given arg (or list thereof) from Args object."""

        def _remove(x):
            found = self.first(x)
            if found is not None:
                self._args.pop(found)

        if _is_collection(x):
            for item in x:
                _remove(x)
        else:
            _remove(x)


    def pop(self, x):
        """Removes and Returns value at given index, else none."""
        try:
            return self._args.pop(x)
        except IndexError:
            return None


    def any_contain(self, x):
        """Tests if given string is contained in any stored argument."""

        return bool(self.first_with(x))


    def contains(self, x):
        """Tests if given object is in arguments list.
           Accepts strings and lists of strings."""

        return self.__contains__(x)


    def first(self, x):
        """Returns first found index of given value (or list of values)"""

        def _find( x):
            try:
                return self.all.index(str(x))
            except ValueError:
                return None

        if _is_collection(x):
            for item in x:
                found = _find(item)
                if found is not None:
                    return found
            return None
        else:
            return _find(x)


    def first_with(self, x):
        """Returns first found index containing value (or list of values)"""

        def _find(x):
            try:
                for arg in self.all:
                    if x in arg:
                        return self.all.index(arg)
            except ValueError:
                return None

        if _is_collection(x):
            for item in x:
                found = _find(item)
                if found:
                    return found
            return None
        else:
            return _find(x)


    def first_without(self, x):
        """Returns first found index not containing value (or list of values)"""

        def _find(x):
            try:
                for arg in self.all:
                    if x not in arg:
                        return self.all.index(arg)
            except ValueError:
                return None

        if _is_collection(x):
            for item in x:
                found = _find(item)
                if found:
                    return found
            return None
        else:
            return _find(x)


    def start_with(self, x):
           """Returns all arguments beginning with given string (or list thereof)"""

           _args = []

           for arg in self.all:
               if _is_collection(x):
                   for _x in x:
                       if arg.startswith(x):
                           _args.append(arg)
                           break
               else:
                   if arg.startswith(x):
                       _args.append(arg)

           return ArgsList(_args, no_argv=True)


    def contains_at(self, x, index):
        """Tests if given [list of] string is at given index."""

        try:
            if _is_collection(x):
                for _x in x:
                    if (_x in self.all[index]) or (_x == self.all[index]):
                        return True
                    else:
                        return False
            else:
                return (x in self.all[index])

        except IndexError:
            return False


    def has(self, x):
        """Returns true if argument exists at given index.
           Accepts: integer.
        """

        try:
            self.all[x]
            return True
        except IndexError:
            return False


    def value_after(self, x):
        """Returns value of argument after given found argument (or list thereof)."""

        try:
            try:
                i = self.all.index(x)
            except ValueError:
                return None

            return self.all[i + 1]

        except IndexError:
            return None


    @property
    def grouped(self):
        """Extracts --flag groups from argument list.
           Returns {format: Args, ...}
        """

        collection = OrderedDict(_=ArgsList(no_argv=True))

        _current_group = None

        for arg in self.all:
            if arg.startswith('-'):
                _current_group = arg
                collection.setdefault(arg, ArgsList(no_argv=True))
            else:
                if _current_group:
                    collection[_current_group]._args.append(arg)
                else:
                    collection['_']._args.append(arg)

        return collection


    @property
    def last(self):
        """Returns last argument."""

        try:
            return self.all[-1]
        except IndexError:
            return None


    @property
    def all(self):
        """Returns all arguments."""

        return self._args


    def all_with(self, x):
        """Returns all arguments containing given string (or list thereof)"""

        _args = []

        for arg in self.all:
            if _is_collection(x):
                for _x in x:
                    if _x in arg:
                        _args.append(arg)
                        break
            else:
                if x in arg:
                    _args.append(arg)

        return ArgsList(_args, no_argv=True)


    def all_without(self, x):
        """Returns all arguments not containing given string (or list thereof)"""

        _args = []

        for arg in self.all:
            if _is_collection(x):
                for _x in x:
                    if _x not in arg:
                        _args.append(arg)
                        break
            else:
                if x not in arg:
                    _args.append(arg)

        return ArgsList(_args, no_argv=True)


    @property
    def flags(self):
        """Returns Arg object including only flagged arguments."""

        return self.start_with('-')


    @property
    def not_flags(self):
        """Returns Arg object excluding flagged arguments."""

        return self.all_without('-')


    @property
    def files(self, absolute=False):
        """Returns an expanded list of all valid paths that were passed in."""

        _paths = []

        for arg in self.all:
            for path in _expand_path(arg):
                if os.path.exists(path):
                    if absolute:
                        _paths.append(os.path.abspath(path))
                    else:
                        _paths.append(path)

        return _paths


    @property
    def not_files(self):
        """Returns a list of all arguments that aren't files/globs."""

        _args = []

        for arg in self.all:
            if not len(_expand_path(arg)):
                if not os.path.exists(arg):
                    _args.append(arg)

        return ArgsList(_args, no_argv=True)

    @property
    def copy(self):
        """Returns a copy of Args object for temporary manipulation."""

        return ArgsList(self.all)


args = ArgsList()
get = args.get
get_with = args.get_with
remove = args.remove
pop = args.pop
any_contain = args.any_contain
contains = args.contains
first = args.first
first_with = args.first_with
first_without = args.first_without
start_with = args.start_with
contains_at = args.contains_at
has = args.has
value_after = args.value_after
grouped = args.grouped
last = args.last
all = args.all
all_with = args.all_with
all_without = args.all_without
flags = args.flags
not_flags = args.not_flags
files = args.files
not_files = args.not_files
copy = args.copy