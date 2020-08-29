"""
A set of convenient on-demand imports
"""

# -----------------------------------------------------------------------------
# Copyright (c) 2018, yt Development Team.
#
# Distributed under the terms of the Modified BSD License.
#
# The full license is in the LICENSE file, distributed with this software.
# -----------------------------------------------------------------------------


class NotAModule(object):
    """
    A class to implement an informative error message that will be outputted if
    someone tries to use an on-demand import without having the requisite
    package installed.
    """

    def __init__(self, pkg_name):
        self.pkg_name = pkg_name
        self.error = ImportError(
            "This functionality requires the %s "
            "package to be installed." % self.pkg_name
        )

    def __getattr__(self, item):
        raise self.error

    def __call__(self, *args, **kwargs):
        raise self.error


class astropy_imports(object):
    _name = "astropy"
    _log = None
    _units = None
    _version = None

    @property
    def log(self):
        if self._log is None:
            try:
                from astropy import log

                if log.exception_logging_enabled():
                    log.disable_exception_logging()
            except ImportError:
                log = NotAModule(self._name)
            self._log = log
        return self._log

    @property
    def units(self):
        if self._units is None:
            try:
                from astropy import units

                self.log
            except ImportError:
                units = NotAModule(self._name)
            self._units = units
        return self._units

    @property
    def __version__(self):
        if self._version is None:
            try:
                import astropy

                version = astropy.__version__
            except ImportError:
                version = NotAModule(self._name)
            self._version = version
        return self._version


_astropy = astropy_imports()


class h5py_imports(object):
    _name = "h5py"
    _File = None
    _version = None

    @property
    def File(self):
        if self._File is None:
            try:
                from h5py import File
            except ImportError:
                File = NotAModule(self._name)
            self._File = File
        return self._File

    @property
    def __version__(self):
        if self._version is None:
            try:
                from h5py import __version__

                self._version = __version__
            except ImportError:
                self._version = NotAModule(self._name)
        return self._version


_h5py = h5py_imports()


class pint_imports(object):
    _name = "pint"
    _UnitRegistry = None

    @property
    def UnitRegistry(self):
        if self._UnitRegistry is None:
            try:
                from pint import UnitRegistry
            except ImportError:
                UnitRegistry = NotAModule(self._name)
            self._UnitRegistry = UnitRegistry
        return self._UnitRegistry


_pint = pint_imports()


class matplotlib_imports(object):
    _name = "matplotlib"
    _pyplot = None
    _units = None
    _use = None

    @property
    def __version__(self):
        if self._version is None:
            try:
                from matplotlib import __version__

                self._version = __version__
            except ImportError:
                self._version = NotAModule(self._name)
        return self._version

    @property
    def pyplot(self):
        if self._pyplot is None:
            try:
                from matplotlib import pyplot
            except ImportError:
                pyplot = NotAModule(self._name)
            self._pyplot = pyplot
        return self._pyplot

    @property
    def units(self):
        if self._units is None:
            try:
                from matplotlib import units
            except ImportError:
                units = NotAModule(self._name)
            self._units = units
        return self._units

    @property
    def use(self):
        if self._use is None:
            try:
                from matplotlib import use
            except ImportError:
                use = NotAModule(self._name)
            self._use = use
        return self._use


_matplotlib = matplotlib_imports()
