# -*- coding: utf-8 -*-

"""
clint
~~~~~

This module sets up the main interface for all of clint.

"""


from __future__ import absolute_import

try:
    from collections import OrderedDict
except ImportError:
    from .packages.ordereddict import OrderedDict
    import collections
    collections.OrderedDict = OrderedDict

from .arguments import *
from . import textui
from . import utils
from .pipes import piped_in



__title__ = 'clint'
__version__ = '0.5.1'
__build__ = 0x000501
__author__ = 'Kenneth Reitz'
__license__ = 'ISC'
__copyright__ = 'Copyright 2012 Kenneth Reitz'
__docformat__ = 'restructuredtext'
