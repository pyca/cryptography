#
# (C) Copyright 2014 Enthought, Inc., Austin, TX
# All right reserved.
#
# This file is open source software distributed according to the terms in
# LICENSE.txt
#
from __future__ import print_function
import os

if 'SHOW_TEST_ENV' in os.environ:
    import sys
    from win32ctypes.core import _backend
    is_64bits = sys.maxsize > 2**32
    print('=' * 30)
    print('Running on python: {} {}'.format(
        sys.version, '64bit' if is_64bits else '32bit'))
    print('The executable is: {}'.format(sys.executable))
    print('Using the {} backend'.format(_backend))
    print('=' * 30)
