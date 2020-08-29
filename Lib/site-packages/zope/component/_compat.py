##############################################################################
#
# Copyright (c) 2001, 2002 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################

import sys
import types

if sys.version_info[0] < 3: #pragma NO COVER

    import cPickle as _pickle

    CLASS_TYPES = (type, types.ClassType)

    PYTHON3 = False
    PYTHON2 = True

else: #pragma NO COVER

    import pickle as _pickle

    CLASS_TYPES = (type,)

    PYTHON3 = True
    PYTHON2 = False


# Prior to https://github.com/zopefoundation/zope.security/issues/71
# zope.security cannot be imported if zope.interface is enforcing
# strict resolution orders. But because zope.security has a dependency
# on this library, and older versions of this library also have problems
# with strict resolution orders, we have a chicken-and-egg scenario. In the
# interim, our only choice is to skip it. (But we don't want a hard dependency
# on zope.interface 5.0, so we do a conditional import.)
ZOPE_SECURITY_NOT_AVAILABLE_EX = (ImportError,)
try:
    from zope.interface.ro import InconsistentResolutionOrderError
except ImportError:
    pass
else:
    ZOPE_SECURITY_NOT_AVAILABLE_EX += (InconsistentResolutionOrderError,)
