# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import unittest

from . import test_classes


suite = unittest.TestSuite()
loader = unittest.TestLoader()
for test_class in test_classes():
    suite.addTest(loader.loadTestsFromTestCase(test_class))
unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
