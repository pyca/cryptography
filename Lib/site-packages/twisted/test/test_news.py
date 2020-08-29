# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Tests for L{twisted.news}.
"""

from twisted.trial.unittest import SynchronousTestCase
from twisted.python.compat import _PY3



class NewsDeprecationTestCase(SynchronousTestCase):
    """
    Tests for the deprecation of L{twisted.news}.
    """
    def test_deprecated(self):
        """
        L{twisted.news} is deprecated.
        """
        from twisted import news
        news
        warningsShown = self.flushWarnings([self.test_deprecated])
        self.assertEqual(len(warningsShown), 1)
        self.assertIs(warningsShown[0]['category'], DeprecationWarning)
        self.assertEqual(
            warningsShown[0]['message'],
            (
                'twisted.news was deprecated in Twisted 20.3.0: '
                'morituri nolumus mori'
            )
        )

    if _PY3:
        test_deprecated.skip = "Not relevant on Python 3"
