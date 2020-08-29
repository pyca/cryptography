# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import unittest
import re


if sys.version_info < (3,):
    str_cls = unicode  # noqa
else:
    str_cls = str


_non_local = {'patched': False}


def patch():
    if sys.version_info >= (3, 0):
        return

    if _non_local['patched']:
        return

    if sys.version_info < (2, 7):
        unittest.TestCase.assertIsInstance = _assert_is_instance
        unittest.TestCase.assertRegex = _assert_regex
        unittest.TestCase.assertRaises = _assert_raises
        unittest.TestCase.assertRaisesRegex = _assert_raises_regex
        unittest.TestCase.assertGreaterEqual = _assert_greater_equal
        unittest.TestCase.assertLess = _assert_less
        unittest.TestCase.assertLessEqual = _assert_less_equal
        unittest.TestCase.assertIn = _assert_in
        unittest.TestCase.assertNotIn = _assert_not_in
    else:
        unittest.TestCase.assertRegex = unittest.TestCase.assertRegexpMatches
        unittest.TestCase.assertRaisesRegex = unittest.TestCase.assertRaisesRegexp
    _non_local['patched'] = True


def _safe_repr(obj):
    try:
        return repr(obj)
    except Exception:
        return object.__repr__(obj)


def _format_message(msg, standard_msg):
    return msg or standard_msg


def _assert_greater_equal(self, a, b, msg=None):
    if not a >= b:
        standard_msg = '%s not greater than or equal to %s' % (_safe_repr(a), _safe_repr(b))
        self.fail(_format_message(msg, standard_msg))


def _assert_less(self, a, b, msg=None):
    if not a < b:
        standard_msg = '%s not less than %s' % (_safe_repr(a), _safe_repr(b))
        self.fail(_format_message(msg, standard_msg))


def _assert_less_equal(self, a, b, msg=None):
    if not a <= b:
        standard_msg = '%s not less than or equal to %s' % (_safe_repr(a), _safe_repr(b))
        self.fail(_format_message(msg, standard_msg))


def _assert_is_instance(self, obj, cls, msg=None):
    if not isinstance(obj, cls):
        if not msg:
            msg = '%s is not an instance of %r' % (obj, cls)
        self.fail(msg)


def _assert_in(self, member, container, msg=None):
    if member not in container:
        standard_msg = '%s not found in %s' % (_safe_repr(member), _safe_repr(container))
        self.fail(_format_message(msg, standard_msg))


def _assert_not_in(self, member, container, msg=None):
    if member in container:
        standard_msg = '%s found in %s' % (_safe_repr(member), _safe_repr(container))
        self.fail(_format_message(msg, standard_msg))


def _assert_regex(self, text, expected_regexp, msg=None):
    """Fail the test unless the text matches the regular expression."""
    if isinstance(expected_regexp, str_cls):
        expected_regexp = re.compile(expected_regexp)
    if not expected_regexp.search(text):
        msg = msg or "Regexp didn't match"
        msg = '%s: %r not found in %r' % (msg, expected_regexp.pattern, text)
        self.fail(msg)


def _assert_raises(self, excClass, callableObj=None, *args, **kwargs):  # noqa
    context = _AssertRaisesContext(excClass, self)
    if callableObj is None:
        return context
    with context:
        callableObj(*args, **kwargs)


def _assert_raises_regex(self, expected_exception, expected_regexp, callable_obj=None, *args, **kwargs):
    if expected_regexp is not None:
        expected_regexp = re.compile(expected_regexp)
    context = _AssertRaisesContext(expected_exception, self, expected_regexp)
    if callable_obj is None:
        return context
    with context:
        callable_obj(*args, **kwargs)


class _AssertRaisesContext(object):
    def __init__(self, expected, test_case, expected_regexp=None):
        self.expected = expected
        self.failureException = test_case.failureException
        self.expected_regexp = expected_regexp

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        if exc_type is None:
            try:
                exc_name = self.expected.__name__
            except AttributeError:
                exc_name = str(self.expected)
            raise self.failureException(
                "{0} not raised".format(exc_name))
        if not issubclass(exc_type, self.expected):
            # let unexpected exceptions pass through
            return False
        self.exception = exc_value  # store for later retrieval
        if self.expected_regexp is None:
            return True

        expected_regexp = self.expected_regexp
        if not expected_regexp.search(str(exc_value)):
            raise self.failureException(
                '"%s" does not match "%s"' %
                (expected_regexp.pattern, str(exc_value))
            )
        return True
