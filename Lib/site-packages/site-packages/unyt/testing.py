"""
Utilities for writing tests

"""

# -----------------------------------------------------------------------------
# Copyright (c) 2018, yt Development Team.
#
# Distributed under the terms of the Modified BSD License.
#
# The full license is in the LICENSE file, distributed with this software.
# -----------------------------------------------------------------------------

import warnings

from unyt.array import allclose_units


def assert_allclose_units(actual, desired, rtol=1e-7, atol=0, **kwargs):
    """Raise an error if two objects are not equal up to desired tolerance

    This is a wrapper for :func:`numpy.testing.assert_allclose` that also
    verifies unit consistency

    Parameters
    ----------
    actual : array-like
        Array obtained (possibly with attached units)
    desired : array-like
        Array to compare with (possibly with attached units)
    rtol : float, optional
        Relative tolerance, defaults to 1e-7
    atol : float or quantity, optional
        Absolute tolerance. If units are attached, they must be consistent
        with the units of ``actual`` and ``desired``. If no units are attached,
        assumes the same units as ``desired``. Defaults to zero.

    See Also
    --------
    :func:`unyt.array.allclose_units`

    Notes
    -----
    Also accepts additional keyword arguments accepted by
    :func:`numpy.testing.assert_allclose`, see the documentation of that
    function for details.

    Examples
    --------
    >>> import unyt as u
    >>> actual = [1e-5, 1e-3, 1e-1]*u.m
    >>> desired = actual.to("cm")
    >>> assert_allclose_units(actual, desired)
    """
    if not allclose_units(actual, desired, rtol, atol, **kwargs):
        raise AssertionError


def _process_warning(op, message, warning_class, args=(), kwargs=None):
    if kwargs is None:
        kwargs = {}
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        op(*args, **kwargs)

        assert len(w) == 1
        assert issubclass(w[0].category, warning_class)
        assert str(w[0].message) == message
