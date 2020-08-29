"""
Test unyt.testing module that contains utilities for writing tests.

"""

# ----------------------------------------------------------------------------
# Copyright (c) 2013, yt Development Team.
#
# Distributed under the terms of the Modified BSD License.
#
# The full license is in the file COPYING.txt, distributed with this software.
# ----------------------------------------------------------------------------

import pytest

from unyt.array import unyt_array, unyt_quantity
from unyt.testing import assert_allclose_units


def test_equality():
    a1 = unyt_array([1.0, 2.0, 3.0], "cm")
    a2 = unyt_array([1.0, 2.0, 3.0], "cm")
    assert_allclose_units(a1, a2)


def test_unequal_error():
    a1 = unyt_array([1.0, 2.0, 3.0], "cm")
    a2 = unyt_array([4.0, 5.0, 6.0], "cm")
    with pytest.raises(AssertionError):
        assert_allclose_units(a1, a2)


def test_conversion_error():
    a1 = unyt_array([1.0, 2.0, 3.0], "cm")
    a2 = unyt_array([1.0, 2.0, 3.0], "kg")
    with pytest.raises(AssertionError):
        assert_allclose_units(a1, a2)


def test_runtime_error():
    a1 = unyt_array([1.0, 2.0, 3.0], "cm")
    a2 = unyt_array([1.0, 2.0, 3.0], "cm")
    with pytest.raises(RuntimeError):
        assert_allclose_units(a1, a2, rtol=unyt_quantity(1e-7, "cm"))


def test_atol_conversion_error():
    a1 = unyt_array([1.0, 2.0, 3.0], "cm")
    a2 = unyt_array([1.0, 2.0, 3.0], "cm")
    with pytest.raises(AssertionError):
        assert_allclose_units(a1, a2, atol=unyt_quantity(0.0, "kg"))
