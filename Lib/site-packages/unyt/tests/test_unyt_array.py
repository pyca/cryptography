"""
Test ndarray subclass that handles symbolic units.




"""

# ----------------------------------------------------------------------------
# Copyright (c) 2013, yt Development Team.
#
# Distributed under the terms of the Modified BSD License.
#
# The full license is in the file COPYING.txt, distributed with this software.
# ----------------------------------------------------------------------------

import copy
import itertools
import math
import numpy as np
import operator
import os
import pickle
import pytest
import shutil
import tempfile
import warnings

from numpy.testing import (
    assert_array_equal,
    assert_equal,
    assert_array_almost_equal,
    assert_almost_equal,
)
from numpy import array
from unyt.array import (
    unyt_array,
    unyt_quantity,
    unary_operators,
    binary_operators,
    uconcatenate,
    ucross,
    udot,
    uintersect1d,
    unorm,
    ustack,
    uunion1d,
    uvstack,
    loadtxt,
    savetxt,
)
from unyt.exceptions import (
    InvalidUnitEquivalence,
    InvalidUnitOperation,
    IterableUnitCoercionError,
    UnitConversionError,
    UnitOperationError,
    UnitParseError,
    UnitsNotReducible,
)
from unyt.testing import assert_allclose_units, _process_warning
from unyt.unit_symbols import cm, m, g, degree
from unyt.unit_registry import UnitRegistry
from unyt._on_demand_imports import _astropy, _h5py, _pint, NotAModule
from unyt._physical_ratios import metallicity_sun, speed_of_light_cm_per_s
from unyt import dimensions, Unit


def operate_and_compare(a, b, op, answer):
    # Test generator for unyt_arrays tests
    assert_array_almost_equal(op(a, b), answer)


def assert_isinstance(a, type):
    assert isinstance(a, type)


def test_addition():
    """
    Test addition of two unyt_arrays

    """

    # Same units
    a1 = unyt_array([1, 2, 3], "cm")
    a2 = unyt_array([4, 5, 6], "cm")
    a3 = [4 * cm, 5 * cm, 6 * cm]
    answer = unyt_array([5, 7, 9], "cm")

    operate_and_compare(a1, a2, operator.add, answer)
    operate_and_compare(a2, a1, operator.add, answer)
    operate_and_compare(a1, a3, operator.add, answer)
    operate_and_compare(a3, a1, operator.add, answer)
    operate_and_compare(a2, a1, np.add, answer)
    operate_and_compare(a1, a2, np.add, answer)
    operate_and_compare(a1, a3, np.add, answer)
    operate_and_compare(a3, a1, np.add, answer)

    # different units
    a1 = unyt_array([1, 2, 3], "cm")
    a2 = unyt_array([4, 5, 6], "m")
    a3 = [4 * m, 5 * m, 6 * m]
    answer1 = unyt_array([401, 502, 603], "cm")
    answer2 = unyt_array([4.01, 5.02, 6.03], "m")

    operate_and_compare(a1, a2, operator.add, answer1)
    operate_and_compare(a2, a1, operator.add, answer2)
    operate_and_compare(a1, a3, operator.add, answer1)
    operate_and_compare(a3, a1, operator.add, answer2)
    operate_and_compare(a1, a2, np.add, answer1)
    operate_and_compare(a2, a1, np.add, answer2)
    operate_and_compare(a1, a3, np.add, answer1)
    operate_and_compare(a3, a1, np.add, answer2)

    # Test dimensionless quantities
    a1 = unyt_array([1, 2, 3])
    a2 = array([4, 5, 6])
    a3 = [4, 5, 6]
    answer = unyt_array([5, 7, 9])

    operate_and_compare(a1, a2, operator.add, answer)
    operate_and_compare(a2, a1, operator.add, answer)
    operate_and_compare(a1, a3, operator.add, answer)
    operate_and_compare(a3, a1, operator.add, answer)
    operate_and_compare(a1, a2, np.add, answer)
    operate_and_compare(a2, a1, np.add, answer)
    operate_and_compare(a1, a3, np.add, answer)
    operate_and_compare(a3, a1, np.add, answer)

    # Catch the different dimensions error
    a1 = unyt_array([1, 2, 3], "m")
    a2 = unyt_array([4, 5, 6], "kg")
    a3 = [7, 8, 9]
    a4 = unyt_array([10, 11, 12], "")

    with pytest.raises(UnitOperationError):
        operator.add(a1, a2)
    with pytest.raises(UnitOperationError):
        operator.iadd(a1, a2)
    with pytest.raises(UnitOperationError):
        operator.add(a1, a3)
    with pytest.raises(UnitOperationError):
        operator.iadd(a1, a3)
    with pytest.raises(UnitOperationError):
        operator.add(a3, a1)
    with pytest.raises(UnitOperationError):
        operator.iadd(a3, a1)
    with pytest.raises(UnitOperationError):
        operator.add(a1, a4)
    with pytest.raises(UnitOperationError):
        operator.iadd(a1, a4)
    with pytest.raises(UnitOperationError):
        operator.add(a4, a1)
    with pytest.raises(UnitOperationError):
        operator.iadd(a4, a1)

    # adding with zero is allowed irrespective of the units
    zeros = np.zeros(3)
    zeros_yta_dimless = unyt_array(zeros, "dimensionless")
    zeros_yta_length = unyt_array(zeros, "m")
    zeros_yta_mass = unyt_array(zeros, "kg")
    operands = [0, zeros, zeros_yta_length]

    for op in [operator.add, np.add]:
        for operand in operands:
            operate_and_compare(a1, operand, op, a1)
            operate_and_compare(operand, a1, op, a1)
            operate_and_compare(4 * m, operand, op, 4 * m)
            operate_and_compare(operand, 4 * m, op, 4 * m)

    operands = [
        unyt_quantity(0),
        unyt_quantity(0, "kg"),
        zeros_yta_dimless,
        zeros_yta_mass,
    ]

    for op in [operator.add, np.add]:
        for operand in operands:
            with pytest.raises(UnitOperationError):
                operate_and_compare(a1, operand, op, a1)
            with pytest.raises(UnitOperationError):
                operate_and_compare(operand, a1, op, a1)
            with pytest.raises(UnitOperationError):
                operate_and_compare(4 * m, operand, op, 4 * m)
            with pytest.raises(UnitOperationError):
                operate_and_compare(operand, 4 * m, op, 4 * m)


def test_subtraction():
    """
    Test subtraction of two unyt_arrays

    """

    # Same units
    a1 = unyt_array([1, 2, 3], "cm")
    a2 = unyt_array([4, 5, 6], "cm")
    a3 = [4 * cm, 5 * cm, 6 * cm]
    answer1 = unyt_array([-3, -3, -3], "cm")
    answer2 = unyt_array([3, 3, 3], "cm")

    operate_and_compare(a1, a2, operator.sub, answer1)
    operate_and_compare(a2, a1, operator.sub, answer2)
    operate_and_compare(a1, a3, operator.sub, answer1)
    operate_and_compare(a3, a1, operator.sub, answer2)
    operate_and_compare(a1, a2, np.subtract, answer1)
    operate_and_compare(a2, a1, np.subtract, answer2)
    operate_and_compare(a1, a3, np.subtract, answer1)
    operate_and_compare(a3, a1, np.subtract, answer2)

    # different units
    a1 = unyt_array([1, 2, 3], "cm")
    a2 = unyt_array([4, 5, 6], "m")
    a3 = [4 * m, 5 * m, 6 * m]
    answer1 = unyt_array([-399, -498, -597], "cm")
    answer2 = unyt_array([3.99, 4.98, 5.97], "m")
    answer3 = unyt_array([399, 498, 597], "cm")

    operate_and_compare(a1, a2, operator.sub, answer1)
    operate_and_compare(a2, a1, operator.sub, answer2)
    operate_and_compare(a1, a3, operator.sub, answer1)
    operate_and_compare(a3, a1, operator.sub, answer3)
    operate_and_compare(a1, a2, np.subtract, answer1)
    operate_and_compare(a2, a1, np.subtract, answer2)
    operate_and_compare(a1, a3, np.subtract, answer1)
    operate_and_compare(a3, a1, np.subtract, answer3)

    # Test dimensionless quantities
    a1 = unyt_array([1, 2, 3])
    a2 = array([4, 5, 6])
    a3 = [4, 5, 6]
    answer1 = unyt_array([-3, -3, -3])
    answer2 = unyt_array([3, 3, 3])

    operate_and_compare(a1, a2, operator.sub, answer1)
    operate_and_compare(a2, a1, operator.sub, answer2)
    operate_and_compare(a1, a3, operator.sub, answer1)
    operate_and_compare(a3, a1, operator.sub, answer2)
    operate_and_compare(a1, a2, np.subtract, answer1)
    operate_and_compare(a2, a1, np.subtract, answer2)
    operate_and_compare(a1, a3, np.subtract, answer1)
    operate_and_compare(a3, a1, np.subtract, answer2)

    # Catch the different dimensions error
    a1 = unyt_array([1, 2, 3], "m")
    a2 = unyt_array([4, 5, 6], "kg")
    a3 = [7, 8, 9]
    a4 = unyt_array([10, 11, 12], "")

    with pytest.raises(UnitOperationError):
        operator.sub(a1, a2)
    with pytest.raises(UnitOperationError):
        operator.isub(a1, a2)
    with pytest.raises(UnitOperationError):
        operator.sub(a1, a3)
    with pytest.raises(UnitOperationError):
        operator.isub(a1, a3)
    with pytest.raises(UnitOperationError):
        operator.sub(a3, a1)
    with pytest.raises(UnitOperationError):
        operator.isub(a3, a1)
    with pytest.raises(UnitOperationError):
        operator.sub(a1, a4)
    with pytest.raises(UnitOperationError):
        operator.isub(a1, a4)
    with pytest.raises(UnitOperationError):
        operator.sub(a4, a1)
    with pytest.raises(UnitOperationError):
        operator.isub(a4, a1)

    # subtracting with zero is allowed irrespective of the units
    zeros = np.zeros(3)
    zeros_yta_dimless = unyt_array(zeros, "dimensionless")
    zeros_yta_length = unyt_array(zeros, "m")
    zeros_yta_mass = unyt_array(zeros, "kg")
    operands = [0, zeros, zeros_yta_length]

    for op in [operator.sub, np.subtract]:
        for operand in operands:
            operate_and_compare(a1, operand, op, a1)
            operate_and_compare(operand, a1, op, -a1)
            operate_and_compare(4 * m, operand, op, 4 * m)
            operate_and_compare(operand, 4 * m, op, -4 * m)

    operands = [
        unyt_quantity(0),
        unyt_quantity(0, "kg"),
        zeros_yta_dimless,
        zeros_yta_mass,
    ]

    for op in [operator.sub, np.subtract]:
        for operand in operands:
            with pytest.raises(UnitOperationError):
                operate_and_compare(a1, operand, op, a1)
            with pytest.raises(UnitOperationError):
                operate_and_compare(operand, a1, op, -a1)
            with pytest.raises(UnitOperationError):
                operate_and_compare(4 * m, operand, op, 4 * m)
            with pytest.raises(UnitOperationError):
                operate_and_compare(operand, 4 * m, op, -4 * m)


def test_multiplication():
    """
    Test multiplication of two unyt_arrays

    """

    # Same units
    a1 = unyt_array([1, 2, 3], "cm")
    a2 = unyt_array([4, 5, 6], "cm")
    a3 = [4 * cm, 5 * cm, 6 * cm]
    answer = unyt_array([4, 10, 18], "cm**2")

    operate_and_compare(a1, a2, operator.mul, answer)
    operate_and_compare(a2, a1, operator.mul, answer)
    operate_and_compare(a1, a3, operator.mul, answer)
    operate_and_compare(a3, a1, operator.mul, answer)
    operate_and_compare(a1, a2, np.multiply, answer)
    operate_and_compare(a2, a1, np.multiply, answer)
    operate_and_compare(a1, a3, np.multiply, answer)
    operate_and_compare(a3, a1, np.multiply, answer)

    # different units, same dimension
    a1 = unyt_array([1, 2, 3], "cm")
    a2 = unyt_array([4, 5, 6], "m")
    a3 = [4 * m, 5 * m, 6 * m]
    answer1 = unyt_array([400, 1000, 1800], "cm**2")
    answer2 = unyt_array([0.04, 0.10, 0.18], "m**2")
    answer3 = unyt_array([4, 10, 18], "cm*m")

    operate_and_compare(a1, a2, operator.mul, answer1)
    operate_and_compare(a2, a1, operator.mul, answer2)
    operate_and_compare(a1, a3, operator.mul, answer1)
    operate_and_compare(a3, a1, operator.mul, answer2)
    operate_and_compare(a1, a2, np.multiply, answer3)
    operate_and_compare(a2, a1, np.multiply, answer3)
    operate_and_compare(a1, a3, np.multiply, answer3)
    operate_and_compare(a3, a1, np.multiply, answer3)

    # different dimensions
    a1 = unyt_array([1, 2, 3], "cm")
    a2 = unyt_array([4, 5, 6], "g")
    a3 = [4 * g, 5 * g, 6 * g]
    answer = unyt_array([4, 10, 18], "cm*g")

    operate_and_compare(a1, a2, operator.mul, answer)
    operate_and_compare(a2, a1, operator.mul, answer)
    operate_and_compare(a1, a3, operator.mul, answer)
    operate_and_compare(a3, a1, operator.mul, answer)
    operate_and_compare(a1, a2, np.multiply, answer)
    operate_and_compare(a2, a1, np.multiply, answer)
    operate_and_compare(a1, a3, np.multiply, answer)
    operate_and_compare(a3, a1, np.multiply, answer)

    # One dimensionless, one unitful
    a1 = unyt_array([1, 2, 3], "cm")
    a2 = array([4, 5, 6])
    a3 = [4, 5, 6]
    answer = unyt_array([4, 10, 18], "cm")

    operate_and_compare(a1, a2, operator.mul, answer)
    operate_and_compare(a2, a1, operator.mul, answer)
    operate_and_compare(a1, a3, operator.mul, answer)
    operate_and_compare(a3, a1, operator.mul, answer)
    operate_and_compare(a1, a2, np.multiply, answer)
    operate_and_compare(a2, a1, np.multiply, answer)
    operate_and_compare(a1, a3, np.multiply, answer)
    operate_and_compare(a3, a1, np.multiply, answer)

    # Both dimensionless quantities
    a1 = unyt_array([1, 2, 3])
    a2 = array([4, 5, 6])
    a3 = [4, 5, 6]
    answer = unyt_array([4, 10, 18])

    operate_and_compare(a1, a2, operator.mul, answer)
    operate_and_compare(a2, a1, operator.mul, answer)
    operate_and_compare(a1, a3, operator.mul, answer)
    operate_and_compare(a3, a1, operator.mul, answer)
    operate_and_compare(a1, a2, np.multiply, answer)
    operate_and_compare(a2, a1, np.multiply, answer)
    operate_and_compare(a1, a3, np.multiply, answer)
    operate_and_compare(a3, a1, np.multiply, answer)


def test_division():
    """
    Test multiplication of two unyt_arrays

    """

    # Same units
    a1 = unyt_array([1.0, 2.0, 3.0], "cm")
    a2 = unyt_array([4.0, 5.0, 6.0], "cm")
    a3 = [4 * cm, 5 * cm, 6 * cm]
    answer1 = unyt_array([0.25, 0.4, 0.5])
    answer2 = unyt_array([4, 2.5, 2])
    op = operator.truediv

    operate_and_compare(a1, a2, op, answer1)
    operate_and_compare(a2, a1, op, answer2)
    operate_and_compare(a1, a3, op, answer1)
    operate_and_compare(a3, a1, op, answer2)
    operate_and_compare(a1, a2, np.divide, answer1)
    operate_and_compare(a2, a1, np.divide, answer2)
    operate_and_compare(a1, a3, np.divide, answer1)
    operate_and_compare(a3, a1, np.divide, answer2)

    # different units, same dimension
    a1 = unyt_array([1.0, 2.0, 3.0], "cm")
    a2 = unyt_array([4.0, 5.0, 6.0], "m")
    a3 = [4 * m, 5 * m, 6 * m]
    answer1 = unyt_array([0.0025, 0.004, 0.005])
    answer2 = unyt_array([400, 250, 200])

    operate_and_compare(a1, a2, op, answer1)
    operate_and_compare(a2, a1, op, answer2)
    operate_and_compare(a1, a3, op, answer1)
    operate_and_compare(a3, a1, op, answer2)
    operate_and_compare(a1, a2, np.divide, answer1)
    operate_and_compare(a2, a1, np.divide, answer2)
    operate_and_compare(a1, a3, np.divide, answer1)
    operate_and_compare(a3, a1, np.divide, answer2)

    # different dimensions
    a1 = unyt_array([1.0, 2.0, 3.0], "cm")
    a2 = unyt_array([4.0, 5.0, 6.0], "g")
    a3 = [4 * g, 5 * g, 6 * g]
    answer1 = unyt_array([0.25, 0.4, 0.5], "cm/g")
    answer2 = unyt_array([4, 2.5, 2], "g/cm")

    operate_and_compare(a1, a2, op, answer1)
    operate_and_compare(a2, a1, op, answer2)
    operate_and_compare(a1, a3, op, answer1)
    operate_and_compare(a3, a1, op, answer2)
    operate_and_compare(a1, a2, np.divide, answer1)
    operate_and_compare(a2, a1, np.divide, answer2)
    operate_and_compare(a1, a3, np.divide, answer1)
    operate_and_compare(a3, a1, np.divide, answer2)

    # One dimensionless, one unitful
    a1 = unyt_array([1.0, 2.0, 3.0], "cm")
    a2 = array([4.0, 5.0, 6.0])
    a3 = [4, 5, 6]
    answer1 = unyt_array([0.25, 0.4, 0.5], "cm")
    answer2 = unyt_array([4, 2.5, 2], "1/cm")

    operate_and_compare(a1, a2, op, answer1)
    operate_and_compare(a2, a1, op, answer2)
    operate_and_compare(a1, a3, op, answer1)
    operate_and_compare(a3, a1, op, answer2)
    operate_and_compare(a1, a2, np.divide, answer1)
    operate_and_compare(a2, a1, np.divide, answer2)
    operate_and_compare(a1, a3, np.divide, answer1)
    operate_and_compare(a3, a1, np.divide, answer2)

    # Both dimensionless quantities
    a1 = unyt_array([1.0, 2.0, 3.0])
    a2 = array([4.0, 5.0, 6.0])
    a3 = [4, 5, 6]
    answer1 = unyt_array([0.25, 0.4, 0.5])
    answer2 = unyt_array([4, 2.5, 2])

    operate_and_compare(a1, a2, op, answer1)
    operate_and_compare(a2, a1, op, answer2)
    operate_and_compare(a1, a3, op, answer1)
    operate_and_compare(a3, a1, op, answer2)
    operate_and_compare(a1, a3, np.divide, answer1)
    operate_and_compare(a3, a1, np.divide, answer2)
    operate_and_compare(a1, a3, np.divide, answer1)
    operate_and_compare(a3, a1, np.divide, answer2)


def test_power():
    """
    Test power operator ensure units are correct.

    """

    from unyt import cm

    cm_arr = np.array([1.0, 1.0]) * cm

    assert_equal((1 * cm) ** 3, unyt_quantity(1, "cm**3"))
    assert_equal(np.power((1 * cm), 3), unyt_quantity(1, "cm**3"))
    assert_equal((1 * cm) ** unyt_quantity(3), unyt_quantity(1, "cm**3"))
    with pytest.raises(UnitOperationError):
        np.power((1 * cm), unyt_quantity(3, "g"))
    with pytest.raises(InvalidUnitOperation):
        np.power(cm, cm)

    assert_equal(cm_arr ** 3, unyt_array([1, 1], "cm**3"))
    assert_equal(np.power(cm_arr, 3), unyt_array([1, 1], "cm**3"))
    assert_equal(cm_arr ** unyt_quantity(3), unyt_array([1, 1], "cm**3"))
    with pytest.raises(UnitOperationError):
        np.power(cm_arr, unyt_quantity(3, "g"))

    try:
        np.power(cm_arr, unyt_quantity(3, "g"))
    except UnitOperationError as err:
        assert isinstance(err.unit1, Unit)
        assert isinstance(err.unit2, Unit)


def test_comparisons():
    """
    Test numpy ufunc comparison operators for unit consistency.

    """
    from unyt.array import unyt_array

    a1 = unyt_array([1, 2, 3], "cm")
    a2 = unyt_array([2, 1, 3], "cm")
    a3 = unyt_array([0.02, 0.01, 0.03], "m")
    a4 = unyt_array([1, 2, 3], "g")
    dimless = np.array([2, 1, 3])

    ops = (np.less, np.less_equal, np.greater, np.greater_equal, np.equal, np.not_equal)

    answers = (
        [True, False, False],
        [True, False, True],
        [False, True, False],
        [False, True, True],
        [False, False, True],
        [True, True, False],
    )

    for op, answer in zip(ops, answers):
        operate_and_compare(a1, a2, op, answer)
    for op, answer in zip(ops, answers):
        operate_and_compare(a1, dimless, op, answer)

    for op, answer in zip(ops, answers):
        operate_and_compare(a1, a3, op, answer)

    for op, answer in zip(ops, answers):
        operate_and_compare(a1, a3.in_units("cm"), op, answer)

    # Check that comparisons with dimensionless quantities work in both
    # directions.
    operate_and_compare(a3, dimless, np.less, [True, True, True])
    operate_and_compare(dimless, a3, np.less, [False, False, False])
    assert_equal(a1 < 2, [True, False, False])
    assert_equal(a1 < 2, np.less(a1, 2))
    assert_equal(2 < a1, [False, False, True])
    assert_equal(2 < a1, np.less(2, a1))

    # Check that comparisons with arrays that have different units with
    # different dimensions work properly
    operate_and_compare(a1, a4, np.equal, [False, False, False])
    operate_and_compare(a1, a4, np.not_equal, [True, True, True])

    # check that comparing quantities returns bools and not 0-D arrays
    el1, el4 = a1[0], a4[0]
    assert (el1 == el4) is False
    assert (el1 != el4) is True

    # comparisons that aren't == and !=
    with pytest.raises(UnitOperationError):
        np.greater(a1, a4)
    with pytest.raises(UnitOperationError):
        a1 > a4
    with pytest.raises(UnitOperationError):
        np.greater(el1, el4)
    with pytest.raises(UnitOperationError):
        el1 > el4


def test_unit_conversions():
    """
    Test operations that convert to different units or cast to ndarray

    """
    from unyt.array import unyt_quantity
    from unyt.unit_object import Unit

    km = unyt_quantity(1.0, "km", dtype="float64")
    km_in_cm = km.in_units("cm")
    cm_unit = Unit("cm")
    kpc_unit = Unit("kpc")

    assert_equal(km_in_cm, km)
    assert_equal(km_in_cm.in_cgs(), 1e5)
    assert_equal(km_in_cm.in_mks(), 1e3)
    assert_equal(km_in_cm.units, cm_unit)

    km_view = km.ndarray_view()
    km.convert_to_units("cm")
    assert km_view.base is km.base

    assert_equal(km, unyt_quantity(1, "km"))
    assert_equal(km.in_cgs(), 1e5)
    assert_equal(km.in_mks(), 1e3)
    assert_equal(km.units, cm_unit)

    km.convert_to_units("kpc")
    assert km_view.base is km.base

    assert_array_almost_equal(km, unyt_quantity(1, "km"))
    assert_array_almost_equal(km.in_cgs(), unyt_quantity(1e5, "cm"))
    assert_array_almost_equal(km.in_mks(), unyt_quantity(1e3, "m"))
    assert_equal(km.units, kpc_unit)

    assert_isinstance(km.to_ndarray(), np.ndarray)
    assert_isinstance(km.ndarray_view(), np.ndarray)

    dyne = unyt_quantity(1.0, "dyne")

    assert_equal(dyne.in_cgs(), dyne)
    assert_equal(dyne.in_cgs(), 1.0)
    assert_equal(dyne.in_mks(), dyne)
    assert_equal(dyne.in_mks(), 1e-5)
    assert_equal(str(dyne.in_mks().units), "N")
    assert_equal(str(dyne.in_cgs().units), "dyn")

    em3 = unyt_quantity(1.0, "erg/m**3")

    assert_equal(em3.in_cgs(), em3)
    assert_equal(em3.in_cgs(), 1e-6)
    assert_equal(em3.in_mks(), em3)
    assert_equal(em3.in_mks(), 1e-7)
    assert_equal(str(em3.in_mks().units), "Pa")
    assert_equal(str(em3.in_cgs().units), "dyn/cm**2")

    em3_converted = unyt_quantity(1545436840.386756, "Msun/(Myr**2*kpc)")
    assert_equal(em3.in_base(unit_system="galactic"), em3)
    assert_array_almost_equal(em3.in_base(unit_system="galactic"), em3_converted)
    assert_equal(str(em3.in_base(unit_system="galactic").units), "Msun/(Myr**2*kpc)")

    dimless = unyt_quantity(1.0, "")
    assert_equal(dimless.in_cgs(), dimless)
    assert_equal(dimless.in_cgs(), 1.0)
    assert_equal(dimless.in_mks(), dimless)
    assert_equal(dimless.in_mks(), 1.0)
    assert_equal(str(dimless.in_cgs().units), "dimensionless")

    kg = unyt_quantity(1.0, "kg")
    assert kg.to(g).v == 1000
    assert kg.in_units(g).v == 1000
    kg.convert_to_units(g)
    assert kg.v == 1000

    ten_grams = 10 * g
    assert kg.to(ten_grams).v == 100
    assert kg.in_units(ten_grams).v == 100
    kg.convert_to_units(ten_grams)
    assert kg.v == 100

    with pytest.raises(UnitParseError):
        kg.to([1, 2] * g)

    with pytest.raises(UnitParseError):
        kg.in_units([1, 2] * g)

    with pytest.raises(UnitParseError):
        kg.convert_to_units([1, 2] * g)


def test_temperature_conversions():
    """
    Test conversions between various supported temperatue scales.

    Also ensure we only allow compound units with temperature
    scales that have a proper zero point.

    """
    from unyt.unit_object import InvalidUnitOperation

    km = unyt_quantity(1, "km", dtype="float64")
    balmy = unyt_quantity(300, "K", dtype="float64")
    balmy_F = unyt_quantity(80.33, "degF")
    balmy_C = unyt_quantity(26.85, "degC")
    balmy_R = unyt_quantity(540, "R")

    assert_array_almost_equal(balmy.in_units("degF").d, balmy_F.d)
    assert balmy.in_units("degF").units, balmy_F.units
    assert_array_almost_equal(balmy.in_units("degC").d, balmy_C.d)
    assert balmy.in_units("degC").units, balmy_C.units
    assert_array_almost_equal(balmy.in_units("R").d, balmy_R.d)
    assert balmy.in_units("R").units == balmy_R.units

    balmy_view = balmy.ndarray_view()

    balmy.convert_to_units("degF")
    assert balmy_view.base is balmy.base
    assert_array_almost_equal(np.array(balmy), np.array(balmy_F))

    balmy.convert_to_units("degC")
    assert balmy_view.base is balmy.base
    assert_array_almost_equal(np.array(balmy), np.array(balmy_C))

    balmy.convert_to_units("R")
    assert balmy_view.base is balmy.base
    assert_array_almost_equal(np.array(balmy), np.array(balmy_R))

    balmy.convert_to_units("degF")
    assert balmy_view.base is balmy.base
    assert_array_almost_equal(np.array(balmy), np.array(balmy_F))

    with pytest.raises(InvalidUnitOperation):
        np.multiply(balmy, km)
    with pytest.raises(InvalidUnitOperation):
        np.multiply(balmy, balmy)
    with pytest.raises(InvalidUnitOperation):
        np.multiply(balmy_F, balmy_F)
    with pytest.raises(InvalidUnitOperation):
        np.multiply(balmy_F, balmy_C)
    with pytest.raises(InvalidUnitOperation):
        np.divide(balmy, balmy)
    with pytest.raises(InvalidUnitOperation):
        np.divide(balmy_F, balmy_F)
    with pytest.raises(InvalidUnitOperation):
        np.divide(balmy_F, balmy_C)
    with pytest.raises(InvalidUnitOperation):
        balmy * km
    with pytest.raises(InvalidUnitOperation):
        balmy * balmy
    with pytest.raises(InvalidUnitOperation):
        balmy_F * balmy_F
    with pytest.raises(InvalidUnitOperation):
        balmy_F * balmy_C
    with pytest.raises(InvalidUnitOperation):
        2 * balmy_F
    with pytest.raises(InvalidUnitOperation):
        balmy / balmy
    with pytest.raises(InvalidUnitOperation):
        balmy_F / balmy_F
    with pytest.raises(InvalidUnitOperation):
        balmy_F / balmy_C
    assert np.add(balmy_F, balmy_F) == unyt_quantity(80.33 * 2, "degF")
    with pytest.raises(InvalidUnitOperation):
        np.add(balmy_F, balmy_C)
    with pytest.raises(InvalidUnitOperation):
        balmy_F + balmy_C
    assert_equal(np.subtract(balmy_C, balmy_C), unyt_quantity(0, "degC"))
    with pytest.raises(InvalidUnitOperation):
        np.subtract(balmy_F, balmy_C)
    with pytest.raises(InvalidUnitOperation):
        balmy_F - balmy_C

    # Does CGS conversion from F to K work?
    assert_array_almost_equal(balmy.in_cgs(), unyt_quantity(300, "K"))


def test_unyt_array_unyt_quantity_ops():
    """
    Test operations that combine unyt_array and unyt_quantity
    """
    a = unyt_array(range(10, 1), "cm")
    b = unyt_quantity(5, "g")

    assert_isinstance(a * b, unyt_array)
    assert_isinstance(b * a, unyt_array)

    assert_isinstance(a / b, unyt_array)
    assert_isinstance(b / a, unyt_array)

    assert_isinstance(a * a, unyt_array)
    assert_isinstance(a / a, unyt_array)

    assert_isinstance(b * b, unyt_quantity)
    assert_isinstance(b / b, unyt_quantity)


def test_selecting():
    """
    Test slicing of two unyt_arrays

    """
    a = unyt_array(range(10), "cm")
    a_slice = a[:3]
    a_fancy_index = a[[1, 1, 3, 5]]
    a_array_fancy_index = a[array([[1, 1], [3, 5]])]
    a_boolean_index = a[a > 5]
    a_selection = a[0]

    assert_array_equal(a_slice, unyt_array([0, 1, 2], "cm"))
    assert_equal(a_slice.units, a.units)
    assert_array_equal(a_fancy_index, unyt_array([1, 1, 3, 5], "cm"))
    assert_equal(a_fancy_index.units, a.units)
    assert_array_equal(a_array_fancy_index, unyt_array([[1, 1], [3, 5]], "cm"))
    assert_equal(a_array_fancy_index.units, a.units)
    assert_array_equal(a_boolean_index, unyt_array([6, 7, 8, 9], "cm"))
    assert_equal(a_boolean_index.units, a.units)
    assert_isinstance(a_selection, unyt_quantity)
    assert_equal(a_selection.units, a.units)

    # .base points to the original array for a numpy view.  If it is not a
    # view, .base is None.
    assert a_slice.base is a


def test_iteration():
    """
    Test that iterating over a unyt_array returns a sequence of unyt_quantity
    instances
    """
    a = np.arange(3)
    b = unyt_array(np.arange(3), "cm")
    for ia, ib in zip(a, b):
        assert_equal(ia, ib.value)
        assert_equal(ib.units, b.units)


def test_ytarray_pickle():
    test_data = [unyt_quantity(12.0, "cm"), unyt_array([1, 2, 3], "km")]

    for data in test_data:
        tempf = tempfile.NamedTemporaryFile(delete=False)
        pickle.dump(data, tempf)
        tempf.close()

        with open(tempf.name, "rb") as fname:
            loaded_data = pickle.load(fname)
        os.unlink(tempf.name)

        assert_array_equal(data, loaded_data)
        assert_equal(data.units, loaded_data.units)
        assert_array_equal(array(data.in_cgs()), array(loaded_data.in_cgs()))
        assert_equal(float(data.units.base_value), float(loaded_data.units.base_value))


def test_copy():
    quan = unyt_quantity(1, "g")
    arr = unyt_array([1, 2, 3], "cm")

    assert_equal(copy.copy(quan), quan)
    assert_array_equal(copy.copy(arr), arr)

    assert_equal(copy.deepcopy(quan), quan)
    assert_array_equal(copy.deepcopy(arr), arr)

    memo = {}
    assert_equal(copy.deepcopy(quan, memo), quan)
    assert_array_equal(copy.deepcopy(arr), arr)

    assert_equal(quan.copy(), quan)
    assert_array_equal(arr.copy(), arr)

    assert_equal(np.copy(quan), quan)
    assert_array_equal(np.copy(arr), arr)


# needed so the tests function on older numpy versions that have
# different sets of ufuncs
def yield_np_ufuncs(ufunc_list):
    for u in ufunc_list:
        ufunc = getattr(np, u, None)
        if ufunc is not None:
            yield ufunc


def unary_ufunc_comparison(ufunc, a):
    out = a.copy()
    a_array = a.to_ndarray()
    if ufunc in (np.isreal, np.iscomplex):
        # According to the numpy docs, these two explicitly do not do
        # in-place copies.
        ret = ufunc(a)
        assert not hasattr(ret, "units")
        assert_array_equal(ret, ufunc(a))
    elif ufunc in yield_np_ufuncs(
        [
            "exp",
            "exp2",
            "log",
            "log2",
            "log10",
            "expm1",
            "log1p",
            "sin",
            "cos",
            "tan",
            "arcsin",
            "arccos",
            "arctan",
            "sinh",
            "cosh",
            "tanh",
            "arccosh",
            "arcsinh",
            "arctanh",
            "deg2rad",
            "rad2deg",
            "isfinite",
            "isinf",
            "isnan",
            "signbit",
            "sign",
            "rint",
            "logical_not",
        ]
    ):
        # These operations should return identical results compared to numpy.
        with np.errstate(invalid="ignore"):
            ret = ufunc(a, out=out)

            assert_array_equal(ret, out)
            assert_array_equal(ret, ufunc(a_array))
            # In-place copies do not drop units.
            assert hasattr(out, "units")
            assert not hasattr(ret, "units")
    elif ufunc in yield_np_ufuncs(
        [
            "absolute",
            "fabs",
            "conjugate",
            "floor",
            "ceil",
            "trunc",
            "negative",
            "spacing",
            "positive",
        ]
    ):

        ret = ufunc(a, out=out)

        assert_array_equal(ret, out)
        assert_array_equal(ret.to_ndarray(), ufunc(a_array))
        assert ret.units == out.units
    elif ufunc in yield_np_ufuncs(["ones_like", "square", "sqrt", "reciprocal"]):
        if ufunc is np.ones_like:
            ret = ufunc(a)
        else:
            with np.errstate(invalid="ignore"):
                ret = ufunc(a, out=out)
            assert_array_equal(ret, out)

        with np.errstate(invalid="ignore"):
            assert_array_equal(ret.to_ndarray(), ufunc(a_array))
        if ufunc is np.square:
            assert out.units == a.units ** 2
            assert ret.units == a.units ** 2
        elif ufunc is np.sqrt:
            assert out.units == a.units ** 0.5
            assert ret.units == a.units ** 0.5
        elif ufunc is np.reciprocal:
            assert out.units == a.units ** -1
            assert ret.units == a.units ** -1
    elif ufunc is np.modf:
        ret1, ret2 = ufunc(a)
        npret1, npret2 = ufunc(a_array)

        assert_array_equal(ret1.to_ndarray(), npret1)
        assert_array_equal(ret2.to_ndarray(), npret2)
    elif ufunc is np.frexp:
        ret1, ret2 = ufunc(a)
        npret1, npret2 = ufunc(a_array)

        assert_array_equal(ret1, npret1)
        assert_array_equal(ret2, npret2)
    elif ufunc is np.invert:
        with pytest.raises(TypeError):
            ufunc(a.astype("int64"))
    elif hasattr(np, "isnat") and ufunc is np.isnat:
        # numpy 1.13 raises ValueError, numpy 1.14 and newer raise TypeError
        with pytest.raises((TypeError, ValueError)):
            ufunc(a)
    # no untested ufuncs
    assert ufunc in yield_np_ufuncs(
        [
            "isreal",
            "iscomplex",
            "exp",
            "exp2",
            "log",
            "log2",
            "log10",
            "expm1",
            "log1p",
            "sin",
            "cos",
            "tan",
            "arcsin",
            "arccos",
            "arctan",
            "sinh",
            "cosh",
            "tanh",
            "arccosh",
            "arcsinh",
            "arctanh",
            "deg2rad",
            "rad2deg",
            "isfinite",
            "isinf",
            "isnan",
            "signbit",
            "sign",
            "rint",
            "logical_not",
            "absolute",
            "fabs",
            "conjugate",
            "floor",
            "ceil",
            "trunc",
            "negative",
            "spacing",
            "positive",
            "ones_like",
            "square",
            "sqrt",
            "reciprocal",
            "invert",
            "isnat",
            "modf",
            "frexp",
        ]
    )


def binary_ufunc_comparison(ufunc, a, b):
    if ufunc in [np.divmod]:
        out = (b.copy(), b.copy())
    else:
        out = b.copy()
    if ufunc in yield_np_ufuncs(
        [
            "add",
            "subtract",
            "remainder",
            "fmod",
            "mod",
            "arctan2",
            "hypot",
            "greater",
            "greater_equal",
            "less",
            "less_equal",
            "logical_and",
            "logical_or",
            "logical_xor",
            "maximum",
            "minimum",
            "fmax",
            "fmin",
            "nextafter",
            "heaviside",
        ]
    ):
        if a.units != b.units and a.units.dimensions != b.units.dimensions:
            with pytest.raises(UnitOperationError):
                ufunc(a, b)
            return
    if ufunc in yield_np_ufuncs(
        [
            "bitwise_and",
            "bitwise_or",
            "bitwise_xor",
            "left_shift",
            "right_shift",
            "ldexp",
        ]
    ):
        with pytest.raises(TypeError):
            ufunc(a, b)
        return

    ret = ufunc(a, b, out=out)
    ret = ufunc(a, b)

    if ufunc is np.multiply:
        assert ret.units == (a.units * b.units).simplify().as_coeff_unit()[1]
    elif ufunc in (np.divide, np.true_divide, np.arctan2):
        assert ret.units.dimensions == (a.units / b.units).dimensions
    elif ufunc in (
        np.greater,
        np.greater_equal,
        np.less,
        np.less_equal,
        np.not_equal,
        np.equal,
        np.logical_and,
        np.logical_or,
        np.logical_xor,
    ):
        assert not isinstance(ret, unyt_array) and isinstance(ret, np.ndarray)
    if isinstance(ret, tuple):
        assert isinstance(out, tuple)
        assert len(out) == len(ret)
        for o, r in zip(out, ret):
            assert_array_equal(r, o)
    else:
        assert_array_equal(ret, out)
    if ufunc in (np.divide, np.true_divide, np.arctan2) and (
        a.units.dimensions == b.units.dimensions
    ):
        assert_array_almost_equal(
            np.array(ret), ufunc(np.array(a.in_cgs()), np.array(b.in_cgs()))
        )


def test_ufuncs():
    for ufunc in unary_operators:
        unary_ufunc_comparison(
            ufunc, unyt_array([0.3, 0.4, 0.5], "cm", dtype="float64")
        )
        unary_ufunc_comparison(ufunc, unyt_array([12, 23, 47], "g", dtype="float64"))
        unary_ufunc_comparison(
            ufunc, unyt_array([2, 4, -6], "erg/m**3", dtype="float64")
        )

    for ufunc in binary_operators:
        # arr**arr is undefined for arrays with units because
        # each element of the result would have different units.
        if ufunc is np.power:
            a = unyt_array([0.3, 0.4, 0.5], "cm")
            b = unyt_array([0.1, 0.2, 0.3], "dimensionless")
            c = np.array(b)
            d = unyt_array([1.0, 2.0, 3.0], "g")
            with pytest.raises(UnitOperationError):
                ufunc(a, b)
            with pytest.raises(UnitOperationError):
                ufunc(a, c)
            with pytest.raises(UnitOperationError):
                ufunc(a, d)
            binary_ufunc_comparison(ufunc, np.array(2.0), b)
            continue

        a = unyt_array([0.3, 0.4, 0.5], "cm")
        b = unyt_array([0.1, 0.2, 0.3], "cm")
        c = unyt_array([0.1, 0.2, 0.3], "m")
        d = unyt_array([0.1, 0.2, 0.3], "g")
        e = unyt_array([0.1, 0.2, 0.3], "erg/m**3")

        for pair in itertools.product([a, b, c, d, e], repeat=2):
            binary_ufunc_comparison(ufunc, pair[0], pair[1])


@pytest.mark.skipif(
    np.__version__ < "1.16", reason="matmul is broken on old numpy versions"
)
def test_dot_matmul():
    arr = unyt_array([[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]], "cm")

    ev_result = arr.dot(unyt_array([1.0, 2.0, 3.0], "kg"))
    matmul_result = arr @ unyt_array([1.0, 2.0, 3.0], "kg")
    res = unyt_array([14.0, 32.0], "cm*kg")
    assert_equal(ev_result, res)
    assert_equal(ev_result.units, res.units)
    assert_isinstance(ev_result, unyt_array)
    assert_equal(matmul_result, res)
    assert_equal(matmul_result.units, res.units)
    assert_isinstance(matmul_result, unyt_array)

    ev_result = arr.dot(np.array([1.0, 2.0, 3.0]))
    matmul_result = arr @ np.array([1.0, 2.0, 3.0])
    res = unyt_array([14.0, 32.0], "cm")
    assert_equal(ev_result, res)
    assert_equal(ev_result.units, res.units)
    assert_isinstance(ev_result, unyt_array)
    assert_equal(matmul_result, res)
    assert_equal(matmul_result.units, res.units)
    assert_isinstance(matmul_result, unyt_array)

    ev_result = arr.dot(arr.T)
    matmul_result = arr @ arr.T
    res = unyt_array([[14.0, 32.0], [32.0, 77.0]], "cm**2")
    assert_equal(ev_result, res)
    assert_equal(ev_result.units, res.units)
    assert_isinstance(ev_result, unyt_array)
    assert_equal(matmul_result, res)
    assert_equal(matmul_result.units, res.units)
    assert_isinstance(matmul_result, unyt_array)

    ev_result = arr.v.dot(arr.T)
    matmul_result = arr.v @ arr.T
    res = unyt_array([[14.0, 32.0], [32.0, 77.0]], "cm")
    assert_equal(ev_result, res)
    assert_equal(ev_result.units, res.units)
    assert_isinstance(ev_result, unyt_array)
    assert_equal(matmul_result, res)
    assert_equal(matmul_result.units, res.units)
    assert_isinstance(matmul_result, unyt_array)

    ev_result = arr.dot(arr.T.v)
    matmul_result = arr @ arr.T.v
    res = unyt_array([[14.0, 32.0], [32.0, 77.0]], "cm")
    assert_equal(ev_result, res)
    assert_equal(ev_result.units, res.units)
    assert_isinstance(ev_result, unyt_array)
    assert_equal(matmul_result, res)
    assert_equal(matmul_result.units, res.units)
    assert_isinstance(matmul_result, unyt_array)

    arr = unyt_array([[1.0, 2.0], [3.0, 4.0]], "kg")
    arr.dot(arr.T, out=arr)
    res = unyt_array([[5.0, 11.0], [11.0, 25.0]], "kg**2")
    assert_equal(arr, res)
    assert_equal(arr.units, res.units)
    assert_isinstance(arr, unyt_array)

    qv = unyt_array([1, 2, 3], "cm").dot(unyt_array([1, 2, 3], "cm"))
    mv = unyt_array([1, 2, 3], "cm") @ unyt_array([1, 2, 3], "cm")
    qa = unyt_quantity(14, "cm**2")
    assert qv == qa
    assert qv.units == qa.units
    assert_isinstance(qv, unyt_quantity)
    assert mv == qa
    assert mv.units == qa.units
    assert_isinstance(mv, unyt_quantity)

    qv = unyt_array([1, 2, 3], "cm").dot(np.array([1, 2, 3]))
    mv = unyt_array([1, 2, 3], "cm") @ np.array([1, 2, 3])
    qa = unyt_quantity(14, "cm")
    assert qv == qa
    assert qv.units == qa.units
    assert_isinstance(qv, unyt_quantity)
    assert mv == qa
    assert mv.units == qa.units
    assert_isinstance(mv, unyt_quantity)


def test_reductions():
    arr = unyt_array([[1, 2, 3], [4, 5, 6]], "cm")

    answers = {
        "prod": (
            unyt_quantity(720, "cm**6"),
            unyt_array([4, 10, 18], "cm**2"),
            unyt_array([6, 120], "cm**3"),
        ),
        "sum": (
            unyt_quantity(21, "cm"),
            unyt_array([5.0, 7.0, 9.0], "cm"),
            unyt_array([6, 15], "cm"),
        ),
        "mean": (
            unyt_quantity(3.5, "cm"),
            unyt_array([2.5, 3.5, 4.5], "cm"),
            unyt_array([2, 5], "cm"),
        ),
        "std": (
            unyt_quantity(1.707825127659933, "cm"),
            unyt_array([1.5, 1.5, 1.5], "cm"),
            unyt_array([0.81649658, 0.81649658], "cm"),
        ),
    }
    for op, (result1, result2, result3) in answers.items():
        ev_result = getattr(arr, op)()
        assert_almost_equal(ev_result, result1)
        assert_equal(ev_result.units, result1.units)
        assert_isinstance(ev_result, unyt_quantity)
        for axis, result in [(0, result2), (1, result3), (-1, result3)]:
            ev_result = getattr(arr, op)(axis=axis)
            assert_almost_equal(ev_result, result)
            assert_equal(ev_result.units, result.units)
            assert_isinstance(ev_result, unyt_array)


def test_convenience():

    for orig in [
        [1.0, 2.0, 3.0],
        (1.0, 2.0, 3.0),
        np.array([1.0, 2.0, 3.0]),
        [[1.0], [2.0], [3.0]],
        np.array([[1.0], [2.0], [3.0]]),
        [[1.0, 2.0, 3.0]],
        np.array([[1.0, 2.0, 3.0]]),
    ]:
        arr = unyt_array(orig, "cm")
        arrou = unyt_array(orig, "1/cm")
        uoarr = unyt_array(1.0 / np.array(orig), "cm")

        assert_equal(arr.unit_quantity, unyt_quantity(1, "cm"))
        assert_equal(arr.uq, unyt_quantity(1, "cm"))
        assert_isinstance(arr.unit_quantity, unyt_quantity)
        assert_isinstance(arr.uq, unyt_quantity)

        assert_array_equal(arr.unit_array, unyt_array(np.ones_like(arr), "cm"))
        assert_array_equal(arr.ua, unyt_array(np.ones_like(arr), "cm"))
        assert_isinstance(arr.unit_array, unyt_array)
        assert_isinstance(arr.ua, unyt_array)

        for u in [arr.units, arr.unit_quantity, arr.unit_array, arr.uq, arr.ua]:
            assert_array_equal(u * orig, arr)
            assert_array_equal(orig * u, arr)
            assert_array_equal(orig / u, arrou)
            assert_array_equal(u / orig, uoarr)

        assert_array_equal(arr.ndview, arr.view(np.ndarray))
        assert_array_equal(arr.d, arr.view(np.ndarray))
        assert arr.ndview.base is arr.base
        assert arr.d.base is arr.base

        assert_array_equal(arr.value, np.array(arr))
        assert_array_equal(arr.v, np.array(arr))


def test_registry_association():
    reg = UnitRegistry()
    a = unyt_quantity(3, "cm", registry=reg)
    b = unyt_quantity(4, "m")
    c = unyt_quantity(6, "", registry=reg)
    d = 5

    assert_equal(id(a.units.registry), id(reg))

    def binary_op_registry_comparison(op):
        e = op(a, b)
        f = op(b, a)
        g = op(c, d)
        h = op(d, c)

        assert_equal(id(e.units.registry), id(reg))
        assert_equal(id(f.units.registry), id(b.units.registry))
        assert_equal(id(g.units.registry), id(h.units.registry))
        assert_equal(id(g.units.registry), id(reg))

    def unary_op_registry_comparison(op):
        c = op(a)
        d = op(b)

        assert_equal(id(c.units.registry), id(reg))
        assert_equal(id(d.units.registry), id(b.units.registry))

    binary_ops = [operator.add, operator.sub, operator.mul, operator.truediv]
    for op in binary_ops:
        binary_op_registry_comparison(op)

    for op in [operator.abs, operator.neg, operator.pos]:
        unary_op_registry_comparison(op)


def test_to_value():

    a = unyt_array([1.0, 2.0, 3.0], "kpc")
    assert_equal(a.to_value(), np.array([1.0, 2.0, 3.0]))
    assert_equal(a.to_value(), a.value)
    assert_equal(a.to_value("km"), a.in_units("km").value)

    b = unyt_quantity(5.5, "Msun")
    assert_equal(b.to_value(), 5.5)
    assert_equal(b.to_value("g"), b.in_units("g").value)


def test_astropy():
    if isinstance(_astropy.__version__, NotAModule):
        return
    ap_arr = np.arange(10) * _astropy.units.km / _astropy.units.hr
    yt_arr = unyt_array(np.arange(10), "km/hr")
    yt_arr2 = unyt_array.from_astropy(ap_arr)

    ap_quan = 10.0 * _astropy.units.Msun ** 0.5 / (_astropy.units.kpc ** 3)
    yt_quan = unyt_quantity(10.0, "sqrt(Msun)/kpc**3")
    yt_quan2 = unyt_quantity.from_astropy(ap_quan)

    assert_array_equal(ap_arr, yt_arr.to_astropy())
    assert_array_equal(yt_arr, unyt_array.from_astropy(ap_arr))
    assert_array_equal(yt_arr, yt_arr2)

    assert_equal(ap_quan, yt_quan.to_astropy())
    assert_equal(yt_quan, unyt_quantity.from_astropy(ap_quan))
    assert_equal(yt_quan, yt_quan2)

    assert_array_equal(yt_arr, unyt_array.from_astropy(yt_arr.to_astropy()))
    assert_equal(yt_quan, unyt_quantity.from_astropy(yt_quan.to_astropy()))


def test_pint():
    def assert_pint_array_equal(arr1, arr2):
        assert_array_equal(arr1.magnitude, arr2.magnitude)
        assert str(arr1.units) == str(arr2.units)

    if isinstance(_pint.UnitRegistry, NotAModule):
        return
    ureg = _pint.UnitRegistry()

    p_arr = np.arange(10) * ureg.km / ureg.year
    yt_arr = unyt_array(np.arange(10), "km/yr")
    yt_arr2 = unyt_array.from_pint(p_arr)

    p_quan = 10.0 * ureg.g ** 0.5 / (ureg.mm ** 3)
    yt_quan = unyt_quantity(10.0, "sqrt(g)/mm**3")
    yt_quan2 = unyt_quantity.from_pint(p_quan)

    assert_pint_array_equal(p_arr, yt_arr.to_pint())
    assert_array_equal(yt_arr, unyt_array.from_pint(p_arr))
    assert_array_equal(yt_arr, yt_arr2)

    assert_pint_array_equal(p_quan, yt_quan.to_pint())
    assert_equal(yt_quan, unyt_quantity.from_pint(p_quan))
    assert_equal(yt_quan, yt_quan2)

    assert_array_equal(yt_arr, unyt_array.from_pint(yt_arr.to_pint()))
    assert_equal(yt_quan, unyt_quantity.from_pint(yt_quan.to_pint()))


def test_subclass():
    class unyt_a_subclass(unyt_array):
        def __new__(
            cls, input_array, units=None, registry=None, bypass_validation=None
        ):
            return super(unyt_a_subclass, cls).__new__(
                cls,
                input_array,
                units,
                registry=registry,
                bypass_validation=bypass_validation,
            )

    a = unyt_a_subclass([4, 5, 6], "g")
    b = unyt_a_subclass([7, 8, 9], "kg")
    nu = unyt_a_subclass([10, 11, 12], "")
    nda = np.array([3, 4, 5])
    yta = unyt_array([6, 7, 8], "mg")
    loq = [unyt_quantity(6, "mg"), unyt_quantity(7, "mg"), unyt_quantity(8, "mg")]
    ytq = unyt_quantity(4, "cm")
    ndf = np.float64(3)

    def op_comparison(op, inst1, inst2, compare_class):
        assert_isinstance(op(inst1, inst2), compare_class)
        assert_isinstance(op(inst2, inst1), compare_class)

    ops = [operator.mul, operator.truediv]
    for op in ops:
        for inst in (b, ytq, ndf, yta, nda, loq):
            op_comparison(op, a, inst, unyt_a_subclass)

        op_comparison(op, ytq, nda, unyt_array)
        op_comparison(op, ytq, yta, unyt_array)

    for op in (operator.add, operator.sub):
        op_comparison(op, nu, nda, unyt_a_subclass)
        op_comparison(op, a, b, unyt_a_subclass)
        op_comparison(op, a, yta, unyt_a_subclass)
        op_comparison(op, a, loq, unyt_a_subclass)

    assert_isinstance(a[0], unyt_quantity)
    assert_isinstance(a[:], unyt_a_subclass)
    assert_isinstance(a[:2], unyt_a_subclass)
    assert_isinstance(unyt_a_subclass(yta), unyt_a_subclass)
    assert_isinstance(a.to("kg"), unyt_a_subclass)
    assert_isinstance(a.copy(), unyt_a_subclass)
    assert_isinstance(copy.deepcopy(a), unyt_a_subclass)

    with pytest.raises(RuntimeError):
        a + "hello"


def test_h5_io():
    if isinstance(_h5py.__version__, NotAModule):
        return

    tmpdir = tempfile.mkdtemp()
    curdir = os.getcwd()
    os.chdir(tmpdir)

    reg = UnitRegistry()

    reg.add("code_length", 10.0, dimensions.length)

    warr = unyt_array(np.random.random((256, 256)), "code_length", registry=reg)

    warr.write_hdf5("test.h5")

    iarr = unyt_array.from_hdf5("test.h5")

    assert_equal(warr, iarr)
    assert_equal(warr.units.registry["code_length"], iarr.units.registry["code_length"])

    # test code to overwrite existing dataset

    warr.write_hdf5("test.h5")

    giarr = unyt_array.from_hdf5("test.h5")

    assert_equal(warr, giarr)

    # test code to overwrite existing dataset with data that has a different
    # shape

    warr = unyt_array(np.random.random((255, 255)), "code_length", registry=reg)

    warr.write_hdf5("test.h5")

    giarr = unyt_array.from_hdf5("test.h5")

    assert_equal(warr, giarr)

    os.remove("test.h5")

    # write to a group that doesn't exist

    warr.write_hdf5(
        "test.h5", dataset_name="test_dset", group_name="/arrays/test_group"
    )

    giarr = unyt_array.from_hdf5(
        "test.h5", dataset_name="test_dset", group_name="/arrays/test_group"
    )

    assert_equal(warr, giarr)

    os.remove("test.h5")

    # write to a group that does exist

    with _h5py.File("test.h5", "a") as f:
        f.create_group("/arrays/test_group")

    warr.write_hdf5(
        "test.h5", dataset_name="test_dset", group_name="/arrays/test_group"
    )

    giarr = unyt_array.from_hdf5(
        "test.h5", dataset_name="test_dset", group_name="/arrays/test_group"
    )

    assert_equal(warr, giarr)

    os.remove("test.h5")

    os.chdir(curdir)
    shutil.rmtree(tmpdir)


def test_equivalencies():
    import unyt as u

    # equivalence is ignored if the conversion doesn't need one
    data = 12.0 * u.g
    data.convert_to_equivalent("kg", None)
    assert data.value == 0.012
    assert data.units == u.kg

    data = 12.0 * u.g
    data = data.to_equivalent("kg", None)
    assert data.value == 0.012
    assert data.units == u.kg

    # incorrect usage of an equivalence raises errors

    with pytest.raises(InvalidUnitEquivalence):
        data.convert_to_equivalent("erg", "thermal")
    with pytest.raises(InvalidUnitEquivalence) as excinfo:
        data.convert_to_equivalent("m", "mass_energy")
    assert (
        str(excinfo.value)
        == "The unit equivalence 'mass_energy: mass <-> energy' does not "
        "exist for units 'kg' to convert to a new unit with dimensions "
        "'(length)'."
    )
    with pytest.raises(InvalidUnitEquivalence):
        data.to_equivalent("erg", "thermal")
    with pytest.raises(InvalidUnitEquivalence):
        data.to_equivalent("m", "mass_energy")

    # Mass-energy

    mp = u.mp.copy()
    mp.convert_to_units("keV", "mass_energy")
    assert_allclose_units(u.mp.in_units("keV", "mass_energy"), mp)
    assert_allclose_units(mp, u.mp * u.clight * u.clight)
    assert_allclose_units(u.mp, mp.in_units("g", "mass_energy"))
    mp.convert_to_units("g", "mass_energy")
    assert_allclose_units(u.mp, mp)

    # Thermal

    T = 1e8 * u.K
    E = T.in_units("W*hr", "thermal")
    assert_allclose_units(E, (u.kboltz * T).in_units("W*hr"))
    assert_allclose_units(T, E.in_units("K", "thermal"))

    T.convert_to_units("W*hr", "thermal")
    assert_allclose_units(E, T)
    T.convert_to_units("K", "thermal")
    assert_allclose_units(T, 1e8 * u.K)

    # Spectral

    # wavelength to frequency

    lam = 4000 * u.angstrom
    nu = lam.in_units("Hz", "spectral")
    assert_allclose_units(nu, u.clight / lam)
    lam.convert_to_units("MHz", "spectral")
    assert_allclose_units(lam, nu)
    assert lam.units == u.MHz.units
    assert nu.units == u.Hz.units

    # wavelength to photon energy

    lam = 4000 * u.angstrom
    hnu = lam.in_units("erg", "spectral")
    assert_allclose_units(hnu, u.h_mks * u.clight / lam)
    lam.convert_to_units("eV", "spectral")
    assert_allclose_units(lam, hnu)
    assert lam.units == u.eV.units
    assert hnu.units == u.erg.units

    # wavelength to spatial frequency

    lam = 4000 * u.angstrom
    nubar = lam.in_units("1/angstrom", "spectral")
    assert_allclose_units(nubar, 1 / lam)
    lam.convert_to_units("1/cm", "spectral")
    assert_allclose_units(lam, nubar)
    assert lam.units == (1 / u.cm).units
    assert nubar.units == (1 / u.angstrom).units

    # frequency to wavelength

    nu = 1.0 * u.MHz
    lam = nu.to("km", "spectral")
    assert_allclose_units(lam, u.clight / nu)
    nu.convert_to_units("m", "spectral")
    assert_allclose_units(lam, nu)
    assert lam.units == u.km.units
    assert nu.units == u.m.units

    # frequency to spatial frequency

    nu = 1.0 * u.MHz
    nubar = nu.to("1/km", "spectral")
    assert_allclose_units(nubar, nu / u.clight)
    nu.convert_to_units("1/m", "spectral")
    assert_allclose_units(nubar, nu)
    assert nubar.units == (1 / u.km).units
    assert nu.units == (1 / u.m).units

    # frequency to photon energy

    nu = 1.0 * u.MHz
    E = nu.to("erg", "spectral")
    assert_allclose_units(E, u.h_mks * nu)
    nu.convert_to_units("J", "spectral")
    assert_allclose_units(nu, E)
    assert nu.units == u.J.units
    assert E.units == u.erg.units

    # photon energy to frequency

    E = 13.6 * u.eV
    nu = E.to("Hz", "spectral")
    assert_allclose_units(nu, E / u.h_mks)
    E.convert_to_units("MHz", "spectral")
    assert_allclose_units(nu, E)
    assert E.units == u.MHz.units
    assert nu.units == u.Hz.units

    # photon energy to wavelength

    E = 13.6 * u.eV
    lam = E.to("nm", "spectral")
    assert_allclose_units(lam, u.h_mks * u.clight / E)
    E.convert_to_units("angstrom", "spectral")
    assert_allclose_units(E, lam)
    assert E.units == u.angstrom.units
    assert lam.units == u.nm.units

    # photon energy to spatial frequency

    E = 13.6 * u.eV
    nubar = E.to("1/nm", "spectral")
    assert_allclose_units(nubar, E / (u.h_mks * u.clight))
    E.convert_to_units("1/angstrom", "spectral")
    assert_allclose_units(E, nubar)
    assert E.units == (1 / u.angstrom).units
    assert nubar.units == (1 / u.nm).units

    # spatial frequency to frequency

    nubar = 1500.0 / u.cm
    nu = nubar.to("Hz", "spectral")
    assert_allclose_units(nu, nubar * u.clight)
    nubar.convert_to_units("MHz", "spectral")
    assert_allclose_units(nu, nubar)
    assert nubar.units == u.MHz.units
    assert nu.units == u.Hz.units

    # spatial frequency to wavelength

    nubar = 1500.0 / u.cm
    lam = nubar.to("nm", "spectral")
    assert_allclose_units(lam, 1 / nubar)
    nubar.convert_to_units("angstrom", "spectral")
    assert_allclose_units(nubar, lam)
    assert nubar.units == u.angstrom.units
    assert lam.units == u.nm.units

    # spatial frequency to photon energy

    nubar = 1500.0 / u.cm
    E = nubar.to("erg", "spectral")
    assert_allclose_units(E, u.h_mks * u.clight * nubar)
    nubar.convert_to_units("J", "spectral")
    assert_allclose_units(nubar, E)
    assert nubar.units == u.J.units
    assert E.units == u.erg.units

    # Sound-speed

    # tempearature <-> velocity

    mu = 0.6
    gg = 5.0 / 3.0
    T = 1e8 * u.K
    c_s = T.in_units("km/s", equivalence="sound_speed")
    assert_allclose_units(c_s, np.sqrt(gg * u.kboltz * T / (mu * u.mh)))
    assert_allclose_units(T, c_s.in_units("K", "sound_speed"))
    T.convert_to_units("m/s", "sound_speed")
    assert_allclose_units(c_s, T)
    assert T.units == u.m.units / u.s.units
    assert c_s.units == u.km.units / u.s.units

    mu = 0.5
    gg = 4.0 / 3.0
    T = 1e8 * u.K
    c_s = T.in_units("km/s", "sound_speed", mu=mu, gamma=gg)
    assert_allclose_units(c_s, np.sqrt(gg * u.kboltz * T / (mu * u.mh)))
    assert_allclose_units(T, c_s.in_units("K", "sound_speed", mu=mu, gamma=gg))
    T.convert_to_units("m/s", "sound_speed", mu=mu, gamma=gg)
    assert_allclose_units(c_s, T)
    assert T.units == u.m.units / u.s.units
    assert c_s.units == u.km.units / u.s.units

    # tempearture <-> energy

    mu = 0.5
    gg = 4.0 / 3.0
    T = 1e8 * u.K
    kT = T.in_units("eV", "sound_speed", mu=mu, gamma=gg)
    assert_allclose_units(kT, u.kboltz * T)
    T.convert_to_units("erg", "sound_speed", mu=mu, gamma=gg)
    assert_allclose_units(T, kT)
    assert T.units == u.erg.units
    assert kT.units == u.eV.units
    assert_allclose_units(T.in_units("K", "sound_speed", mu=mu, gamma=gg), 1e8 * u.K)
    kT.convert_to_units("K", "sound_speed", mu=mu, gamma=gg)
    assert_allclose_units(kT, 1e8 * u.K)

    # velocity <-> energy

    c_s = 300 * u.m / u.s
    kT = c_s.in_units("erg", "sound_speed", mu=mu, gamma=gg)
    assert_allclose_units(kT, c_s ** 2 * mu * u.mh / gg)
    c_s.convert_to_units("J", "sound_speed", mu=mu, gamma=gg)
    assert_allclose_units(c_s, kT)
    assert c_s.units == u.J.units
    assert kT.units == u.erg.units
    assert_allclose_units(
        kT.in_units("m/s", "sound_speed", mu=mu, gamma=gg), 300 * u.m / u.s
    )
    c_s.convert_to_units("m/s", "sound_speed", mu=mu, gamma=gg)
    assert_allclose_units(c_s, 300 * u.m / u.s)

    # Lorentz

    v = 0.8 * u.clight
    g = v.in_units("dimensionless", "lorentz")
    g2 = unyt_quantity(1.0 / np.sqrt(1.0 - 0.8 * 0.8), "dimensionless")
    assert_allclose_units(g, g2)
    v.convert_to_units("", "lorentz")
    assert_allclose_units(v, g2)
    v.convert_to_units("c", "lorentz")
    v2 = g2.in_units("mile/hr", "lorentz")
    assert_allclose_units(v2, v.in_units("mile/hr"))

    # Schwarzschild

    msun = 1.0 * u.unit_symbols.Msun
    msun.convert_to_equivalent("km", "schwarzschild")
    R = u.mass_sun_mks.in_units("kpc", "schwarzschild")
    assert_allclose_units(msun, R)
    assert_allclose_units(R.in_mks(), 2 * u.G * u.mass_sun_mks / (u.clight ** 2))
    assert_allclose_units(u.mass_sun_mks, R.in_units("kg", "schwarzschild"))
    R.convert_to_units("Msun", "schwarzschild")
    assert_allclose_units(u.mass_sun_mks, R)
    assert R.units == u.unit_symbols.Msun.units
    assert msun.units == u.km.units

    # Compton

    me = 1.0 * u.me
    me.convert_to_units("nm", "compton")
    length = u.me.in_units("angstrom", "compton")
    assert_allclose_units(length, me)
    assert_allclose_units(length, u.h_mks / (u.me * u.clight))
    assert_allclose_units(u.me, length.in_units("g", "compton"))
    assert me.units == u.nm.units
    assert length.units == u.angstrom.units
    me.convert_to_units("me", "compton")
    assert_almost_equal(me.value, 1.0)

    # Number density

    rho = u.mp / u.m ** 3
    n = rho.in_units("m**-3", "number_density")
    assert_allclose_units(n, rho / (u.mh * 0.6))
    assert_allclose_units(rho, n.in_units("kg/m**3", "number_density"))
    rho.convert_to_units("cm**-3", "number_density")
    assert rho.units == (1 / u.cm ** 3).units
    assert n.units == (1 / u.m ** 3).units
    assert_allclose_units(n, rho)
    rho.convert_to_units("kg/m**3", "number_density")
    assert_allclose_units(u.mp / u.m ** 3, rho)
    assert rho.units == (u.kg / u.m ** 3).units

    rho = u.mp / u.m ** 3
    n = rho.in_units("m**-3", equivalence="number_density", mu=0.75)
    assert_allclose_units(n, rho / (u.mh * 0.75))
    assert_allclose_units(
        rho, n.in_units("kg/m**3", equivalence="number_density", mu=0.75)
    )
    rho.convert_to_units("cm**-3", "number_density", mu=0.75)
    assert rho.units == (1 / u.cm ** 3).units
    assert n.units == (1 / u.m ** 3).units
    assert_allclose_units(n, rho)
    rho.convert_to_units("kg/m**3", "number_density", mu=0.75)
    assert_allclose_units(u.mp / u.m ** 3, rho)
    assert rho.units == (u.kg / u.m ** 3).units

    # Effective temperature

    T = 1e4 * u.K
    F = T.in_units("W/m**2", equivalence="effective_temperature")
    assert_allclose_units(F, u.stefan_boltzmann_constant * T ** 4)
    assert_allclose_units(T, F.in_units("K", equivalence="effective_temperature"))
    T.convert_to_units("erg/s/cm**2", "effective_temperature")
    assert_allclose_units(T, F)
    assert T.units == u.Unit("erg/cm**2/s")
    assert F.units == u.W / u.m ** 2
    assert_almost_equal(T.in_units("K", "effective_temperature").value, 1e4)
    T.convert_to_units("K", "effective_temperature")
    assert_almost_equal(T.value, 1e4)
    assert T.units == u.K

    # to_value test

    assert_allclose_units(
        F.value, T.to_value("W/m**2", equivalence="effective_temperature")
    )
    assert_allclose_units(
        n.value, rho.to_value("m**-3", equivalence="number_density", mu=0.75)
    )


def test_electromagnetic():
    import unyt as u

    # Various tests of SI and CGS electromagnetic units

    t = 1.0 * u.Tesla
    g = 1.0 * u.gauss
    assert t.to("gauss") == 1e4 * u.gauss
    assert g.to("T") == 1e-4 * u.Tesla
    assert t.in_mks() == t
    assert g.in_cgs() == g
    t.convert_to_mks()
    assert t == 1.0 * u.Tesla
    g.convert_to_cgs()
    assert g == 1.0 * u.gauss

    qp_mks = u.qp_cgs.in_units("C")
    assert_equal(qp_mks.units.dimensions, dimensions.charge_mks)
    assert_almost_equal(qp_mks.v, 10.0 * u.qp.v / speed_of_light_cm_per_s)
    qp = 1.0 * u.qp_cgs
    assert_equal(qp, u.qp_cgs.in_units("esu"))
    qp.convert_to_units("C")
    assert_equal(qp.units.dimensions, dimensions.charge_mks)
    assert_almost_equal(qp.v, 10 * u.qp.v / u.clight.v)

    qp_cgs = u.qp.in_units("esu")
    assert_array_almost_equal(qp_cgs, u.qp_cgs)
    assert_equal(qp_cgs.units.dimensions, u.qp_cgs.units.dimensions)
    qp = u.qp.copy()
    qp.convert_to_units("esu")
    assert_almost_equal(qp_cgs, qp_cgs)
    assert qp.units == u.esu.units
    qp.convert_to_units("C")
    assert_almost_equal(u.qp, qp)
    assert qp.units == u.C.units

    qp_mks_k = u.qp_cgs.in_units("kC")
    assert_array_almost_equal(qp_mks_k.v, 1.0e-2 * u.qp_cgs.v / speed_of_light_cm_per_s)
    qp = 1.0 * u.qp_cgs
    qp.convert_to_units("kC")
    assert_almost_equal(qp, qp_mks_k)

    B = 1.0 * u.T
    B_cgs = B.in_units("gauss")
    assert_equal(B.units.dimensions, dimensions.magnetic_field_mks)
    assert_equal(B_cgs.units.dimensions, dimensions.magnetic_field_cgs)
    assert_array_almost_equal(B_cgs, unyt_quantity(1.0e4, "gauss"))
    B_cgs = B.in_cgs()
    assert_equal(B.units.dimensions, dimensions.magnetic_field_mks)
    assert_equal(B_cgs.units.dimensions, dimensions.magnetic_field_cgs)
    assert_array_almost_equal(B_cgs, unyt_quantity(1.0e4, "gauss"))
    B_cgs = B.in_base("cgs")
    assert_equal(B.units.dimensions, dimensions.magnetic_field_mks)
    assert_equal(B_cgs.units.dimensions, dimensions.magnetic_field_cgs)
    assert_array_almost_equal(B_cgs, unyt_quantity(1.0e4, "gauss"))
    B.convert_to_cgs()
    assert_almost_equal(B, B_cgs)
    B.convert_to_mks()
    B_cgs2 = B.to("gauss")
    assert_almost_equal(B_cgs, B_cgs2)
    B_mks2 = B_cgs2.to("T")
    assert_almost_equal(B, B_mks2)

    B = 1.0 * u.T
    u_mks = B * B / (2 * u.mu_0)
    assert_equal(u_mks.units.dimensions, dimensions.pressure)
    u_cgs = B_cgs * B_cgs / (8 * np.pi)
    assert_equal(u_mks, u_cgs.to(u_mks.units))
    assert_equal(u_mks.to(u_cgs.units), u_cgs)
    assert_equal(u_mks.in_cgs(), u_cgs)
    assert_equal(u_cgs.in_mks(), u_mks)

    current = 1.0 * u.A
    I_cgs = current.in_units("statA")
    assert_array_almost_equal(
        I_cgs, unyt_quantity(0.1 * speed_of_light_cm_per_s, "statA")
    )
    assert_array_almost_equal(I_cgs.in_units("mA"), current.in_units("mA"))
    assert_equal(I_cgs.units.dimensions, dimensions.current_cgs)
    current.convert_to_units("statA")
    assert current.units == u.statA.units
    current.convert_to_units("A")
    assert current.units == u.A.units
    I_cgs2 = current.to("statA")
    assert I_cgs2.units == u.statA.units
    assert_array_almost_equal(
        I_cgs2, unyt_quantity(0.1 * speed_of_light_cm_per_s, "statA")
    )

    current = 1.0 * u.A
    R = unyt_quantity(1.0, "ohm")
    R_cgs = R.in_units("statohm")
    P_mks = current * current * R
    P_cgs = I_cgs * I_cgs * R_cgs
    assert_equal(P_mks.units.dimensions, dimensions.power)
    assert_equal(P_cgs.units.dimensions, dimensions.power)
    assert_almost_equal(P_cgs.in_cgs(), P_cgs)
    assert_almost_equal(P_mks.in_cgs(), P_cgs)
    assert_almost_equal(P_cgs.in_mks(), P_mks)
    assert_almost_equal(P_mks.in_mks(), P_mks)

    V = unyt_quantity(1.0, "statV")
    V_mks = V.in_units("V")
    assert_array_almost_equal(V_mks.v, 1.0e8 * V.v / speed_of_light_cm_per_s)

    data = 1.0 * u.C * u.T * u.V
    with pytest.raises(UnitConversionError):
        data.to("statC*G*statV")
    with pytest.raises(UnitConversionError):
        data.convert_to_units("statC*G*statV")
    with pytest.raises(UnitsNotReducible):
        data.in_cgs()

    data = 1.0 * u.statC * u.G * u.statV
    with pytest.raises(UnitConversionError):
        data.to("C*T*V")
    with pytest.raises(UnitConversionError):
        data.convert_to_units("C*T*V")
    assert_almost_equal(data.in_mks(), 6.67408e-18 * u.m ** 5 / u.s ** 4)

    mu_0 = 4.0e-7 * math.pi * u.N / u.A ** 2
    eps_0 = 8.85418781782e-12 * u.m ** -3 / u.kg * u.s ** 4 * u.A ** 2
    assert_almost_equal((1.0 / (u.clight ** 2 * mu_0)).in_units(eps_0.units), eps_0)


def test_ytarray_coercion():
    a = unyt_array([1, 2, 3], "cm")
    q = unyt_quantity(3, "cm")
    na = np.array([1, 2, 3])

    assert_isinstance(a * q, unyt_array)
    assert_isinstance(q * na, unyt_array)
    assert_isinstance(q * 3, unyt_quantity)
    assert_isinstance(q * np.float64(3), unyt_quantity)
    assert_isinstance(q * np.array(3), unyt_quantity)


def test_numpy_wrappers():
    a1 = unyt_array([1, 2, 3], "cm")
    a2 = unyt_array([2, 3, 4, 5, 6], "cm")
    a3 = unyt_array([[1, 2, 3], [4, 5, 6]], "cm")
    a4 = unyt_array([7, 8, 9, 10, 11], "cm")
    catenate_answer = [1, 2, 3, 2, 3, 4, 5, 6]
    intersect_answer = [2, 3]
    union_answer = [1, 2, 3, 4, 5, 6]
    vstack_answer = [[2, 3, 4, 5, 6], [7, 8, 9, 10, 11]]
    vstack_answer_last_axis = [[2, 7], [3, 8], [4, 9], [5, 10], [6, 11]]
    cross_answer = [-2, 4, -2]
    norm_answer = np.sqrt(1 ** 2 + 2 ** 2 + 3 ** 2)
    arr_norm_answer = [norm_answer, np.sqrt(4 ** 2 + 5 ** 2 + 6 ** 2)]
    dot_answer = 14

    assert_array_equal(unyt_array(catenate_answer, "cm"), uconcatenate((a1, a2)))
    assert_array_equal(catenate_answer, np.concatenate((a1, a2)))

    assert_array_equal(unyt_array(intersect_answer, "cm"), uintersect1d(a1, a2))
    assert_array_equal(intersect_answer, np.intersect1d(a1, a2))

    assert_array_equal(unyt_array(union_answer, "cm"), uunion1d(a1, a2))
    assert_array_equal(union_answer, np.union1d(a1, a2))

    assert_array_equal(
        unyt_array(cross_answer, "cm**2"), ucross(a1, a1 + (2 * a1.units))
    )
    assert_array_equal(cross_answer, np.cross(a1.v, a1.v + 2))

    assert_array_equal(unorm(a1), unyt_quantity(norm_answer, "cm"))
    assert_array_equal(np.linalg.norm(a1), norm_answer)
    assert_array_equal(unorm(a3, axis=1), unyt_array(arr_norm_answer, "cm"))
    assert_array_equal(np.linalg.norm(a3, axis=1), arr_norm_answer)

    assert_array_equal(udot(a1, a1), unyt_quantity(dot_answer, "cm**2"))

    assert_array_equal(np.array(catenate_answer), uconcatenate((a1.v, a2.v)))
    with pytest.raises(RuntimeError):
        uconcatenate((a1, a2.v))
    with pytest.raises(RuntimeError):
        uconcatenate((a1.to("m"), a2))
    assert_array_equal(unyt_array(vstack_answer, "cm"), uvstack([a2, a4]))
    assert_array_equal(vstack_answer, np.vstack([a2, a4]))
    assert_array_equal(unyt_array(vstack_answer, "cm"), ustack([a2, a4]))
    assert_array_equal(vstack_answer, np.stack([a2, a4]))

    assert_array_equal(
        unyt_array(vstack_answer_last_axis, "cm"), ustack([a2, a4], axis=-1)
    )
    assert_array_equal(vstack_answer_last_axis, np.stack([a2, a4], axis=-1))


def test_dimensionless_conversion():
    a = unyt_quantity(1, "Zsun")
    b = a.in_units("Zsun")
    a.convert_to_units("Zsun")
    assert a.units.base_value == metallicity_sun
    assert b.units.base_value == metallicity_sun


def test_modified_unit_division():
    reg1 = UnitRegistry()
    reg2 = UnitRegistry()

    reg1.modify("g", 50)

    a = unyt_quantity(3, "g", registry=reg1)
    b = unyt_quantity(3, "g", registry=reg2)

    ret = a / b
    assert ret == 50000.0
    assert ret.units.is_dimensionless
    assert ret.units.base_value == 1.0


def test_loadtxt_and_savetxt():
    tmpdir = tempfile.mkdtemp()
    curdir = os.getcwd()
    os.chdir(tmpdir)

    a = unyt_array(np.random.random(10), "kpc")
    b = unyt_array(np.random.random(10), "Msun")
    c = unyt_array(np.random.random(10), "km/s")

    savetxt("arrays.dat", [a, b, c], delimiter=",")

    d, e = loadtxt("arrays.dat", usecols=(1, 2), delimiter=",")

    assert_array_equal(b, d)
    assert_array_equal(c, e)

    # adding newlines to the file doesn't matter

    savetxt("arrays.dat", [a, b, c], delimiter=",")

    with open("arrays.dat", "r+") as f:
        content = f.read()
        f.seek(0, 0)
        f.write("\n" + content)

    d, e = loadtxt("arrays.dat", usecols=(1, 2), delimiter=",")

    assert_array_equal(b, d)
    assert_array_equal(c, e)

    # data saved by numpy savetxt are loaded without units

    np.savetxt("arrays.dat", np.squeeze(np.transpose([a.v, b.v, c.v])), delimiter=",")

    d, e = loadtxt("arrays.dat", usecols=(1, 2), delimiter=",")

    assert_array_equal(b.v, d)
    assert_array_equal(c.v, e)

    # save a single array

    savetxt("arrays.dat", a)

    d = loadtxt("arrays.dat")

    assert_array_equal(a, d)

    # save an array with no units and an array with units with a header

    savetxt("arrays.dat", [a.v, b], header="this is a header!")

    d, e = loadtxt("arrays.dat")

    assert_array_equal(a.v, d)
    assert_array_equal(b, e)

    os.chdir(curdir)
    shutil.rmtree(tmpdir)


def test_trig_ufunc_degrees():
    for ufunc in (np.sin, np.cos, np.tan):
        degree_values = np.random.random(10) * degree
        radian_values = degree_values.in_units("radian")
        assert_array_equal(ufunc(degree_values), ufunc(radian_values))


def test_builtin_sum():
    from unyt import km

    arr = [1, 2, 3] * km
    assert_equal(sum(arr), 6 * km)


def test_initialization_different_registries():

    reg1 = UnitRegistry()
    reg2 = UnitRegistry()

    reg1.add("code_length", 1.0, dimensions.length)
    reg2.add("code_length", 3.0, dimensions.length)

    l1 = unyt_quantity(1.0, "code_length", registry=reg1)
    l2 = unyt_quantity(1.0, "code_length", registry=reg2)

    assert_almost_equal(float(l1.in_mks()), 1.0)
    assert_almost_equal(float(l2.in_mks()), 3.0)


def test_ones_and_zeros_like():
    data = unyt_array([1, 2, 3], "cm")
    zd = np.zeros_like(data)
    od = np.ones_like(data)

    assert_equal(zd, unyt_array([0, 0, 0], "cm"))
    assert_equal(zd.units, data.units)
    assert_equal(od, unyt_array([1, 1, 1], "cm"))
    assert_equal(od.units, data.units)


def test_coerce_iterable():
    from unyt import cm, km

    a = unyt_array([1, 2, 3], "cm")
    b = [1 * cm, 2 * km, 3 * cm]

    with pytest.raises(IterableUnitCoercionError):
        a + b
    with pytest.raises(IterableUnitCoercionError):
        b + a
    with pytest.raises(IterableUnitCoercionError):
        unyt_array(b)


def test_bypass_validation():
    from unyt import unyt_array, cm, UnitRegistry

    obj = unyt_array(np.array([1.0, 2.0, 3.0]), cm, bypass_validation=True)
    assert obj.units is cm

    reg = UnitRegistry()
    obj = unyt_array(
        np.array([1.0, 2.0, 3.0]), cm, registry=reg, bypass_validation=True
    )
    assert obj.units == cm
    assert obj.units.registry is reg


def test_creation():
    from unyt import cm, UnitRegistry

    data = [1, 2, 3] * cm

    new_data = unyt_array(data)

    assert new_data.units is cm
    assert_array_equal(new_data.v, np.array([1, 2, 3], dtype="float64"))

    reg = UnitRegistry()

    new_data = unyt_array(data, registry=reg)
    assert_array_equal(new_data.v, np.array([1, 2, 3], dtype="float64"))
    assert new_data.units is not cm
    assert new_data.units == cm
    assert new_data.units.registry is reg

    new_data = unyt_array([1, 2, 3], cm)
    assert_array_equal(new_data.v, np.array([1, 2, 3], dtype="float64"))
    assert new_data.units is cm

    new_data = unyt_array([1, 2, 3], cm, registry=reg)
    assert_array_equal(new_data.v, np.array([1, 2, 3], dtype="float64"))
    assert new_data.units is not cm
    assert new_data.units == cm
    assert new_data.units.registry is reg

    with pytest.raises(RuntimeError):
        unyt_quantity("hello", "cm")
    with pytest.raises(RuntimeError):
        unyt_quantity(np.array([1, 2, 3]), "cm")


def test_round():
    from unyt import km

    assert_equal(round(3.3 * km), 3.0)
    assert_equal(round(3.5 * km), 4.0)
    assert_equal(round(3 * km), 3)
    assert_equal(round(3.7 * km), 4)

    with pytest.raises(TypeError):
        round([1, 2, 3] * km)


def test_integer_arrays():
    from unyt import km, m, mile, ms, s

    def integer_semantics(inp):
        arr = inp * km
        assert arr.dtype == np.int_

        arr = np.array(inp, dtype="int32") * km
        assert arr.dtype.name == "int32"

        ret = arr.in_units("mile")

        assert arr.dtype.name == "int32"
        answer = (inp * km).astype("int32").to("mile")
        assert_array_equal(ret, answer)
        assert ret.dtype.name == "float32"

        ret = arr.in_units("m")
        assert arr.dtype != ret.dtype
        assert ret.dtype.name == "float32"

        arr.convert_to_units("m")
        assert arr.dtype.name == "float32"

        arr = inp * km
        arr.convert_to_units("mile")
        assert arr.dtype.name == "float" + str(np.int_().dtype.itemsize * 8)

    for foo in [[1, 2, 3], 12, -8, 0, [1, -2, 3]]:
        integer_semantics(foo)

    arr1 = [1, 2, 3] * km
    arr2 = [4, 5, 6] * mile
    assert (arr1 + arr2).dtype.name == "float64"
    assert (arr1 * arr2).dtype == np.int_
    assert (arr1 / arr2).dtype.name == "float64"

    arr1 = [1, 2, 3] * km
    arr2 = [4, 5, 6] * m
    assert (arr1 + arr2).dtype.name == "float64"
    assert (arr1 * arr2).dtype == np.int_
    assert (arr1 / arr2).dtype.name == "float64"

    arr1 = [1, 2, 3] * km
    arr2 = [4, 5, 6] * km
    assert (arr1 + arr2).dtype == np.int_
    assert (arr1 * arr2).dtype == np.int_
    assert (arr1 / arr2).dtype.name == "float64"

    # see issue #118 for details
    assert 1000 * ms == 1 * s
    assert 1 * s == 1000 * ms


def test_overflow_warnings():
    from unyt import km

    data = [2 ** 53, 2 ** 54] * km

    message = "Overflow encountered while converting to units 'mile'"
    _process_warning(data.to, message, RuntimeWarning, ("mile",))
    _process_warning(data.in_units, message, RuntimeWarning, ("mile",))
    _process_warning(data.convert_to_units, message, RuntimeWarning, ("mile",))


def test_input_units_deprecation():
    from unyt.array import unyt_array, unyt_quantity

    message = "input_units has been deprecated, please use units instead"

    _process_warning(
        unyt_array, message, DeprecationWarning, ([1, 2, 3],), {"input_units": "mile"}
    )
    _process_warning(
        unyt_quantity, message, DeprecationWarning, (3,), {"input_units": "mile"}
    )

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        assert_array_equal(
            unyt_array([1, 2, 3], "mile"), unyt_array([1, 2, 3], input_units="mile")
        )
        assert unyt_quantity(3, "mile") == unyt_quantity(3, input_units="mile")


def test_clip():
    from unyt import km

    data = [1, 2, 3, 4, 5, 6] * km
    answer = [2, 2, 3, 4, 4, 4] * km

    ret = np.clip(data, 2, 4)
    assert_array_equal(ret, answer)
    assert ret.units == answer.units

    np.clip(data, 2, 4, out=data)

    assert_array_equal(data, answer)
    assert data.units == answer.units

    left_edge = [0.0, 0.0, 0.0] * km
    right_edge = [1.0, 1.0, 1.0] * km

    positions = [[0.0, 0.0, 0.0], [1.0, 1.0, -0.1], [1.5, 1.0, 0.9]] * km
    np.clip(positions, left_edge, right_edge, positions)
    assert positions.units == left_edge.units
    assert positions.max() == 1.0 * km
    assert positions.min() == 0.0 * km


def test_name_attribute():
    a = unyt_array([0, 1, 2], "s")
    assert a.name is None
    a.name = "time"
    assert a.name == "time"
    assert a[0].name == "time"
    a.convert_to_units("ms")
    assert a.name == "time"
    b = unyt_quantity(1, "m", name="distance")
    assert b.name == "distance"
    c = b.copy()
    assert c.name == "distance"
    c_1 = copy.deepcopy(b)
    assert c_1.name == "distance"
    d = b.in_units("mm")
    assert d.name == "distance"
    e = b.to("mm")
    assert e.name == "distance"
    f = unyt_array([3, 4, 5], "K", name="temperature")
    g = f.in_units("J", equivalence="thermal")
    assert g.name is None
    g_1 = f.to_equivalent("J", equivalence="thermal")
    assert g_1.name is None
    f.convert_to_equivalent("J", equivalence="thermal")
    assert f.name is None
    h = f.to("J", equivalence="thermal")
    assert h.name is None


def test_neper_bel():
    assert 0 * Unit("dB") + 20 * Unit("dB") == unyt_quantity(20, "dB")
    with pytest.raises(InvalidUnitOperation):
        unyt_array([1, 10], "V") * Unit("dB")
    with pytest.raises(InvalidUnitOperation):
        Unit("Np") * unyt_array([1, 10], "s")
    with pytest.raises(InvalidUnitOperation):
        unyt_array([0, 20], "dB") ** 2
    with pytest.raises(InvalidUnitOperation):
        np.power(unyt_array([0, 20], "dB"), -2)
