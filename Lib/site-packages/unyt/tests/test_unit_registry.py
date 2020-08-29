"""
Test unit lookup tables and registry




"""

# -----------------------------------------------------------------------------
# Copyright (c) 2018, yt Development Team.
#
# Distributed under the terms of the Modified BSD License.
#
# The full license is in the LICENSE file, distributed with this software.
# -----------------------------------------------------------------------------

import os
import pytest

from numpy.testing import assert_allclose

from unyt.dimensions import length, energy
from unyt.exceptions import SymbolNotFoundError, UnitParseError
from unyt.unit_object import Unit
from unyt.unit_registry import UnitRegistry


def test_add_modify_error():
    from unyt import m

    ureg = UnitRegistry()

    with pytest.raises(UnitParseError):
        ureg.add("tayne", 1, length)
    with pytest.raises(UnitParseError):
        ureg.add("tayne", "blah", length)
    with pytest.raises(UnitParseError):
        ureg.add("tayne", 1.0, length, offset=1)
    with pytest.raises(UnitParseError):
        ureg.add("tayne", 1.0, length, offset="blah")

    ureg.add("tayne", 1.1, length)

    with pytest.raises(SymbolNotFoundError):
        ureg.remove("tayn")
    with pytest.raises(SymbolNotFoundError):
        ureg.modify("tayn", 1.2)

    ureg.modify("tayne", 1.0 * m)

    assert ureg["tayne"][:3] == ureg["m"][:3]


def test_keys():
    ureg = UnitRegistry()
    assert sorted(ureg.keys()) == sorted(ureg.lut.keys())


def test_prefixable_units():
    ureg = UnitRegistry()
    pu = ureg.prefixable_units
    assert "m" in pu
    assert "pc" in pu
    assert "mol" in pu
    ureg.add("foobar", 1.0, length, prefixable=True)
    assert "foobar" in ureg.prefixable_units
    mfoobar = Unit("mfoobar", registry=ureg)
    foobar = Unit("foobar", registry=ureg)
    assert (1 * foobar) / (1 * mfoobar) == 1000


def test_registry_contains():
    ureg = UnitRegistry()
    assert "m" in ureg
    assert "cm" in ureg
    assert "erg" in ureg
    assert "Merg" in ureg
    assert "foobar" not in ureg
    assert Unit("m", registry=ureg) in ureg


def test_registry_json():
    reg = UnitRegistry()
    reg.add("tayne", 1.0, length)
    json_reg = reg.to_json()
    unserialized_reg = UnitRegistry.from_json(json_reg)

    assert reg.lut == unserialized_reg.lut

    assert reg.lut["m"][1] is length
    assert reg.lut["erg"][1] is energy
    assert reg.lut["tayne"][1] is length


def test_old_registry_json():
    path = os.sep.join([os.path.dirname(__file__), "data/old_json_registry.txt"])
    with open(path) as f:
        json_text = f.read()
    reg = UnitRegistry.from_json(json_text)
    default_reg = UnitRegistry()

    loaded_keys = reg.keys()

    for k in default_reg.keys():
        assert k in loaded_keys
        loaded_val = reg[k]
        val = default_reg[k]
        assert_allclose(loaded_val[0], val[0])
        assert loaded_val[1:] == val[1:]
