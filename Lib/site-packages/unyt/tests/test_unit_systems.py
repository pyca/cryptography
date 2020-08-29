"""
Test unit systems.

"""

# -----------------------------------------------------------------------------
# Copyright (c) 2018, yt Development Team.
#
# Distributed under the terms of the Modified BSD License.
#
# The full license is in the LICENSE file, distributed with this software.
# -----------------------------------------------------------------------------

import pytest

import unyt.unit_symbols as us

from unyt.exceptions import IllDefinedUnitSystem, MissingMKSCurrent
from unyt.unit_object import Unit
from unyt.unit_systems import (
    UnitSystem,
    cgs_unit_system,
    mks_unit_system,
    unit_system_registry,
)
from unyt.unit_registry import UnitRegistry
from unyt import dimensions


def test_unit_systems():
    goofy_unit_system = UnitSystem(
        "goofy",
        "ly",
        "lbm",
        "hr",
        temperature_unit="R",
        angle_unit="arcsec",
        current_mks_unit="mA",
        luminous_intensity_unit="cd",
    )
    assert goofy_unit_system["temperature"] == Unit("R")
    assert goofy_unit_system[dimensions.solid_angle] == Unit("arcsec**2")
    assert goofy_unit_system["energy"] == Unit("lbm*ly**2/hr**2")
    goofy_unit_system["energy"] = "eV"
    assert goofy_unit_system["energy"] == Unit("eV")
    assert goofy_unit_system["magnetic_field_mks"] == Unit("lbm/(hr**2*mA)")
    assert "goofy" in unit_system_registry


def test_unit_system_id():
    reg1 = UnitRegistry()
    reg2 = UnitRegistry()
    assert reg1.unit_system_id == reg2.unit_system_id
    reg1.modify("g", 2.0)
    assert reg1.unit_system_id != reg2.unit_system_id
    reg1 = UnitRegistry()
    reg1.add("dinosaurs", 12.0, dimensions.length)
    assert reg1.unit_system_id != reg2.unit_system_id
    reg1 = UnitRegistry()
    reg1.remove("g")
    assert reg1.unit_system_id != reg2.unit_system_id
    reg1.add("g", 1.0e-3, dimensions.mass, prefixable=True)
    assert reg1.unit_system_id == reg2.unit_system_id


def test_bad_unit_system():
    with pytest.raises(IllDefinedUnitSystem):
        UnitSystem("atomic", "nm", "fs", "nK", "rad")
    with pytest.raises(IllDefinedUnitSystem):
        UnitSystem("atomic", "nm", "fs", "nK", "rad", registry=UnitRegistry())
    with pytest.raises(IllDefinedUnitSystem):
        UnitSystem("atomic", us.nm, us.fs, us.nK, us.rad)
    with pytest.raises(IllDefinedUnitSystem):
        UnitSystem("atomic", us.nm, us.fs, us.nK, us.rad, registry=UnitRegistry())


def test_code_unit_system():
    ureg = UnitRegistry()
    ureg.add("code_length", 2.0, dimensions.length)
    ureg.add("code_mass", 3.0, dimensions.mass)
    ureg.add("code_time", 4.0, dimensions.time)
    ureg.add("code_temperature", 5.0, dimensions.temperature)
    code_unit_system = UnitSystem(
        "my_unit_system",
        "code_length",
        "code_mass",
        "code_time",
        "code_temperature",
        registry=ureg,
    )
    assert code_unit_system["length"] == Unit("code_length", registry=ureg)
    assert code_unit_system["length"].base_value == 2
    assert code_unit_system["mass"] == Unit("code_mass", registry=ureg)
    assert code_unit_system["mass"].base_value == 3
    assert code_unit_system["time"] == Unit("code_time", registry=ureg)
    assert code_unit_system["time"].base_value == 4
    assert code_unit_system["temperature"] == Unit("code_temperature", registry=ureg)
    assert code_unit_system["temperature"].base_value == 5


def test_mks_current():
    with pytest.raises(MissingMKSCurrent):
        cgs_unit_system[dimensions.current_mks]
    with pytest.raises(MissingMKSCurrent):
        cgs_unit_system[dimensions.magnetic_field]
    with pytest.raises(MissingMKSCurrent):
        cgs_unit_system[dimensions.current_mks] = "foo"
    with pytest.raises(MissingMKSCurrent):
        cgs_unit_system[dimensions.magnetic_field] = "bar"
    assert cgs_unit_system.has_current_mks is False
    assert mks_unit_system.has_current_mks is True


def test_create_unit_system_from_unit_objects():
    s = UnitSystem("test_units", us.Mpc, us.Msun, us.s)
    assert s["length"] == us.Mpc
    assert s["mass"] == us.Msun
    assert s["time"] == us.s


def test_create_unit_system_from_quantity():
    s = UnitSystem("test_units", us.Mpc, 3 * us.Msun, us.s)
    assert s["length"] == us.Mpc
    assert s["mass"] == Unit("3*Msun")
    assert s["time"] == us.s
