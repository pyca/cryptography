"""
Unit system class.

"""

# -----------------------------------------------------------------------------
# Copyright (c) 2018, yt Development Team.
#
# Distributed under the terms of the Modified BSD License.
#
# The full license is in the LICENSE file, distributed with this software.
# -----------------------------------------------------------------------------

from collections import OrderedDict
from unyt import dimensions
from unyt.exceptions import MissingMKSCurrent, IllDefinedUnitSystem, UnitsNotReducible
from unyt._parsing import parse_unyt_expr
from unyt._unit_lookup_table import (
    default_unit_symbol_lut as default_lut,
    inv_name_alternatives,
    physical_constants,
    unit_prefixes,
)


def add_symbols(namespace, registry):
    """Adds the unit symbols from :mod:`unyt.unit_symbols` to a namespace

    Parameters
    ----------

    namespace : dict
       The dict to insert unit symbols into. The keys will be string
       unit names and values will be the corresponding unit objects.
    registry : :class:`unyt.unit_registry.UnitRegistry`
       The registry to create units from. Note that if you would like to
       use a custom unit system, ensure your registry was created using
       that unit system.

    Example
    -------
    >>> from unyt.unit_registry import UnitRegistry
    >>> class MyClass():
    ...     def __init__(self):
    ...         self.reg = UnitRegistry()
    ...         add_symbols(vars(self), self.reg)
    >>> foo = MyClass()
    >>> foo.kilometer
    km
    >>> foo.joule
    J
    """
    import unyt.unit_symbols as us
    from unyt.unit_object import Unit

    for name, unit in vars(us).items():
        if name.startswith("_"):
            continue
        namespace[name] = Unit(unit.expr, registry=registry)
    for name in [k for k in registry.keys() if k not in namespace]:
        namespace[name] = Unit(name, registry=registry)


def add_constants(namespace, registry):
    """Adds the quantities from :mod:`unyt.physical_constants` to a namespace

    Parameters
    ----------

    namespace : dict
       The dict to insert quantities into. The keys will be string names
       and values will be the corresponding quantities.
    registry : :class:`unyt.unit_registry.UnitRegistry`
       The registry to create units from. Note that if you would like to
       use a custom unit system, ensure your registry was created using
       that unit system.

    Example
    -------
    >>> from unyt.unit_registry import UnitRegistry
    >>> class MyClass():
    ...     def __init__(self):
    ...         self.reg = UnitRegistry(unit_system='cgs')
    ...         add_constants(vars(self), self.reg)
    >>> foo = MyClass()
    >>> foo.gravitational_constant
    unyt_quantity(6.67408e-08, 'cm**3/(g*s**2)')
    >>> foo.speed_of_light
    unyt_quantity(2.99792458e+10, 'cm/s')
    """
    from unyt.array import unyt_quantity

    for constant_name in physical_constants:
        value, unit_name, alternate_names = physical_constants[constant_name]
        for name in alternate_names + [constant_name]:
            quan = unyt_quantity(value, unit_name, registry=registry)
            try:
                namespace[name] = quan.in_base(unit_system=registry.unit_system)
            except UnitsNotReducible:
                namespace[name] = quan
            namespace[name + "_mks"] = unyt_quantity(
                value, unit_name, registry=registry
            )
            try:
                namespace[name + "_cgs"] = quan.in_cgs()
            except UnitsNotReducible:
                pass
            if name == "h":
                # backward compatibility for unyt 1.0, which defined hmks
                namespace["hmks"] = namespace["h_mks"].copy()
                namespace["hcgs"] = namespace["h_cgs"].copy()


def _split_prefix(symbol_str, unit_symbol_lut):
    possible_prefix = symbol_str[0]

    if symbol_str[:2] == "da":
        possible_prefix = "da"

    if possible_prefix in unit_prefixes:
        # the first character could be a prefix, check the rest of the symbol
        symbol_wo_pref = symbol_str[1:]

        # deca is the only prefix with length 2
        if symbol_str[:2] == "da":
            symbol_wo_pref = symbol_str[2:]
            possible_prefix = "da"

        entry = unit_symbol_lut.get(symbol_wo_pref, None)

        if entry and entry[4]:
            return possible_prefix, symbol_wo_pref
    return "", symbol_str


def _get_system_unit_string(dims, base_units):
    # The dimensions of a unit object is the product of the base dimensions.
    # Use sympy to factor the dimensions into base CGS unit symbols.
    units = []
    my_dims = dims.expand()
    if my_dims is dimensions.dimensionless:
        return ""
    for factor in my_dims.as_ordered_factors():
        dim = list(factor.free_symbols)[0]
        unit_string = str(base_units[dim])
        if factor.is_Pow:
            power_string = "**(%s)" % factor.as_base_exp()[1]
        else:
            power_string = ""
        units.append("(%s)%s" % (unit_string, power_string))
    return " * ".join(units)


unit_system_registry = {}

cmks = dimensions.current_mks


class UnitSystem(object):
    """
    Create a UnitSystem for facilitating conversions to a default set of units.

    Parameters
    ----------
    name : string
        The name of the unit system. Will be used as the key in the
        *unit_system_registry* dict to reference the unit system by.
    length_unit : string or :class:`unyt.unit_object.Unit`
        The base length unit of this unit system.
    mass_unit : string or :class:`unyt.unit_object.Unit`
        The base mass unit of this unit system.
    time_unit : string or :class:`unyt.unit_object.Unit`
        The base time unit of this unit system.
    temperature_unit : string or :class:`unyt.unit_object.Unit`, optional
        The base temperature unit of this unit system. Defaults to "K".
    angle_unit : string or :class:`unyt.unit_object.Unit`, optional
        The base angle unit of this unit system. Defaults to "rad".
    mks_system: boolean, optional
        Whether or not this unit system has SI-specific units.
        Default: False
    current_mks_unit : string or :class:`unyt.unit_object.Unit`, optional
        The base current unit of this unit system. Defaults to "A".
    luminous_intensity_unit : string or :class:`unyt.unit_object.Unit`, optional
        The base luminous intensity unit of this unit system.
        Defaults to "cd".
    registry : :class:`unyt.unit_registry.UnitRegistry` object
        The unit registry associated with this unit system. Only
        useful for defining unit systems based on code units.
    """

    def __init__(
        self,
        name,
        length_unit,
        mass_unit,
        time_unit,
        temperature_unit="K",
        angle_unit="rad",
        current_mks_unit="A",
        luminous_intensity_unit="cd",
        logarithmic_unit="Np",
        registry=None,
    ):
        self.registry = registry
        self.units_map = OrderedDict(
            [
                (dimensions.length, length_unit),
                (dimensions.mass, mass_unit),
                (dimensions.time, time_unit),
                (dimensions.temperature, temperature_unit),
                (dimensions.angle, angle_unit),
                (dimensions.current_mks, current_mks_unit),
                (dimensions.luminous_intensity, luminous_intensity_unit),
                (dimensions.logarithmic, logarithmic_unit),
            ]
        )
        for k, v in self.units_map.items():
            if v is not None:
                if hasattr(v, "value") and hasattr(v, "units"):
                    self.units_map[k] = v.value * v.units.expr
                else:
                    self.units_map[k] = parse_unyt_expr(str(v))
        for dimension, unit in self.units_map.items():
            # CGS sets the current_mks unit to none, so catch it here
            if unit is None and dimension is dimensions.current_mks:
                continue
            if unit.is_Mul:
                unit = unit.as_coeff_Mul()[1]
            if (
                self.registry is not None
                and self.registry[str(unit)][1] is not dimension
            ):
                raise IllDefinedUnitSystem(self.units_map)
            elif self.registry is None:
                bu = _split_prefix(str(unit), default_lut)[1]
                inferred_dimension = default_lut[inv_name_alternatives[bu]][1]
                if inferred_dimension is not dimension:
                    raise IllDefinedUnitSystem(self.units_map)
        self._dims = [
            "length",
            "mass",
            "time",
            "temperature",
            "angle",
            "current_mks",
            "luminous_intensity",
            "logarithmic",
        ]
        self.registry = registry
        self.base_units = self.units_map.copy()
        unit_system_registry[name] = self
        self.name = name

    def __getitem__(self, key):
        from unyt.unit_object import Unit

        if isinstance(key, str):
            key = getattr(dimensions, key)
        um = self.units_map
        if key not in um or um[key] is None:
            if cmks in key.free_symbols and self.units_map[cmks] is None:
                raise MissingMKSCurrent(self.name)
            units = _get_system_unit_string(key, self.units_map)
            self.units_map[key] = parse_unyt_expr(units)
            return Unit(units, registry=self.registry)
        return Unit(self.units_map[key], registry=self.registry)

    def __setitem__(self, key, value):
        if isinstance(key, str):
            if key not in self._dims:
                self._dims.append(key)
            key = getattr(dimensions, key)
        if self.units_map[cmks] is None and cmks in key.free_symbols:
            raise MissingMKSCurrent(self.name)
        self.units_map[key] = parse_unyt_expr(str(value))

    def __str__(self):
        return self.name

    def __repr__(self):
        repr = "%s Unit System\n" % self.name
        repr += " Base Units:\n"
        for dim in self.base_units:
            if self.base_units[dim] is not None:
                repr += "  %s: %s\n" % (str(dim).strip("()"), self.base_units[dim])
        repr += " Other Units:\n"
        for key in self._dims:
            dim = getattr(dimensions, key)
            if dim not in self.base_units:
                repr += "  %s: %s\n" % (key, self.units_map[dim])
        return repr[:-1]

    @property
    def has_current_mks(self):
        """Does this unit system have an MKS current dimension?"""
        return self.units_map[cmks] is not None


#: The CGS unit system
cgs_unit_system = UnitSystem("cgs", "cm", "g", "s", current_mks_unit=None)
cgs_unit_system["energy"] = "erg"
cgs_unit_system["specific_energy"] = "erg/g"
cgs_unit_system["pressure"] = "dyne/cm**2"
cgs_unit_system["force"] = "dyne"
cgs_unit_system["magnetic_field_cgs"] = "gauss"
cgs_unit_system["charge_cgs"] = "esu"
cgs_unit_system["current_cgs"] = "statA"
cgs_unit_system["power"] = "erg/s"

#: The MKS unit system
mks_unit_system = UnitSystem("mks", "m", "kg", "s")
mks_unit_system["energy"] = "J"
mks_unit_system["specific_energy"] = "J/kg"
mks_unit_system["pressure"] = "Pa"
mks_unit_system["force"] = "N"
mks_unit_system["magnetic_field"] = "T"
mks_unit_system["charge"] = "C"
mks_unit_system["frequency"] = "Hz"
mks_unit_system["power"] = "W"
mks_unit_system["electric_potential"] = "V"
mks_unit_system["capacitance"] = "F"
mks_unit_system["inductance"] = "H"
mks_unit_system["resistance"] = "ohm"
mks_unit_system["magnetic_flux"] = "Wb"
mks_unit_system["luminous_flux"] = "lm"

#: The imperial unit system
imperial_unit_system = UnitSystem("imperial", "ft", "lb", "s", temperature_unit="R")
imperial_unit_system["force"] = "lbf"
imperial_unit_system["energy"] = "ft*lbf"
imperial_unit_system["pressure"] = "lbf/ft**2"
imperial_unit_system["power"] = "hp"

#: The galactic unit system
galactic_unit_system = UnitSystem("galactic", "kpc", "Msun", "Myr")
galactic_unit_system["energy"] = "keV"
galactic_unit_system["magnetic_field_cgs"] = "uG"

#: The solar unit system
solar_unit_system = UnitSystem("solar", "AU", "Mearth", "yr")

#: Geometrized unit system
geometrized_unit_system = UnitSystem("geometrized", "l_geom", "m_geom", "t_geom")

#: Planck unit system
planck_unit_system = UnitSystem(
    "planck", "l_pl", "m_pl", "t_pl", temperature_unit="T_pl"
)
planck_unit_system["energy"] = "E_pl"
planck_unit_system["charge_mks"] = "q_pl"
